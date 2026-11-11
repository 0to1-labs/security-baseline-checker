# -*- coding: utf-8 -*-
"""检查引擎：SSH 连接目标主机，执行只读检查命令，按规则自动判定"""
import re, json, base64, socket
import paramiko

GUIDANCE_RE = re.compile(r'^(检查|查看|尝试登录|控制台)')
SQL_RE = re.compile(r'^(SELECT|SHOW|EXEC|WITH|DECLARE|SET)\b', re.I)
STEP_TIMEOUT = 25


def _jjudge(rule, out, err):
    """返回 'pass'|'fail'|'manual'|'na'"""
    from rules import V, _strip_c
    if not callable(rule):
        errl = (err or '').lower()
        if 'denied' in errl or 'not found' in errl or 'command not found' in errl:
            return 'manual'
    if callable(rule):
        try:
            return rule(out or '', err or '')
        except Exception:
            return 'manual'
    if isinstance(rule, str):
        rule = rule.lower()
    out = out or ''
    stripped = out.strip()
    if rule == 'empty':
        return 'pass' if not stripped else 'fail'
    if rule == 'nonempty':
        return 'pass' if stripped else 'fail'
    if isinstance(rule, dict):
        if rule.get('cc'):
            out = _strip_c(out)
            stripped = out.strip()
        if 're' in rule:
            if not stripped:
                return rule.get('empty', 'fail')
            m = re.search(rule['re'], out, re.I | re.M)
            hit = bool(m)
            ok = (not hit) if rule.get('neg') else hit
            return 'pass' if ok else 'fail'
        if 'num' in rule:
            if not stripped:
                return rule.get('empty', 'manual')
            m = re.search(rule['num'], out)
            if not m:
                return 'manual'
            try:
                digits = m.group(1) or m.group(0)
                n = int(re.sub(r'[^\d]', '', digits))
            except Exception:
                return 'manual'
            ops = {'<=': n <= rule['val'], '>=': n >= rule['val'], '<': n < rule['val'],
                   '>': n > rule['val'], '==': n == rule['val'], '!=': n != rule['val']}
            return 'pass' if ops[rule['op']] else 'fail'
    return 'manual'


class SshRunner:
    def __init__(self, ip, port, user, password, os_type='linux'):
        self.ip, self.port, self.user, self.password = ip, int(port), user, password
        self.os_type = os_type
        self.cli = None

    def connect(self):
        self.cli = paramiko.SSHClient()
        self.cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.cli.connect(self.ip, self.port, self.user, self.password,
                         timeout=15, banner_timeout=15, auth_timeout=15,
                         allow_agent=False, look_for_keys=False)

    def close(self):
        try:
            self.cli.close()
        except Exception:
            pass

    def run(self, cmd, timeout=STEP_TIMEOUT):
        stdin, stdout, stderr = self.cli.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        rc = stdout.channel.recv_exit_status()
        return out, err, rc


def build_exec(cmd, item, ctx):
    """把检查命令包装成可执行命令；返回 None 表示该步骤是人工指引"""
    b = item['baseline']
    if GUIDANCE_RE.match(cmd):
        return None
    dbu, dbp = ctx.get('db_user', ''), ctx.get('db_pass', '')
    # 数据库 SQL
    if b in ('mysql', 'postgresql', 'oracle', 'sqlserver', 'dm') and SQL_RE.match(cmd):
        sql = cmd.replace('"', '\\"')
        if b == 'mysql':
            return f'export MYSQL_PWD="{dbp}"; mysql -u {dbu} --connect-timeout=5 -e "{sql}" 2>&1'
        if b == 'postgresql':
            return f'export PGPASSWORD="{dbp}"; psql -U {dbu} -d postgres -c "{sql}" 2>&1'
        if b == 'sqlserver':
            return f'sqlcmd -S localhost -U {dbu} -P {dbp} -W -Q "{sql}" 2>&1'
        if b == 'oracle':
            return f'echo "{sql};" | sqlplus -S {dbu}/{dbp} 2>&1'
        if b == 'dm':
            return f'echo "{sql};" | disql {dbu}/{dbp} 2>&1'
    if b in ('redis_db', 'redis_mw') and dbp:
        cmd = cmd.replace('redis-cli ', f'redis-cli --no-auth-warning -a "{dbp}" ', 1)
    if b == 'mongodb' and dbu:
        cmd = cmd.replace('mongosh', f'mongosh --quiet -u {dbu} -p {dbp}', 1)
        cmd = cmd.replace('mongo ', f'mongo --quiet -u {dbu} -p {dbp} ', 1)
    if b == 'tomcat' and 'CATALINA_HOME' in cmd:
        pre = ('CATALINA_HOME=$(ls -d /opt/apache-tomcat* /usr/local/apache-tomcat* /opt/tomcat* '
               '/usr/local/tomcat* /usr/share/tomcat* /var/lib/tomcat* 2>/dev/null | head -1)')
        return f'export {pre}; {cmd}'
    if b == 'weblogic' and '$DOMAIN_HOME' in cmd:
        pre = ('DOMAIN_HOME=$(ls -d /opt/*domain* /u01/oracle/user_projects/domains/* '
               '/usr/local/user_projects/domains/* 2>/dev/null | head -1)')
        return f'export {pre}; {cmd}'
    return cmd


# ---------- WinRM ----------
class WinrmRunner:
    """Windows 主机通过 WinRM (5985/5986) 远程执行命令"""

    def __init__(self, ip, port, user, password, os_type='windows'):
        self.ip, self.port, self.user, self.password = ip, int(port), user, password
        self.os_type = os_type
        self.sess = None

    def connect(self):
        import winrm
        proto = 'https' if self.port == 5986 else 'http'
        self.sess = winrm.Session(f'{proto}://{self.ip}:{self.port}/wsman',
                                 auth=(self.user, self.password), transport='ntlm')
        r = self.sess.run_cmd('echo ok')
        if b'ok' not in r.std_out:
            raise RuntimeError('WinRM 连接验证失败')

    def close(self):
        pass

    def run(self, cmd, timeout=STEP_TIMEOUT):
        r = self.sess.run_cmd(cmd)
        out = r.std_out.decode('utf-8', 'replace')
        err = r.std_err.decode('utf-8', 'replace')
        return out, err, r.status_code


def make_runner(host_row, password):
    """根据主机记录创建对应的连接器（password 为已解密的明文）"""
    if host_row['os_type'] == 'windows' and (host_row['conn_type'] or 'ssh') == 'winrm':
        return WinrmRunner(host_row['ip'], host_row['port'] or 5985,
                           host_row['username'], password, host_row['os_type'])
    return SshRunner(host_row['ip'], host_row['port'] or 22,
                     host_row['username'], password, host_row['os_type'])


# ---------- 组件自动探测 ----------
LINUX_DISCOVER = r'''# BLCHKDISCO-MARKER
OS=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -sr)
echo "@os@$OS"
P=$(ps -e -o comm= 2>/dev/null | sort -u)
A=$(ps -e -o args= 2>/dev/null | grep -v 'BLCHKDISCO-MARKER')
for pair in "mysqld|mariadbd:mysql" "^postgres:postgresql" "ora_pmon:oracle" "sqlservr:sqlserver" \
            "mongod:mongodb" "redis-server:redis_db" "dmserver:dm" "nginx:nginx" "httpd|apache2:apache"; do
  pat=${pair%%:*}; key=${pair##*:}
  if echo "$P" | grep -qiE "$pat"; then echo "@found@$key"; fi
done
if echo "$A" | grep -q 'cat[a]lina'; then echo "@found@tomcat"; fi
if echo "$A" | grep -qi 'web[l]ogic'; then echo "@found@weblogic"; fi
if echo "$A" | grep -q 'kaf[k]a\.Kafka'; then echo "@found@kafka"; fi
if echo "$A" | grep -qi 'nac[o]s'; then echo "@found@nacos"; fi
if echo "$P" | grep -q 'beam.smp' && echo "$A" | grep -qi 'rab[b]it'; then echo "@found@rabbitmq"; fi
echo "@done@"
'''

WINDOWS_DISCOVER = r'''
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$os = (Get-CimInstance Win32_OperatingSystem).Caption
echo "@os@$os"
$ErrorActionPreference='SilentlyContinue'
$svcs = (Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name) -join ','
$names = (Get-Process).Name -join ','
$procs = (Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine) -join "`n"
$all = $svcs + "`n" + $names + "`n" + $procs
foreach ($kv in @(@('mysql','mysql'), @('postgres','postgresql'), @('MSSQL|SQL Server','sqlserver'),
                 @('mongod|MongoDB','mongodb'), @('redis','redis_db'), @('dmserver|dmservice','dm'),
                 @('nginx','nginx'), @('apache|httpd','apache'), @('catalina','tomcat'),
                 @('weblogic','weblogic'), @('kafka','kafka'), @('nacos','nacos'),
                 @('rabbit|beam','rabbitmq'))) {
  if ($all -match $kv[0]) { echo "@found@$($kv[1])" }
}
echo "@done@"
'''

DETECT_MAP = {'mysql': 'MySQL/MariaDB', 'postgresql': 'PostgreSQL', 'oracle': 'Oracle',
              'sqlserver': 'SQL Server', 'mongodb': 'MongoDB', 'redis_db': 'Redis',
              'dm': '达梦 DM', 'nginx': 'Nginx', 'apache': 'Apache',
              'tomcat': 'Tomcat', 'weblogic': 'WebLogic', 'kafka': 'Kafka',
              'rabbitmq': 'RabbitMQ', 'nacos': 'Nacos'}


def discover(runner):
    """探测主机上的 OS 与数据库/中间件组件，返回 {os, keys, raw}"""
    if runner.os_type == 'windows':
        b64 = base64.b64encode(WINDOWS_DISCOVER.encode('utf-16-le')).decode()
        out, err, rc = runner.run(f'powershell -NoProfile -NonInteractive -EncodedCommand {b64}')
    else:
        out, err, rc = runner.run("bash -c " + _shquote(LINUX_DISCOVER))
    os_name, keys = '', []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('@os@'):
            os_name = line[4:]
        elif line.startswith('@found@'):
            k = line[7:]
            if k not in keys:
                keys.append(k)
    return {'os': os_name, 'keys': keys, 'raw': out}


def _shquote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def run_item(runner, item, ctx):
    """执行一个检查项，返回 {steps:[{cmd,exec,out,err,verdict}], auto, verdict}"""
    from rules import get_judges
    judges = get_judges(item['baseline'], item['name']) or []
    steps = []
    if item.get('mode') == '不适用':
        return {'steps': [], 'auto': 'na', 'verdict': 'na'}
    for i, raw in enumerate(item.get('commands', [])):
        step = {'cmd': raw}
        exec_cmd = build_exec(raw, item, ctx)
        if exec_cmd is None:
            step.update(exec=None, out='', err='', verdict='manual')
        elif runner.os_type == 'windows':
            b64 = base64.b64encode(raw.replace('"', "'").encode('utf-16-le')).decode()
            try:
                out, err, rc = runner.run(f'powershell -NoProfile -NonInteractive -EncodedCommand {b64}')
                step.update(exec=True, out=out, err=err)
            except Exception as e:
                step.update(exec=True, out='', err=f'执行失败: {e}')
            out, err = step['out'], step['err']
            j = judges[i] if i < len(judges) else None
            step['verdict'] = _jjudge(j, out, err) if j else 'manual'
            if j is None:
                step['verdict'] = 'manual'
        else:
            try:
                out, err, rc = runner.run(exec_cmd)
                step.update(exec=True, out=out, err=err)
            except Exception as e:
                step.update(exec=True, out='', err=f'执行失败: {e}')
                step['verdict'] = 'manual'
                steps.append(step)
                continue
            j = judges[i] if i < len(judges) else None
            if j is None:
                step['verdict'] = 'manual'
            else:
                # 数据库命令把 stderr 合并后再判定
                merged = step['out'] + ('\n' + step['err'] if step['err'] else '')
                if item['baseline'] in ('mysql', 'postgresql', 'oracle', 'sqlserver', 'dm'):
                    step['verdict'] = _jjudge(j, merged, '')
                else:
                    step['verdict'] = _jjudge(j, step['out'], step['err'])
        steps.append(step)
    judged = [s['verdict'] for s in steps if s['verdict'] in ('pass', 'fail')]
    manuals = [s['verdict'] for s in steps if s['verdict'] in ('manual',)]
    nas = [s for s in steps if s['verdict'] == 'na']
    if nas and not judged:
        auto = 'na'
    elif judged and 'fail' in judged:
        auto = 'fail'
    elif manuals:
        auto = 'manual'
    elif judged and all(v == 'pass' for v in judged):
        auto = 'pass'
    else:
        auto = 'manual'
    # 部分人工的项目：命令自动结果仅作参考，最终待人工确认
    if item.get('mode') in ('部分人工', '人工核查') and auto == 'pass':
        auto = 'manual'
    return {'steps': steps, 'auto': auto, 'verdict': auto}
