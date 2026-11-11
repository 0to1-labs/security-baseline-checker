# -*- coding: utf-8 -*-
"""自动判定规则库：key=(baseline, 检查项名) -> 与 commands 等长的 judge 列表
judge 类型：
  'empty'      输出为空 -> 符合
  'nonempty'   输出非空 -> 符合
  {'re':..,'neg':..,'empty':'fail|na|manual'}  正则匹配 -> 符合（neg=True 则不匹配才符合）
  {'num':..,'op':..,'val':..} 提取数字比较
  函数        fn(out, err) -> 'pass'|'fail'|'manual'|'na'
缺省：无规则的步骤 -> 待人工
"""
import re

V = dict(pass_='pass', fail='fail', manual='manual', na='na')


def _strip_c(text):
    """去掉配置输出里的注释行（nginx -T / httpd -S / server.xml 等）"""
    return '\n'.join(l for l in (text or '').splitlines()
                     if not l.strip().startswith('#') and not l.strip().startswith('<!--'))


def _num(out, pattern, op, val):
    m = re.search(pattern, out)
    if not m:
        return 'manual'
    try:
        n = int(re.sub(r'[^\d]', '', m.group(1)) or m.group(0))
    except Exception:
        return 'manual'
    return 'pass' if {'<=': n <= val, '>=': n >= val, '<': n < val, '>': n > val, '!=': n != val, '==': n == val}[op] else 'fail'


# ---------------- Linux ----------------
def j_linux_pass_policy(out, err):
    ok = True
    md = re.search(r'PASS_MAX_DAYS\s+(\d+)', out)
    ml = re.search(r'PASS_MIN_LEN\s+(\d+)', out)
    if md and int(md.group(1)) > 90: ok = False
    if ml and int(ml.group(1)) < 8: ok = False
    if md is None and ml is None: return 'manual'
    if not re.search(r'pam_pwquality|pam_passwdqc|pam_cracklib', out): ok = False
    return 'pass' if ok else 'fail'


def j_linux_login_lock(out, err):
    if not re.search(r'pam_tally2|pam_faillock', out): return 'fail'
    d = re.search(r'deny=(\d+)', out)
    t = re.search(r'lock_time=(\d+)|lockout_time_sec=(\d+)', out)
    if d and int(d.group(1)) <= 10 and t: return 'pass'
    return 'fail'


def j_linux_uid0(out, err):
    users = [l.strip() for l in out.splitlines() if l.strip()]
    return 'pass' if users == ['root'] else 'fail'


def j_linux_root_login(out, err):
    return 'pass' if re.search(r'permitrootlogin\s+(no|prohibit-password)', out, re.I) else 'fail'


def j_linux_sshport(out, err):
    m = re.search(r'^port\s+(\d+)', out.strip(), re.I | re.M)
    if not m: return 'manual'
    return 'pass' if m.group(1) != '22' else 'fail'


def j_linux_crontab(out, err):
    if not out.strip(): return 'manual'
    m = re.search(r'^-(\S+)\s+\d+\s+(\S+)\s+(\S+)', out)
    if not m: return 'manual'
    perm, u, g = m.groups()
    return 'pass' if 's' not in perm and u == 'root' and g == 'root' else 'fail'


def j_linux_initd(out, err):
    return 'pass' if re.search(r'root\s+root\s+75[05]', out) else 'fail'


def j_linux_umask(out, err):
    m = re.search(r'umask\s+(0[27]7|027|077|02[0-9])', out)
    return 'pass' if m else 'fail'


def j_linux_auditd(out, err):
    return 'pass' if re.search(r'auditd', out) and re.search(r'rsyslog', out) else 'fail'


def j_linux_auditctl(out, err):
    return 'fail' if re.search(r'no rules', out, re.I) else ('pass' if out.strip() else 'fail')


def j_linux_hist(out, err):
    m = re.search(r'HISTSIZE=(\d+)|HISTFILESIZE=(\d+)', out)
    return 'pass' if m else 'fail'


def j_linux_ping(out, err):
    if re.search(r'icmp.*drop|drop.*icmp', out, re.I): return 'pass'
    return 'pass' if re.search(r'^\s*1\s*$', out.strip()) else 'fail'


def j_linux_srcroute(out, err):
    vals = re.findall(r'\d+', out)
    return 'pass' if vals and all(v == '0' for v in vals) else 'fail'


def j_linux_tmout(out, err):
    m = re.search(r'TMOUT=(\d+)', out)
    return 'pass' if m and 0 < int(m.group(1)) <= 900 else 'fail'


def j_linux_limits(out, err):
    lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith('#') and not l.startswith('ulimit')]
    return 'pass' if lines else 'fail'


def j_linux_home_owner(out, err):
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            import os
            if os.path.basename(parts[0]) != parts[1]:
                return 'fail'
    return 'pass' if out.strip() else 'pass'


def j_linux_suid_whitelist(out, err):
    return 'pass' if not out.strip() else 'manual'


def j_linux_passwd_perm(out, err):
    need = {'/etc/fstab': '644', '/etc/passwd': '644', '/etc/shadow': '600', '/etc/group': '600',
            '/etc/services': '600', '/etc/aliases': '755', '/etc/securetty': '400'}
    for path, perm in need.items():
        m = re.search(r'[-pbcllsd]+\S*\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+' + re.escape(path) + r'\b', out)
        if not m: return 'manual'
    return 'pass'


def j_linux_lsattr_i(out, err):
    lines = [l for l in out.splitlines() if l.strip()]
    return 'pass' if lines and all('-i-' in l or l.split()[0].count('i') > 0 for l in lines) else 'manual'


def j_linux_proto2(out, err):
    if re.search(r':(23|21|110|143)\b', out): return 'fail'
    return 'pass' if re.search(r'protocol 2|ssh 2', out, re.I) else 'manual'


def j_linux_default_accts(out, err):
    return 'pass' if not out.strip() else 'manual'


def j_linux_uid_dup(out, err):
    return 'pass' if not out.strip() else 'fail'


def j_linux_securetty(out, err):
    tty = [l.strip() for l in out.splitlines() if l.strip()]
    bad = [t for t in tty if re.match(r'^(ttyp|pts/|ttyS)', t)]
    return 'pass' if not bad else 'manual'


def j_linux_dns(out, err):
    ns = re.findall(r'nameserver\s+([\d.]+)', out)
    if not ns: return 'manual'
    return 'manual'  # 需对照企业 DNS 清单


def j_linux_agent(out, err):
    return 'pass' if re.search(r'agent|qingteng|titanagent|al_agent', out, re.I) else 'manual'


def j_linux_svc_minimal(out, err):
    return 'manual'


RULES = {
    'linux': {
        'a) 身份标识和鉴别（禁止空密码登陆）': [
            'empty',
            lambda o, e: 'na' if 'not found' in (e or '').lower() else ('pass' if not o.strip() else 'fail'),
            {'re': r'permitemptypasswords\s+no', 'empty': 'manual'}],
        'b) 口令复杂度与更换（含：密码安全策略、检查密码是否安全）': [j_linux_pass_policy, j_linux_pass_policy, {'re': r'remember=\d+'}],
        'c) 登录失败处理（含：认证失败锁定策略）': [j_linux_login_lock],
        'd) 远程管理加密（含：ssh2 版本、禁止记住密码）': [j_linux_proto2, j_linux_proto2],
        'e) 用户名唯一性': ['empty', 'empty'],
        '管理密码': [
            'empty',
            lambda o, e: 'fail' if re.search(r'PASS_MAX_DAYS\s+(\d+)', o) and int(re.search(r'PASS_MAX_DAYS\s+(\d+)', o).group(1)) > 90 else ('manual' if 'PASS_MAX_DAYS' not in o else 'pass'),
            lambda o, e: 'manual' if 'PASS_MIN_LEN' not in o else ('pass' if int(re.search(r'PASS_MIN_LEN\s+(\d+)', o).group(1)) >= 8 else 'fail'),
            {'re': r'remember=\d+'},
            {'re': r'pam_wheel', 'empty': 'fail'},
            {'re': r'wheel:', 'empty': 'manual'}],
        'f) 双因素鉴别（含：动态口令验证）': [{'re': r'pam_google_authenticator|pam_radius|pam_oath|pam_securid', 'empty': 'manual'}],
        '确保 uid 为 0 的用户只有 root': [j_linux_uid0],
        '禁止 root 登陆': [j_linux_root_login],
        '修改 ssh 默认端口': [j_linux_sshport],
        '危险文件': ['empty', 'empty'],
        '敏感目录 S 标志位检查': [j_linux_suid_whitelist],
        '用户目录 S 标志位检查': ['empty'],
        '用户目录/文件所属检查': [j_linux_home_owner],
        '用户目录设备文件检查': ['empty'],
        'Crontab 只允许 root 添加': [j_linux_crontab],
        '/etc/rc.d/init.d 权限': [j_linux_initd],
        'umask': [j_linux_umask, j_linux_umask],
        'a) 审计范围（含：开启 audit 审计）': [{'re': r'active'}, {'re': r'enabled'}],
        'b) 审计内容': [j_linux_auditd, j_linux_auditctl],
        '审计历史记录': [j_linux_hist, j_linux_hist],
        'a) 鉴别信息存储空间清除（banner 信息）': [{'re': r'\\S|\\r|\\v|\\m|\\l|kernel', 'neg': True, 'empty': 'pass'}],
        '关闭 ping 响应': [j_linux_ping, j_linux_ping],
        '禁止 ip 源路径路由': [j_linux_srcroute, j_linux_srcroute],
        'b) 登录超时锁定（含：TMOUT）': [j_linux_tmout],
        'd) 单个用户资源限制': [j_linux_limits, {'num': r'ulimit\s+(\d+)|^(\d+)$', 'op': '<=', 'val': 99999999, 'empty': 'manual'}],
        '配置安全的 dns 服务器': [j_linux_dns],
        '禁用使用控制台程序': ['empty'],
        'a) 访问控制功能（含：敏感文件权限）': [j_linux_passwd_perm, j_linux_lsattr_i, 'empty'],
        '其它（缺省账户/不可改变位/uid唯一性）': [j_linux_default_accts, j_linux_lsattr_i, j_linux_uid_dup, j_linux_uid_dup],
        'a) 终端接入限制（含：限制 ip 登陆、Root 仅控制台）': [{'re': r'sshd', 'empty': 'manual'}, {'re': r'.', 'empty': 'manual'}, {'re': r'allowusers|allowgroups', 'empty': 'manual'}, j_linux_securetty],
        'a) 入侵检测与报警（EDR）': [j_linux_agent],
        'a) 防恶意代码软件': [j_linux_agent],
        'f) 审计记录保护（含：日志文件权限、日志备份）': [j_linux_limits, {'re': r'@@', 'empty': 'manual'}],
    },
}

# ---------------- Windows ----------------
def j_win_localuser(out, err):
    # Get-LocalUser 输出行式解析不可靠，做辅助判定
    if re.search(r'PasswordRequired\s+False', out, re.I): return 'fail'
    if re.search(r'Guest\s+True', out, re.I): return 'fail'
    return 'manual'


def j_win_net_accounts(out, err):
    def getval(label_re):
        m = re.search(label_re, out, re.I)
        return int(m.group(1)) if m else None
    keys = {
        '复杂性': [r'复杂性要求.*?:\s*(已启用|Enabled)', r'密码必须符合复杂性'],
        '长度': [r'(?:密码长度最小值|Minimum password length).*?(\d+)'],
        '期限': [r'(?:密码最长使用期限|Maximum password age).*?(\d+)'],
        '历史': [r'(?:保留密码的历史记录长度|Length of password history maintained).*?(\d+)'],
    }
    return 'manual'


def j_win_lockout(out, err):
    thr = re.search(r'(?:锁定阈值|Lockout threshold).*?(\d+)', out, re.I)
    dur = re.search(r'(?:锁定持续时间|Lockout duration).*?(\d+)', out, re.I)
    win = re.search(r'(?:锁定观察窗口|Lockout observation window).*?(\d+)', out, re.I)
    if not thr:
        return 'manual'
    t = int(thr.group(1))
    if t == 0:
        return 'fail'
    ok = t <= 5
    if dur and int(dur.group(1)) < 30: ok = False
    if win and int(win.group(1)) < 30: ok = False
    return 'pass' if ok else 'fail'


def j_win_rdp_enc(out, err):
    lvl = re.search(r'MinEncryptionLevel\s*:?\s*(\d+)', out)
    auth = re.search(r'UserAuthentication\s*:?\s*(\d+)', out)
    if lvl is None and auth is None: return 'manual'
    if lvl and int(lvl.group(1)) >= 3 and auth and int(auth.group(1)) == 1: return 'pass'
    return 'fail'


def j_win_rdp_port(out, err):
    m = re.search(r'PortNumber\s*:?\s*(\d+)', out)
    if not m: return 'manual'
    return 'pass' if int(m.group(1)) != 3389 else 'fail'


def j_win_anon(out, err):
    ra = re.search(r'RestrictAnonymous\s*:?\s*(\d+)', out)
    rs = re.search(r'RestrictAnonymousSAM\s*:?\s*(\d+)', out)
    if ra is None and rs is None: return 'manual'
    if ra and int(ra.group(1)) == 1 and rs and int(rs.group(1)) == 1: return 'pass'
    return 'fail'


def j_win_uac(out, err):
    e = re.search(r'EnableLUA\s*:?\s*(\d+)', out)
    c = re.search(r'ConsentPromptBehaviorAdmin\s*:?\s*(\d+)', out)
    if e is None: return 'manual'
    if int(e.group(1)) == 1 and c and int(c.group(1)) != 0: return 'pass'
    return 'fail'


def j_win_autorun(out, err):
    m = re.search(r'NoDriveTypeAutoRun\s*:?\s*(\d+)', out)
    return 'pass' if m and int(m.group(1)) == 255 else ('fail' if m else 'manual')


def j_win_fw(out, err):
    vals = re.findall(r'(Domain|Private|Public)\s+True', out, re.I)
    return 'pass' if len(vals) >= 3 else ('fail' if vals or 'False' in out else 'manual')


def j_win_srcroute(out, err):
    d = re.search(r'DisableIPSourceRouting\s*:?\s*(\d+)', out)
    i = re.search(r'EnableICMPRedirect\s*:?\s*(\d+)', out)
    if d is None: return 'manual'
    if int(d.group(1)) == 2 and i and int(i.group(1)) == 0: return 'pass'
    return 'fail'


def j_win_pagefile(out, err):
    c = re.search(r'ClearPageFileAtShutdown\s*:?\s*(\d+)', out)
    d = re.search(r'DontDisplayLastUserName\s*:?\s*(\d+)', out)
    if c is None and d is None: return 'manual'
    if c and int(c.group(1)) == 1 and d and int(d.group(1)) == 1: return 'pass'
    return 'fail'


def j_win_crashdump(out, err):
    m = re.search(r'CrashDumpEnabled\s*:?\s*(\d+)', out)
    return 'pass' if m and int(m.group(1)) == 0 else ('fail' if m else 'manual')


def j_win_pswaudit(out, err):
    m = re.search(r'EnableScriptBlockLogging\s*:?\s*(\d+)', out)
    return 'pass' if m and int(m.group(1)) == 1 else ('fail' if m else 'manual')


def j_win_denyrdp(out, err):
    if 'SeDenyRemoteInteractiveLogonRight' not in out: return 'manual'
    return 'pass' if re.search(r'Administrator', out) else 'fail'


def j_win_seclog(out, err):
    m = re.search(r'maxSize:\s*(\d+)', out)
    if not m: return 'manual'
    return 'pass' if int(m.group(1)) >= 196608 else 'fail'


def j_win_usb(out, err):
    m = re.search(r'Start\s*:?\s*(\d+)', out)
    return 'pass' if m and int(m.group(1)) == 4 else ('fail' if m else 'manual')


def j_win_idle(out, err):
    m = re.search(r'MaxIdleTime\s*:?\s*(\d+)', out)
    if not m: return 'manual'
    return 'pass' if 0 < int(m.group(1)) <= 900000 else 'fail'


RULES['windows'] = {
    'a) 身份标识和鉴别（禁止空密码登录）': [j_win_localuser, j_win_localuser],
    'c) 登录失败处理（含：账户锁定策略）': [j_win_lockout],
    'e) 用户名唯一性': [{'re': r'.', 'empty': 'manual'}, 'empty'],
    'd) 远程管理加密（含：RDP 加密、禁止明文服务）': [j_win_rdp_enc, {'re': r'Running', 'neg': True, 'empty': 'na'}, {'re': r'.', 'neg': True, 'empty': 'na'}],
    'j) 修改 RDP 默认端口': [j_win_rdp_port, {'re': r'.', 'neg': True, 'empty': 'na'}],
    'j) 匿名访问限制（含：空会话、匿名枚举）': [j_win_anon],
    'k) UAC 用户账户控制': [j_win_uac],
    'l) 自动播放禁用（AutoRun）': [j_win_autorun, j_win_autorun],
    'e) 禁止 IP 源路径路由（含：ICMP 重定向）': [j_win_srcroute],
    'g) 主机防火墙启用': [j_win_fw, j_win_fw],
    'a) 鉴别信息存储空间清除（含：内存页面文件、登录痕迹）': [j_win_pagefile, j_win_pagefile],
    'c) 内存转储保护': [j_win_crashdump, {'re': r'.', 'empty': 'manual'}],
    'g) PowerShell 操作审计': [j_win_pswaudit, j_win_pswaudit],
    'b) 审计内容（含：安全日志配置）': [j_win_seclog],
    'i) 禁止默认管理员远程登录': [j_win_denyrdp],
    'b) 登录超时锁定（含：会话超时、屏幕保护）': [j_win_idle, {'re': r'ScreenSaveActive\s*:?\s*1', 'empty': 'manual'}],
    'g) 可移动存储设备限制': [j_win_usb],
}

# ---------------- 数据库 ----------------
RULES['mysql'] = {
    '密码有效期': [{'num': r'default_password_lifetime\s+(\d+)', 'op': '<=', 'val': 90}],
    '空密码账户检查': ['empty'],
    '匿名账户检查': ['empty'],
    '远程 root 登录限制': ['empty'],
    'secure_file_priv 限制': [{'re': r'secure_file_priv\s+\S+', 'neg': False}],
    '审计日志启用': [{'re': r'general_log\s+ON|audit', 'empty': 'manual'}],
    '慢查询日志': [{'re': r'slow_query_log\s+ON'}],
    '禁用 LOCAL INFILE': [{'re': r'local_infile\s+OFF'}],
    'skip-grant-tables 检查': ['empty'],
    '最大连接数限制': [{'num': r'max_connections\s+(\d+)', 'op': '>=', 'val': 100, 'empty': 'manual'}],
    '连接超时设置': [{'num': r'wait_timeout\s+(\d+)', 'op': '<=', 'val': 28800}],
}


def j_pg_empty_rows(out, err):
    body = re.sub(r'^\(0 rows\)$', '', out.strip(), flags=re.M).strip()
    return 'pass' if not body else 'fail'


def j_pg_passenc(out, err):
    return 'pass' if re.search(r'scram-sha-256|md5', out) else 'fail'


def j_pg_valuntil(out, err):
    rows = [l for l in out.splitlines() if '|' in l and 'rolname' not in l]
    if not rows: return 'manual'
    ok = all(len([c for c in l.split('|') if c.strip()]) >= 2 for l in rows)
    return 'pass' if ok else 'fail'


RULES['postgresql'] = {
    '密码加密存储': [j_pg_passenc],
    '空密码账户检查': [j_pg_empty_rows],
    '密码有效期': [j_pg_valuntil],
    'pg_hba.conf 认证配置': [{'re': r'\btrust\b', 'neg': True, 'empty': 'manual'}],
    '审计日志启用': [{'re': r'\b(ddl|all)\b'}, {'re': r'\bon\b'}],
    'SSL 加密通信': [{'re': r'\bon\b'}],
    '最大连接数限制': [{'num': r'max_connections\s+(\d+)', 'op': '>=', 'val': 50, 'empty': 'manual'}],
}

RULES['sqlserver'] = {
    '空密码检查': ['empty'],
    '密码策略': [{'re': r'1', 'empty': 'manual'}],
    'xp_cmdshell 禁用': [{'num': r'config_value\s+(\d+)|run_value\s+(\d+)', 'op': '==', 'val': 0, 'empty': 'manual'}],
}

RULES['mongodb'] = {
    '认证启用': [{'re': r'enabled', 'empty': 'manual'}],
}


def j_redis_requirepass(out, err):
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    vals = [l for l in lines if not l.startswith('requirepass')]
    return 'pass' if vals and not re.match(r'^$', vals[0]) else 'fail'


def j_redis_bind(out, err):
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    vals = [l for l in lines if not l.startswith('bind')]
    if not vals: return 'manual'
    return 'fail' if '0.0.0.0' in vals[0] else 'pass'


def j_redis_rename(out, err):
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    vals = [l for l in lines if not l.startswith('rename-command')]
    return 'pass' if vals and any(re.search(r'(?:FLUSHALL|FLUSHDB|CONFIG|KEYS)', l, re.I) for l in vals) else 'fail'


def j_redis_slowlog(out, err):
    vals = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('slowlog')]
    if not vals: return 'manual'
    return 'pass' if vals[0] not in ('0',) else 'fail'


def j_redis_tls(out, err):
    vals = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('tls-port')]
    if not vals: return 'manual'
    return 'pass' if vals[0] not in ('0',) else 'manual'


def j_redis_maxmem(out, err):
    vals = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('maxmemory')]
    if not vals: return 'manual'
    return 'pass' if vals[0] not in ('0',) else 'fail'


def j_redis_maxclients(out, err):
    vals = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('maxclients')]
    if not vals: return 'manual'
    return 'pass' if vals[0] not in ('0',) else 'fail'


for _b in ('redis_db', 'redis_mw'):
    RULES[_b] = {
        '密码认证': [j_redis_requirepass],
        '监听地址限制': [j_redis_bind],
        '危险命令禁用': [j_redis_rename],
        '危险命令禁用/重命名': [j_redis_rename],
        '慢查询日志': [j_redis_slowlog],
        'TLS 加密': [j_redis_tls],
        'TLS 加密通信': [j_redis_tls],
        '最大内存限制': [j_redis_maxmem],
        '最大客户端连接数': [j_redis_maxclients],
    }

RULES['dm'] = {
    '空密码检查': ['empty'],
    '审计功能启用': [{'re': r'1|TRUE|ENABLED', 'empty': 'manual'}],
}
RULES['oracle'] = {
    '锁定账户检查': [{'re': r'.', 'empty': 'pass'}],
    '审计功能启用': [{'re': r'\b(DB|OS|TRUE)\b', 'empty': 'manual'}],
}

# ---------------- 中间件 ----------------
def j_mw_nonroot(out, err, users=r'nginx|www|www-data|apache|nobody'):
    lines = [l for l in out.splitlines() if re.search(r'\bworker\b', l)]
    if not lines:
        return 'manual'
    bad = [l for l in lines if re.match(r'^\S+\s+root\b', l)]
    return 'fail' if bad else 'pass'


def j_nginx_token(out, err):
    out = _strip_c(out)
    if not out.strip(): return 'fail'
    return 'pass' if re.search(r'server_tokens\s+off', out) else 'fail'


def j_nginx_autoindex(out, err):
    out = _strip_c(out)
    return 'pass' if not re.search(r'autoindex\s+on', out) else 'fail'


def j_nginx_accesslog(out, err):
    out = _strip_c(out)
    if not out.strip(): return 'fail'
    return 'fail' if re.search(r'access_log\s+off', out) else 'pass'


def j_nginx_sslproto(out, err):
    out = _strip_c(out)
    if not out.strip(): return 'na'
    bad = re.search(r'SSLv2|SSLv3|TLSv1(?![.\d])|TLSv1\.0|TLSv1\.1', out)
    good = re.search(r'TLSv1\.[23]', out)
    if bad: return 'fail'
    return 'pass' if good else 'manual'


def j_nginx_ciphers(out, err):
    out = _strip_c(out)
    if not out.strip(): return 'na'
    bad = re.search(r'RC4|DES(?![a-zA-Z])|MD5|EXPORT|NULL|aNULL', out)
    return 'fail' if bad else 'pass'


def j_nginx_cms(out, err):
    out = _strip_c(out)
    m = re.search(r'client_max_body_size\s+(\d+)([km]?)', out)
    if not m: return 'manual'
    return 'pass'


def j_nginx_keepalive(out, err):
    out = _strip_c(out)
    m = re.search(r'keepalive_timeout\s+(\d+)', out)
    return 'pass' if m and int(m.group(1)) <= 65 else ('fail' if m else 'manual')


RULES['nginx'] = {
    '运行用户最小化': [lambda o, e: j_mw_nonroot(o, e, r'nginx|www|nobody')],
    '管理接口认证': [{'re': r'auth_basic|allow\s+\d', 'empty': 'na', 'cc': True}],
    '隐藏版本信息': [j_nginx_token],
    '目录浏览禁用': [j_nginx_autoindex],
    '限制 HTTP 方法': [{'re': r'limit_except|if.*REQUEST_METHOD', 'empty': 'manual', 'cc': True}],
    '访问日志启用': [j_nginx_accesslog],
    '错误日志启用': [{'re': r'error_log', 'empty': 'fail', 'cc': True}],
    '错误页面不泄露信息': [{'re': r'error_page', 'empty': 'manual', 'cc': True}],
    'SSL/TLS 协议版本': [j_nginx_sslproto],
    '加密套件配置': [j_nginx_ciphers],
    '请求头超限': [j_nginx_cms],
    '连接数限制': [{'re': r'limit_conn_zone|limit_req_zone', 'empty': 'manual', 'cc': True}],
    '超时设置': [j_nginx_keepalive, {'re': r'client_header_timeout|client_body_timeout', 'empty': 'manual', 'cc': True}],
}

RULES['apache'] = {
    '运行用户最小化': [lambda o, e: j_mw_nonroot(o, e, r'apache|www-data|www|daemon|nobody')],
    '管理界面认证': [{'re': r'Require|AuthType', 'empty': 'na', 'cc': True}],
    '隐藏版本信息': [{'re': r'ServerTokens\s+Prod', 'empty': 'manual', 'cc': True}, {'re': r'ServerSignature\s+Off', 'empty': 'manual', 'cc': True}],
    '目录浏览禁用': [{'re': r'Options.*Indexes', 'neg': True, 'empty': 'pass', 'cc': True}],
    '限制 HTTP 方法': [{'re': r'TraceEnable\s+Off', 'empty': 'manual', 'cc': True}],
    '访问日志启用': [{'re': r'CustomLog', 'empty': 'fail', 'cc': True}],
    '错误日志启用': [{'re': r'ErrorLog', 'empty': 'fail', 'cc': True}],
    '错误页面不泄露信息': [{'re': r'ErrorDocument', 'empty': 'manual', 'cc': True}],
    'SSL/TLS 协议版本': [j_nginx_sslproto],
    '加密套件配置': [j_nginx_ciphers],
    '加载安全模块': [{'re': r'security', 'empty': 'manual'}],
    '超时设置': [{'num': r'Timeout\s+(\d+)', 'op': '<=', 'val': 60, 'empty': 'manual', 'cc': True}],
    '请求体大小限制': [{'re': r'LimitRequestBody', 'empty': 'manual', 'cc': True}],
}


def j_tomcat_users(out, err):
    out = _strip_c(out)
    if not out.strip(): return 'manual'
    weak = re.search(r'password="(tomcat|changeme|admin|s3cret)"', out, re.I)
    return 'fail' if weak else 'pass'


def j_tomcat_webapps(out, err):
    entries = [l.strip().rstrip('/') for l in out.splitlines() if l.strip()]
    bad = [e for e in entries if e.split('/')[-1] in ('docs', 'examples', 'host-manager', 'manager')]
    return 'fail' if bad else ('pass' if entries else 'manual')


def j_tomcat_ajp(out, err):
    out = _strip_c(out)
    if not out.strip(): return 'pass'
    if re.search(r'protocol="AJP.*secret=|address="127\.0\.0\.1"', out): return 'pass'
    return 'fail' if re.search(r'AJP', out) else 'pass'


def j_tomcat_ctimeout(out, err):
    out = _strip_c(out)
    m = re.search(r'connectionTimeout="(\d+)"', out)
    return 'pass' if m and int(m.group(1)) <= 20000 else ('fail' if m else 'manual')


RULES['tomcat'] = {
    '管理界面认证': [j_tomcat_users],
    '关闭默认示例': [j_tomcat_webapps],
    '隐藏版本信息': [{'re': r'server="(?!\s*Apache-Coyote)', 'empty': 'manual'}],
    '禁用 WAR 自动部署': [{'re': r'autoDeploy="false"', 'empty': 'fail'}, {'re': r'deployOnStartup="false"', 'empty': 'fail'}],
    '访问日志启用': [{'re': r'AccessLogValve', 'empty': 'fail'}],
    '错误页面不泄露信息': [{'re': r'error-page', 'empty': 'manual'}],
    '禁用不必要 Connector': [j_tomcat_ajp],
    'SSL/TLS 配置': [j_nginx_sslproto],
    '连接超时设置': [j_tomcat_ctimeout],
    '最大线程数限制': [{'re': r'maxThreads="\d+"', 'empty': 'manual'}],
}

RULES['rabbitmq'] = {
    '管理界面认证': [{'re': r'guest', 'neg': True, 'empty': 'manual'}],
    'VHost 权限隔离': [{'re': r'.', 'empty': 'manual'}],
}
RULES['nacos'] = {
    '控制台认证': [{'re': r'nacos\.core\.auth\.enabled\s*=\s*true', 'empty': 'fail'}],
    'API Token 认证': [{'re': r'nacos\.core\.auth\.(server\.identity|enabled)', 'empty': 'fail'}],
}


def get_judges(baseline, name):
    return RULES.get(baseline, {}).get(name)
