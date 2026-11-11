# -*- coding: utf-8 -*-
"""一键部署脚本：通过 SSH 把本目录上传到 Linux 服务器并安装 systemd 服务

用法（凭据通过环境变量提供，不要写进代码）：
  export DEPLOY_HOST=1.2.3.4
  export DEPLOY_USER=root
  export DEPLOY_PASSWORD='your-password'
  export DEPLOY_DIR=/opt/security-baseline    # 可选，默认 /opt/security-baseline
  python deploy.py
"""
import os, sys, time
import paramiko

HOST = os.environ.get('DEPLOY_HOST')
USER = os.environ.get('DEPLOY_USER', 'root')
PWD = os.environ.get('DEPLOY_PASSWORD', '')
REMOTE = os.environ.get('DEPLOY_DIR', '/opt/security-baseline')
PORT = int(os.environ.get('DEPLOY_PORT', '22'))

if not HOST or not PWD:
    print('请先设置环境变量：DEPLOY_HOST / DEPLOY_USER / DEPLOY_PASSWORD')
    sys.exit(1)

LOCAL = os.path.dirname(os.path.abspath(__file__))
FILES = ['app.py', 'engine.py', 'rules.py', 'parse_lib.py', 'checklib.json',
         'requirements.txt', 'baseline-checker.service']

print(f'== 连接 {USER}@{HOST}:{PORT}')
cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect(HOST, PORT, USER, PWD, timeout=20)


def run(cmd, timeout=600):
    stdin, stdout, stderr = cli.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', 'replace')
    err = stderr.read().decode('utf-8', 'replace')
    rc = stdout.channel.recv_exit_status()
    if rc != 0:
        print(f'   命令失败({rc}): {cmd}\n   {err[:300]}')
    return out, err, rc


run(f'mkdir -p {REMOTE}/templates {REMOTE}/static')
run('id -u blchecker >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin blchecker')

print('== 上传文件')
sftp = cli.open_sftp()
for f in FILES:
    sftp.put(os.path.join(LOCAL, f), f'{REMOTE}/{f}')
    print('   ', f)
for d in ('templates', 'static'):
    for f in os.listdir(os.path.join(LOCAL, d)):
        sftp.put(os.path.join(LOCAL, d, f), f'{REMOTE}/{d}/{f}')
        print(f'    {d}/{f}')
sftp.close()

print('== 安装依赖')
run(f'cd {REMOTE} && python3 -m venv venv && '
    f'venv/bin/pip install -q -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt')

print('== 安装 systemd 服务')
run(f'chown -R blchecker:blchecker {REMOTE}')
run(f'sed "s|/opt/security-baseline|{REMOTE}|g" {REMOTE}/baseline-checker.service '
    f'> /etc/systemd/system/baseline-checker.service')
run('systemctl daemon-reload && systemctl enable baseline-checker && systemctl restart baseline-checker')

time.sleep(3)
print('== 验证')
out, err, rc = run('systemctl is-active baseline-checker && '
                   'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8090/login')
print('   服务状态 + 页面HTTP码:', out.strip())
cli.close()
print(f'\n部署完成：http://{HOST}:8090  （默认账号 admin，初始密码可用环境变量 INIT_ADMIN_PASSWORD 自定义）')
