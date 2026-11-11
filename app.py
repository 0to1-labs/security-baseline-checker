# -*- coding: utf-8 -*-
"""安全基线检查系统 - Flask 应用"""
import os, json, threading, io, base64, re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

from cryptography.fernet import Fernet
import engine

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, 'data')
os.makedirs(DATA, exist_ok=True)
DB_PATH = os.path.join(DATA, 'checker.db')
KEY_PATH = os.path.join(DATA, 'secret.key')

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# ---------- 加密 ----------
def _fernet():
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, 'wb') as f:
            f.write(Fernet.generate_key())
    return Fernet(open(KEY_PATH, 'rb').read())

SK_PATH = os.path.join(DATA, 'session.key')

def _secret_key():
    if not os.path.exists(SK_PATH):
        import secrets
        with open(SK_PATH, 'w') as f:
            f.write(secrets.token_hex(32))
    return open(SK_PATH).read().strip()

app.secret_key = _secret_key()

def encrypt(s):
    return _fernet().encrypt(s.encode()).decode() if s else ''

def decrypt(s):
    try:
        return _fernet().decrypt(s.encode()).decode() if s else ''
    except Exception:
        return ''

# ---------- 检查库 ----------
LIB = json.load(open(os.path.join(BASE, 'checklib.json'), encoding='utf-8'))
BASELINES = {
    'linux': dict(name='Linux 主机', kind='host'),
    'windows': dict(name='Windows 主机', kind='host'),
    'mysql': dict(name='MySQL / MariaDB', kind='db'),
    'postgresql': dict(name='PostgreSQL', kind='db'),
    'oracle': dict(name='Oracle', kind='db'),
    'sqlserver': dict(name='SQL Server', kind='db'),
    'mongodb': dict(name='MongoDB', kind='db'),
    'redis_db': dict(name='Redis（数据库）', kind='db'),
    'dm': dict(name='达梦 DM', kind='db'),
    'nginx': dict(name='Nginx', kind='mw'),
    'apache': dict(name='Apache HTTP Server', kind='mw'),
    'tomcat': dict(name='Tomcat', kind='mw'),
    'weblogic': dict(name='WebLogic', kind='mw'),
    'kafka': dict(name='Kafka', kind='mw'),
    'redis_mw': dict(name='Redis（中间件）', kind='mw'),
    'rabbitmq': dict(name='RabbitMQ', kind='mw'),
    'nacos': dict(name='Nacos', kind='mw'),
}

# ---------- DB ----------
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE IF NOT EXISTS hosts(
          id INTEGER PRIMARY KEY, name TEXT, ip TEXT, port INTEGER DEFAULT 22,
          os_type TEXT DEFAULT 'linux', username TEXT, password_enc TEXT,
          db_user TEXT DEFAULT '', db_pass_enc TEXT DEFAULT '', created_at TEXT);
        CREATE TABLE IF NOT EXISTS tasks(
          id INTEGER PRIMARY KEY, host_id INTEGER, baseline TEXT, status TEXT,
          progress INTEGER DEFAULT 0, total INTEGER, message TEXT,
          created_at TEXT, finished_at TEXT);
        CREATE TABLE IF NOT EXISTS results(
          id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, item_id TEXT,
          category TEXT, name TEXT, mode TEXT, criteria TEXT, expected TEXT,
          why TEXT, detail TEXT, auto TEXT, verdict TEXT, manual TEXT);
        CREATE TABLE IF NOT EXISTS schedules(
          id INTEGER PRIMARY KEY, name TEXT, host_ids TEXT, mode TEXT DEFAULT 'auto',
          baselines TEXT DEFAULT '[]', sched_type TEXT, sched_val TEXT,
          enabled INTEGER DEFAULT 1, last_run TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS runs(
          id TEXT PRIMARY KEY, created_at TEXT, name TEXT, schedule_id INTEGER);
        ''')
        # 已有部署的字段迁移
        def _addcol(table, col, decl):
            cols = [r[1] for r in con.execute(f'PRAGMA table_info({table})')]
            if col not in cols:
                con.execute(f'ALTER TABLE {table} ADD COLUMN {col} {decl}')
        _addcol('hosts', 'conn_type', "TEXT DEFAULT 'ssh'")
        _addcol('tasks', 'run_group', 'TEXT')
        _addcol('tasks', 'schedule_id', 'INTEGER')
        _addcol('tasks', 'discovery', 'TEXT')
        if not con.execute('SELECT 1 FROM users').fetchone():
            con.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',
                        ('admin', generate_password_hash(os.environ.get('INIT_ADMIN_PASSWORD', 'Baseline@2026'))))

VERDICT_CN = {'pass': '符合', 'fail': '不符合', 'na': '不适用', 'manual': '待人工'}

# ---------- 登录 ----------
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get('uid'):
            return redirect(url_for('login'))
        return f(*a, **kw)
    return w

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password']
        with db() as con:
            row = con.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
        if row and check_password_hash(row['password_hash'], p):
            session['uid'] = row['id']
            session['username'] = u
            return redirect('/')
        error = '用户名或密码错误'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/password', methods=['GET', 'POST'])
@login_required
def password():
    msg = ''
    if request.method == 'POST':
        old, new = request.form['old'], request.form['new']
        with db() as con:
            row = con.execute('SELECT * FROM users WHERE id=?', (session['uid'],)).fetchone()
            if check_password_hash(row['password_hash'], old):
                con.execute('UPDATE users SET password_hash=? WHERE id=?',
                            (generate_password_hash(new), session['uid']))
                msg = 'ok'
            else:
                msg = '旧密码错误'
    return render_template('password.html', msg=msg)

# ---------- 首页/任务 ----------
@app.route('/')
@login_required
def index():
    with db() as con:
        tasks = con.execute('''SELECT t.*, h.name AS hname, h.ip FROM tasks t
                               LEFT JOIN hosts h ON h.id=t.host_id
                               ORDER BY t.id DESC LIMIT 200''').fetchall()
    tasks2 = []
    for t in tasks:
        t = dict(t)
        with db() as con:
            stats = con.execute('''SELECT verdict, COUNT(*) c FROM results
                                   WHERE task_id=? GROUP BY verdict''', (t['id'],)).fetchall()
        t['stats'] = {r['verdict']: r['c'] for r in stats}
        tasks2.append(t)
    gmap, singles, order = {}, [], []
    for t in tasks2:
        if t['run_group']:
            if t['run_group'] not in gmap:
                gmap[t['run_group']] = []
                order.append(t['run_group'])
            gmap[t['run_group']].append(t)
        else:
            singles.append(t)
    groups = []
    if order:
        with db() as con:
            q = ','.join('?' * len(order))
            runs = {r['id']: dict(r) for r in con.execute(f'SELECT * FROM runs WHERE id IN ({q})', order).fetchall()}
        for gid in order:
            if not gmap[gid]:
                continue
            g = dict(runs.get(gid, {'id': gid, 'name': '批量运行', 'created_at': ''}))
            g['tasks'] = gmap[gid]
            agg = {'pass': 0, 'fail': 0, 'na': 0, 'manual': 0, 'done': 0, 'running': 0, 'error': 0}
            for t in g['tasks']:
                for k in ('pass', 'fail', 'na', 'manual'):
                    agg[k] += t['stats'].get(k, 0)
                if t['status'] == 'done':
                    agg['done'] += 1
                elif t['status'] == 'error':
                    agg['error'] += 1
                else:
                    agg['running'] += 1
            g['agg'] = agg
            g['hosts'] = len({t['host_id'] for t in g['tasks']})
            groups.append(g)
    return render_template('index.html', tasks=singles, groups=groups, vc=VERDICT_CN,
                           baselines=BASELINES)

@app.route('/hosts', methods=['GET', 'POST'])
@login_required
def hosts():
    if request.method == 'POST':
        fid = request.form.get('id')
        conn_type = request.form.get('conn_type', 'ssh')
        port_raw = request.form.get('port', '').strip()
        port = int(port_raw) if port_raw else (5985 if conn_type == 'winrm' else 22)
        vals = (request.form['name'], request.form['ip'], port,
                request.form.get('os_type', 'linux'), request.form['username'],
                request.form.get('password', ''), request.form.get('db_user', ''),
                request.form.get('db_pass', ''))
        enc = encrypt(vals[5])
        encdb = encrypt(vals[7])
        with db() as con:
            if fid:
                con.execute('''UPDATE hosts SET name=?,ip=?,port=?,os_type=?,conn_type=?,username=?,
                               password_enc=COALESCE(NULLIF(?, ''),password_enc),
                               db_user=?, db_pass_enc=COALESCE(NULLIF(?, ''),db_pass_enc)
                               WHERE id=?''',
                            (vals[0], vals[1], vals[2], vals[3], conn_type, vals[4], enc, vals[6], encdb, fid))
            else:
                con.execute('''INSERT INTO hosts(name,ip,port,os_type,conn_type,username,password_enc,db_user,db_pass_enc,created_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?)''',
                            (vals[0], vals[1], vals[2], vals[3], conn_type, vals[4], enc, vals[6], encdb,
                             datetime.now().strftime('%Y-%m-%d %H:%M')))
    with db() as con:
        rows = con.execute('SELECT * FROM hosts ORDER BY id DESC').fetchall()
    return render_template('hosts.html', hosts=rows, import_result=None)


@app.route('/hosts/import', methods=['POST'])
@login_required
def hosts_import():
    """批量导入主机：粘贴文本或上传 CSV。
    列顺序：名称,IP,端口,系统类型,连接方式,账号,密码,数据库账号,数据库密码"""
    text = request.form.get('import_text', '')
    f = request.files.get('import_file')
    if f and f.filename:
        try:
            text = f.read().decode('utf-8-sig')
        except Exception:
            text = ''
    ok, bad = 0, []
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    for ln, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        for sep in ('\t', ',', '，'):
            if sep in line:
                parts = [p.strip() for p in line.split(sep)]
                break
        else:
            parts = [line]
        if ln == 1 and len(parts) >= 2 and parts[0] in ('名称', '主机', 'name', 'Name') \
                and parts[1].lower().startswith('ip'):
            continue  # 表头
        if len(parts) < 5:
            bad.append(f'第{ln}行: 列数不足（至少需要 名称,IP,系统类型,连接方式,账号,密码）')
            continue
        try:
            name, ip = parts[0], parts[1]
            os_type = 'windows' if 'win' in parts[3].lower() else 'linux'
            conn_type = 'winrm' if 'winrm' in parts[4].lower() else 'ssh'
            port = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else (5985 if conn_type == 'winrm' else 22)
            user = parts[5] if len(parts) > 5 else parts[4]
            pwd = parts[6] if len(parts) > 6 else ''
            dbu = parts[7] if len(parts) > 7 else ''
            dbp = parts[8] if len(parts) > 8 else ''
            with db() as con:
                con.execute('''INSERT INTO hosts(name,ip,port,os_type,conn_type,username,password_enc,db_user,db_pass_enc,created_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?)''',
                            (name, ip, port, os_type, conn_type, user, encrypt(pwd), dbu, encrypt(dbp), now))
            ok += 1
        except Exception as e:
            bad.append(f'第{ln}行: {e}')
    import_result = dict(ok=ok, bad=bad)
    with db() as con:
        rows = con.execute('SELECT * FROM hosts ORDER BY id DESC').fetchall()
    return render_template('hosts.html', hosts=rows, import_result=import_result)

@app.route('/hosts/delete/<int:hid>', methods=['POST'])
@login_required
def host_delete(hid):
    with db() as con:
        con.execute('DELETE FROM hosts WHERE id=?', (hid,))
    return redirect('/hosts')

@app.route('/check/new', methods=['GET', 'POST'])
@login_required
def check_new():
    if request.method == 'POST':
        host_ids = [int(x) for x in request.form.getlist('host_ids')]
        mode = request.form.get('mode', 'fixed')
        baseline = request.form.get('baseline', 'linux')
        if not host_ids:
            return redirect('/check/new')
        if mode == 'auto' or len(host_ids) > 1:
            gid = start_batch(host_ids, mode, [baseline] if mode == 'fixed' else [],
                              f'手动批量 {datetime.now().strftime("%m-%d %H:%M")}')
            return redirect(f'/run/{gid}')
        with db() as con:
            con.execute('INSERT INTO tasks(host_id,baseline,status,progress,total,created_at) VALUES(?,?,?,?,?,?)',
                        (host_ids[0], baseline, 'pending', 0, len(LIB[baseline]),
                         datetime.now().strftime('%Y-%m-%d %H:%M')))
            tid = con.execute('SELECT MAX(id) id FROM tasks').fetchone()['id']
        threading.Thread(target=run_task, args=(tid,), daemon=True).start()
        return redirect(f'/task/{tid}')
    with db() as con:
        hrows = con.execute('SELECT * FROM hosts ORDER BY id DESC').fetchall()
    return render_template('check_new.html', hosts=hrows, baselines=BASELINES)

TASK_LOCK = threading.Lock()


def create_task(host_id, baseline, run_group=None, schedule_id=None, discovery=None):
    with db() as con:
        con.execute('''INSERT INTO tasks(host_id,baseline,status,progress,total,created_at,
                       run_group,schedule_id,discovery) VALUES(?,?,?,?,?,?,?,?,?)''',
                    (host_id, baseline, 'pending', 0, len(LIB[baseline]),
                     datetime.now().strftime('%Y-%m-%d %H:%M'), run_group, schedule_id,
                     json.dumps(discovery, ensure_ascii=False) if discovery else None))
        return con.execute('SELECT MAX(id) id FROM tasks').fetchone()['id']


def start_batch(host_ids, mode, fixed_baselines, name, schedule_id=None):
    """创建批量运行组，后台线程依次对每台主机探测（auto）并执行各基线"""
    import uuid
    gid = uuid.uuid4().hex[:12]
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    with db() as con:
        con.execute('INSERT INTO runs(id,created_at,name,schedule_id) VALUES(?,?,?,?)',
                    (gid, now, name, schedule_id))

    def worker():
        for hid in host_ids:
            with db() as con:
                host = con.execute('SELECT * FROM hosts WHERE id=?', (hid,)).fetchone()
            if not host:
                continue
            host = dict(host)
            keys, disc = [], None
            if mode == 'auto':
                try:
                    runner = engine.make_runner(host, decrypt(host['password_enc']))
                    runner.connect()
                    disc = engine.discover(runner)
                    runner.close()
                    keys = [host['os_type']] if host['os_type'] in ('linux', 'windows') else ['linux']
                    keys += [k for k in disc['keys'] if k in LIB and k not in keys]
                except Exception as e:
                    osb = 'windows' if host['os_type'] == 'windows' else 'linux'
                    tid = create_task(hid, osb, gid, schedule_id, {'error': str(e)})
                    with db() as con:
                        con.execute("UPDATE tasks SET status='error', message=?, finished_at=? WHERE id=?",
                                    (f'连接失败: {e}', datetime.now().strftime('%Y-%m-%d %H:%M'), tid))
                    continue
            else:
                keys = [b for b in fixed_baselines if b in LIB]
            if not keys:
                continue
            for k in keys:
                tid = create_task(hid, k, gid, schedule_id,
                                  disc if k in ('linux', 'windows') else None)
                run_task(tid)
    threading.Thread(target=worker, daemon=True).start()
    return gid

def run_task(tid):
    with TASK_LOCK:
        with db() as con:
            task = con.execute('SELECT * FROM tasks WHERE id=?', (tid,)).fetchone()
            host = con.execute('SELECT * FROM hosts WHERE id=?', (task['host_id'],)).fetchone()
            con.execute("UPDATE tasks SET status='running', message='正在连接目标主机…' WHERE id=?", (tid,))
        if not task or not host:
            return
        host = dict(host)
        items = LIB[task['baseline']]
        try:
            runner = engine.make_runner(host, decrypt(host['password_enc']))
            runner.connect()
        except Exception as e:
            with db() as con:
                con.execute("UPDATE tasks SET status='error', message=?, finished_at=? WHERE id=?",
                            (f'SSH 连接失败: {e}', datetime.now().strftime('%Y-%m-%d %H:%M'), tid))
            return
        ctx = dict(db_user=host['db_user'] or '', db_pass=decrypt(host['db_pass_enc']))
        for i, item in enumerate(items):
            try:
                r = engine.run_item(runner, item, ctx)
            except Exception as e:
                r = {'steps': [], 'auto': 'manual', 'verdict': 'manual',
                     'error': str(e)}
            with db() as con:
                con.execute('''INSERT INTO results(task_id,item_id,category,name,mode,criteria,expected,why,detail,auto,verdict,manual)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                            (tid, item['id'], item['category'], item['name'], item.get('mode', ''),
                             item.get('criteria', ''), item.get('expected', ''), item.get('why', ''),
                             json.dumps(r, ensure_ascii=False), r['auto'], r['verdict'], ''))
                con.execute('UPDATE tasks SET progress=?, message=? WHERE id=?',
                            (i + 1, item['name'], tid))
        runner.close()
        with db() as con:
            con.execute("UPDATE tasks SET status='done', finished_at=? WHERE id=?",
                       (datetime.now().strftime('%Y-%m-%d %H:%M'), tid))

@app.route('/task/<int:tid>')
@login_required
def task_view(tid):
    with db() as con:
        task = con.execute('''SELECT t.*, h.name hname, h.ip, h.os_type FROM tasks t
                              LEFT JOIN hosts h ON h.id=t.host_id WHERE t.id=?''', (tid,)).fetchone()
        results = con.execute('SELECT * FROM results WHERE task_id=? ORDER BY id', (tid,)).fetchall()
    cats, stats = {}, {'pass': 0, 'fail': 0, 'na': 0, 'manual': 0}
    for r in results:
        v = r['manual'] or r['verdict']
        stats[v] = stats.get(v, 0) + 1
        c = cats.setdefault(r['category'], {'pass': 0, 'fail': 0, 'na': 0, 'manual': 0, 'total': 0})
        c[v] = c.get(v, 0) + 1
        c['total'] += 1
    should = stats['pass'] + stats['fail']
    rate = f"{stats['pass']/should*100:.0f}%" if should else '-'
    return render_template('task.html', task=task, results=results, cats=cats,
                           stats=stats, rate=rate, vc=VERDICT_CN,
                           bl_name=BASELINES[task['baseline']]['name'])

@app.route('/task/<int:tid>/verdict', methods=['POST'])
@login_required
def set_verdict(tid):
    data = request.get_json()
    with db() as con:
        con.execute('UPDATE results SET manual=? WHERE task_id=? AND item_id=?',
                    (data['verdict'], tid, data['item']))
    return jsonify(ok=True)

@app.route('/task/<int:tid>/status')
@login_required
def task_status(tid):
    with db() as con:
        t = con.execute('SELECT status,progress,total,message FROM tasks WHERE id=?', (tid,)).fetchone()
    return jsonify(dict(t))

@app.route('/task/<int:tid>/delete', methods=['POST'])
@login_required
def task_delete(tid):
    with db() as con:
        con.execute('DELETE FROM tasks WHERE id=?', (tid,))
        con.execute('DELETE FROM results WHERE task_id=?', (tid,))
    return redirect('/')

# ---------- Word 报告 ----------
@app.route('/task/<int:tid>/export')
@login_required
def export(tid):
    from docx import Document
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    with db() as con:
        task = con.execute('''SELECT t.*, h.name hname, h.ip FROM tasks t
                              LEFT JOIN hosts h ON h.id=t.host_id WHERE t.id=?''', (tid,)).fetchone()
        results = con.execute('SELECT * FROM results WHERE task_id=? ORDER BY id', (tid,)).fetchall()
    doc = Document()
    style = doc.styles['Normal']
    style.font.name = '微软雅黑'
    style.font.size = Pt(10)
    style.element.rPr.rFonts.set(__import__('docx').oxml.ns.qn('w:eastAsia'), '微软雅黑')

    h = doc.add_heading('安全基线检查报告', level=0)
    h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph()
    p.add_run(f'检查对象：{task["hname"]}（{task["ip"]}）\n'
              f'基线类型：{BASELINES[task["baseline"]]["name"]}\n'
              f'检查时间：{task["created_at"]}\n'
              f'检查工具：安全基线检查系统（依据基线检查指导书 V1.0）')

    stats = {'pass': 0, 'fail': 0, 'na': 0, 'manual': 0}
    for r in results:
        stats[manual_of(r)] = stats.get(manual_of(r), 0) + 1
    should = stats['pass'] + stats['fail']
    doc.add_heading('一、检查结果汇总', level=1)
    tb = doc.add_table(rows=2, cols=7)
    tb.style = 'Table Grid'
    heads = ['检查项数', '符合', '不符合', '不适用', '待人工', '符合率', '检查结论']
    vals = [len(results), stats['pass'], stats['fail'], stats['na'], stats['manual'],
            f"{stats['pass']/should*100:.0f}%" if should else '-',
            '符合' if stats['fail'] == 0 and should and stats['pass'] == should else '存在不符合项，需整改']
    for i, (hh, vv) in enumerate(zip(heads, vals)):
        tb.rows[0].cells[i].text = hh
        tb.rows[1].cells[i].text = str(vv)

    doc.add_heading('二、不符合项清单', level=1)
    fails = [r for r in results if manual_of(r) == 'fail']
    if not fails:
        doc.add_paragraph('无不符合项。')
    for r in fails:
        p = doc.add_paragraph(style='List Number')
        p.add_run(f'【{r["category"]}】{r["name"]}').bold = True
        doc.add_paragraph(f'通过标准：{r["criteria"] or r["expected"]}')
        det = json.loads(r['detail'])
        outs = [s.get('out', '').strip() for s in det.get('steps', []) if s.get('out', '').strip()]
        if outs:
            doc.add_paragraph('检查输出：' + outs[0][:500])

    doc.add_heading('三、检查明细', level=1)
    tb = doc.add_table(rows=1, cols=5)
    tb.style = 'Table Grid'
    for i, hh in enumerate(['类别', '检查项', '判定', '通过标准', '检查输出']):
        tb.rows[0].cells[i].text = hh
    for r in results:
        det = json.loads(r['detail'])
        outs = []
        for s in det.get('steps', []):
            o = (s.get('out', '') or '').strip()
            e = (s.get('err', '') or '').strip()
            txt = (o + (' [err] ' + e if e else '')).replace('\n', ' ')[:300]
            if s.get('cmd'):
                outs.append(f"$ {s['cmd'][:80]}\n{txt}")
        row = tb.add_row()
        row.cells[0].text = r['category']
        row.cells[1].text = r['name']
        c = row.cells[2]
        c.text = VERDICT_CN[manual_of(r)]
        if manual_of(r) == 'fail':
            c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xC0, 0x00, 0x00)
        elif manual_of(r) == 'pass':
            c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x00, 0x80, 0x00)
        row.cells[3].text = (r['criteria'] or r['expected'] or '')[:200]
        row.cells[4].text = '\n'.join(outs)[:600]

    doc.add_heading('四、说明', level=1)
    doc.add_paragraph('1. 检查命令均为只读命令，不修改目标系统任何配置。')
    doc.add_paragraph('2. "待人工"项为指导书中标注人工核查/部分人工的检查项，'
                      '自动采集了命令输出供人工判定参考，请按人工核查项清单执行后确认。')
    doc.add_paragraph('3. 符合率 = 符合 ÷（符合 + 不符合），不含不适用与待人工项。')

    bio = io.BytesIO()
    doc.save(bio)
    bio.seek(0)
    fname = f'基线检查报告_{task["ip"]}_{task["created_at"][:10]}.docx'
    return send_file(bio, as_attachment=True, download_name=fname,
                     mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

def manual_of(r):
    return r['manual'] or r['verdict']

# ---------- 检查库查看 ----------
@app.route('/library')
@login_required
def library():
    b = request.args.get('b', 'linux')
    return render_template('library.html', items=LIB.get(b, []), baselines=BASELINES, cur=b)

# ---------- 运行组 ----------
@app.route('/run/<gid>')
@login_required
def run_view(gid):
    with db() as con:
        run = con.execute('SELECT * FROM runs WHERE id=?', (gid,)).fetchone()
        tasks = con.execute('''SELECT t.*, h.name hname, h.ip FROM tasks t
                                LEFT JOIN hosts h ON h.id=t.host_id
                                WHERE t.run_group=? ORDER BY t.id''', (gid,)).fetchall()
    tasks2 = []
    all_done = True
    for t in tasks:
        t = dict(t)
        if t['status'] not in ('done', 'error'):
            all_done = False
        with db() as con:
            stats = con.execute('''SELECT verdict, COUNT(*) c FROM results
                                   WHERE task_id=? GROUP BY verdict''', (t['id'],)).fetchall()
        t['stats'] = {r['verdict']: r['c'] for r in stats}
        if t.get('discovery'):
            try:
                t['disc'] = json.loads(t['discovery'])
            except Exception:
                t['disc'] = None
        tasks2.append(t)
    return render_template('run.html', run=run, tasks=tasks2, vc=VERDICT_CN,
                           baselines=BASELINES, det_names=engine.DETECT_MAP,
                           all_done=all_done)


# ---------- 定时任务 ----------
@app.route('/schedules', methods=['GET', 'POST'])
@login_required
def schedules():
    if request.method == 'POST':
        host_ids = request.form.getlist('host_ids')
        mode = request.form.get('mode', 'auto')
        baselines = request.form.getlist('baselines') if mode == 'fixed' else []
        sched_type = request.form.get('sched_type', 'daily')
        if sched_type == 'daily':
            sched_val = request.form.get('time_daily', '02:00')
        elif sched_type == 'hours':
            sched_val = request.form.get('interval_hours', '24')
        else:
            sched_val = request.form.get('weekday', '1') + ' ' + request.form.get('time_weekly', '02:00')
        if host_ids:
            with db() as con:
                con.execute('''INSERT INTO schedules(name,host_ids,mode,baselines,sched_type,sched_val,enabled,created_at)
                               VALUES(?,?,?,?,?,?,1,?)''',
                            (request.form.get('name', '定时扫描'), json.dumps([int(x) for x in host_ids]),
                             mode, json.dumps(baselines), sched_type, sched_val,
                             datetime.now().strftime('%Y-%m-%d %H:%M')))
    with db() as con:
        rows = con.execute('SELECT * FROM schedules ORDER BY id DESC').fetchall()
        hrows = con.execute('SELECT id,name,ip,os_type FROM hosts ORDER BY id DESC').fetchall()
    scheds = []
    for s in rows:
        s = dict(s)
        s['host_ids'] = json.loads(s['host_ids'] or '[]')
        s['baselines'] = json.loads(s['baselines'] or '[]')
        s['next'] = next_run_text(s)
        hmap = {h['id']: h['name'] for h in hrows}
        s['host_names'] = [hmap.get(h, str(h)) for h in s['host_ids']]
        scheds.append(s)
    return render_template('schedules.html', schedules=scheds, hosts=hrows, baselines=BASELINES)


@app.route('/schedules/<int:sid>/<action>', methods=['POST'])
@login_required
def schedule_action(sid, action):
    with db() as con:
        s = con.execute('SELECT * FROM schedules WHERE id=?', (sid,)).fetchone()
        if not s:
            return redirect('/schedules')
        if action == 'toggle':
            con.execute('UPDATE schedules SET enabled=1-enabled WHERE id=?', (sid,))
        elif action == 'delete':
            con.execute('DELETE FROM schedules WHERE id=?', (sid,))
        elif action == 'run':
            start_batch(json.loads(s['host_ids']), s['mode'], json.loads(s['baselines'] or '[]'),
                        f'定时:{s["name"]}（手动触发）', schedule_id=sid)
    return redirect('/schedules')


def _parse_hm(val):
    try:
        h, m = val.split(':')
        return int(h), int(m)
    except Exception:
        return 2, 0


def next_run_text(s):
    """估算下次运行时间（用于展示）"""
    now = datetime.now()
    try:
        last = datetime.strptime(s['last_run'], '%Y-%m-%d %H:%M') if s['last_run'] else None
    except Exception:
        last = None
    if s['sched_type'] == 'hours':
        n = max(1, int(s['sched_val'] or 24))
        base = last or now
        nxt = base + timedelta(hours=n)
        return f'每 {n} 小时（下次约 {nxt.strftime("%m-%d %H:%M")}）'
    if s['sched_type'] == 'daily':
        h, m = _parse_hm(s['sched_val'])
        nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        return f'每天 {s["sched_val"]}（下次 {nxt.strftime("%m-%d %H:%M")}）'
    try:
        wday, hm = s['sched_val'].split()
        wday = int(wday)
        h, m = _parse_hm(hm)
        days_ahead = (wday - 1 - now.weekday()) % 7
        nxt = now.replace(hour=h, minute=m, second=0, microsecond=0) + timedelta(days=days_ahead)
        if nxt <= now:
            nxt += timedelta(days=7)
        return f'每周{["一","二","三","四","五","六","日"][wday-1]} {hm}（下次 {nxt.strftime("%m-%d %H:%M")}）'
    except Exception:
        return s['sched_val']


def check_schedules():
    now = datetime.now()
    with db() as con:
        rows = con.execute('SELECT * FROM schedules WHERE enabled=1').fetchall()
    for s in rows:
        s = dict(s)
        try:
            last = datetime.strptime(s['last_run'], '%Y-%m-%d %H:%M') if s['last_run'] else None
        except Exception:
            last = None
        due = False
        if s['sched_type'] == 'hours':
            n = max(1, int(s['sched_val'] or 24))
            due = last is None or (now - last).total_seconds() >= n * 3600
        elif s['sched_type'] == 'daily':
            h, m = _parse_hm(s['sched_val'])
            due = (last is None or last.date() < now.date()) and \
                  (now.hour, now.minute) >= (h, m)
        else:
            try:
                wday, hm = s['sched_val'].split()
                h, m = _parse_hm(hm)
                due = now.weekday() + 1 == int(wday) and (now.hour, now.minute) >= (h, m) and \
                      (last is None or last.date() < now.date())
            except Exception:
                due = False
        if due:
            with db() as con:
                con.execute('UPDATE schedules SET last_run=? WHERE id=?',
                            (now.strftime('%Y-%m-%d %H:%M'), s['id']))
            start_batch(json.loads(s['host_ids'] or '[]'), s['mode'],
                        json.loads(s['baselines'] or '[]'),
                        f'定时:{s["name"]}', schedule_id=s['id'])


def scheduler_loop():
    import time
    while True:
        try:
            check_schedules()
        except Exception:
            pass
        time.sleep(30)


def start_scheduler():
    threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == '__main__':
    init_db()
    start_scheduler()
    app.run(host='0.0.0.0', port=8090)
