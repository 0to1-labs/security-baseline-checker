# -*- coding: utf-8 -*-
"""把四份基线检查指导书 docx 解析为结构化检查库 JSON"""
import zipfile, json, re, sys, io, os
import xml.etree.ElementTree as ET

W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
DOCS = sys.argv[1] if len(sys.argv) > 1 \
    else os.environ.get('BASELINE_DOCS_DIR', './docs')

DB_PRODUCTS = {
    'MySQL/MariaDB': 'mysql', 'PostgreSQL': 'postgresql', 'Oracle': 'oracle',
    'SQL Server': 'sqlserver', 'MongoDB': 'mongodb', 'Redis（数据库）': 'redis_db',
    '达梦 DM': 'dm',
}
MW_PRODUCTS = {
    'Nginx': 'nginx', 'Apache HTTP Server': 'apache', 'Tomcat': 'tomcat',
    'WebLogic': 'weblogic', 'Kafka': 'kafka', 'Redis': 'redis_mw',
    'RabbitMQ': 'rabbitmq', 'Nacos': 'nacos',
}
CATEGORY_RE = re.compile(r'^[一二三四五六七]、(.+)$')


def para_text(p):
    return ''.join(el.text or '' for el in p.iter(W + 't')).strip()


def cell_paras(tc):
    return [t for t in (para_text(p) for p in tc.findall(f'.//{W}p')) if t]


def parse_cmd_cell(paras):
    """Linux/Windows 指导书：检查命令列是多段落结构"""
    mode, content, commands, criteria, manual = '人工核查', '', [], '', ''
    collecting = False
    started = False
    for p in paras:
        if not started and p.startswith('【'):
            m = p.strip('【】').rstrip('*')
            mode = m
            started = True
        elif p.startswith('检查内容：'):
            content = p.split('：', 1)[1]; collecting = False
        elif p.startswith('检查命令：'):
            rest = p.split('：', 1)[1].strip()
            if rest:
                commands.append(rest)
            collecting = True
        elif p.startswith('通过标准：'):
            criteria = p.split('：', 1)[1]; collecting = False
        elif p.startswith('需人工核实：'):
            manual = p.split('：', 1)[1]; collecting = False
        elif collecting:
            commands.append(p)
    return mode, content, commands, criteria, manual


GUIDANCE_RE = re.compile(r'^(检查|查看|尝试登录|控制台|列出)')
SQL_RE = re.compile(r'^(SELECT|SHOW|EXEC|WITH|DECLARE)\b', re.I)


def parse_cmd_blob(text):
    """数据库/中间件指导书：检查命令列是单段落文本"""
    text = text.strip()
    idx = text.find('通过标准')
    criteria, manual = '', ''
    if idx >= 0:
        criteria = text[idx:]
        criteria = criteria.split('：', 1)[1] if '：' in criteria else criteria.replace('通过标准', '', 1)
        text = text[:idx].strip()
    if text.startswith('检查命令：'):
        text = text.split('：', 1)[1].strip()
    manual_m = re.search(r'需人工核实[：:]', text)
    if manual_m:
        manual = text[manual_m.end():].strip()
        text = text[:manual_m.start()].strip()
    text = text.rstrip(';；').strip()
    parts = [s.strip().rstrip(';；').strip() for s in re.split(r';\s*(?=[A-Za-z])', text)]
    commands = [s for s in parts if s]
    return commands, criteria, manual


def parse_doc(path, doc_kind):
    """doc_kind: 'host' (Linux/Windows) 或 'product' (数据库/中间件)"""
    with zipfile.ZipFile(path) as z:
        root = ET.fromstring(z.read('word/document.xml'))
    body = root.find(f'{W}body')
    items = []
    category = ''
    product = ''
    for el in body:
        tag = el.tag.split('}')[1]
        if tag == 'p':
            t = para_text(el)
            if not t:
                continue
            m = CATEGORY_RE.match(t)
            if m:
                category = t
            if doc_kind == 'product':
                prods = DB_PRODUCTS if '数据库' in path else MW_PRODUCTS
                if t in prods:
                    product = t
            continue
        if tag != 'tbl':
            continue
        rows = [[cell_paras(tc) for tc in tr.findall(W + 'tc')] for tr in el.findall(W + 'tr')]
        if not rows:
            continue
        header = [' '.join(c) for c in rows[0]]
        if '检查项' not in header[0]:
            continue
        for r in rows[1:]:
            if not r or not r[0]:
                continue
            name = r[0][0] if r[0] else ''
            if not name or name.startswith('检查项'):
                continue
            desc = ' '.join(r[1]) if len(r) > 1 else ''
            why = ' '.join(r[2]) if len(r) > 2 else ''
            expected = ' '.join(r[3]) if len(r) > 3 else ''
            if len(r) < 5:
                continue
            if doc_kind == 'host':
                cmdcell = r[5] if len(r) >= 6 else r[-1]
                mode, content, commands, criteria, manual = parse_cmd_cell(cmdcell)
                item = dict(baseline=None, category=category, name=name, desc=desc, why=why,
                            expected=expected, mode=mode, content=content,
                            commands=commands, criteria=criteria, manual_note=manual)
            else:
                blob = ' '.join(r[4])
                if name.startswith('（不适用）'):
                    note = desc or blob
                    item = dict(baseline=None, category=category, name='（不适用）' + category,
                                desc=note, why='', expected='', mode='不适用',
                                content='', commands=[], criteria=note, manual_note='')
                else:
                    commands, criteria, manual = parse_cmd_blob(blob)
                    mode = '人工核查' if all(GUIDANCE_RE.match(c) for c in commands) else '命令可查'
                    item = dict(baseline=None, category=category, name=name, desc=desc, why=why,
                                expected=expected, mode=mode, content='',
                                commands=commands, criteria=criteria, manual_note=manual)
                item['product'] = product
            items.append(item)
    return items


def main():
    lib = {}
    linux = parse_doc(DOCS + '\\Linux主机安全基线检查指导书.docx', 'host')
    windows = parse_doc(DOCS + '\\Windows主机安全基线检查指导书.docx', 'host')
    for it in linux:
        it['baseline'] = 'linux'
    for it in windows:
        it['baseline'] = 'windows'
    lib['linux'], lib['windows'] = linux, windows

    db = parse_doc(DOCS + '\\数据库安全基线检查指导书.docx', 'product')
    mw = parse_doc(DOCS + '\\中间件安全基线检查指导书.docx', 'product')
    for it in db:
        key = DB_PRODUCTS.get(it.pop('product'))
        it['baseline'] = key
        lib.setdefault(key, []).append(it)
    for it in mw:
        key = MW_PRODUCTS.get(it.pop('product'))
        it['baseline'] = key
        lib.setdefault(key, []).append(it)

    out = {}
    for key, items in lib.items():
        seen = set()
        for i, it in enumerate(items):
            base = it['name']
            n = 1
            while it['name'] in seen:
                n += 1
                it['name'] = f'{base}({n})'
            seen.add(it['name'])
            it['id'] = f'{key}:{i+1}'
        out[key] = items
    with io.open('checklib.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    sys.stdout.reconfigure(encoding='utf-8')
    for k, v in out.items():
        auto = sum(1 for x in v if x['mode'] in ('命令可查', '命令可查*'))
        print(f'{k:12s} {len(v):3d}项  (命令可查 {auto}, 人工 {len(v)-auto})')
    # 校验：抽几项看解析质量
    for k in ('linux', 'mysql', 'nginx'):
        it = out[k][0]
        print('---', k, '示例:', it['name'], '| 命令数:', len(it['commands']))
        for c in it['commands'][:3]:
            print('   $', c[:120])


if __name__ == '__main__':
    main()
