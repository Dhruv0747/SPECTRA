"""Portable case storage, evidence normalization, and offline reporting."""
import hashlib
import html
import ipaddress
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent.parent
CONFIDENCE = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CONFIRMED': 3}
TYPES = ('Auto', 'Name', 'Email', 'Phone', 'Username', 'Domain', 'IP', 'URL', 'Image')
DEFAULTS = {'shodan_api_key': '', 'hibp_api_key': '', 'spiderfoot_url': 'http://127.0.0.1:5001',
            'spiderfoot_enabled': True, 'auto_pivot': False, 'pivot_depth': 1,
            'timeout': 12, 'retries': 1, 'developer_mode': False,
            'connectors': ['DNS', 'InternetDB', 'GitHub', 'HIBP', 'Shodan', 'Image']}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temp.open('w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def classify_target(value):
    v = value.strip()
    if not v:
        return 'unknown'
    try:
        ipaddress.ip_address(v)
        return 'ip'
    except ValueError:
        pass
    if v.lower().startswith(('http://', 'https://')) and urlsplit(v).hostname:
        return 'url'
    if re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', v):
        return 'email'
    if re.fullmatch(r'\+?[\d ()-]+', v) and 8 <= sum(c.isdigit() for c in v) <= 15:
        return 'phone'
    if re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?', v):
        return 'domain'
    if re.fullmatch(r'@?[A-Za-z0-9._-]{1,40}', v):
        return 'username'
    return 'name'


def target(value, kind='Auto'):
    value = value.strip()
    kind = classify_target(value) if kind.lower() == 'auto' else kind.lower()
    if not value or kind not in [t.lower() for t in TYPES[1:]]:
        raise ValueError('Enter a supported target.')
    if kind == 'ip':
        value = str(ipaddress.ip_address(value))
    elif kind == 'url':
        u = urlsplit(value)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            raise ValueError('Enter an HTTP(S) URL without credentials.')
    elif kind == 'domain':
        value = value.lower().rstrip('.')
        if classify_target(value) != 'domain':
            raise ValueError('Enter a valid domain name.')
    elif kind == 'email' and classify_target(value) != 'email':
        raise ValueError('Enter a valid email address.')
    elif kind == 'username':
        value = value.lstrip('@')
    return {'value': value, 'type': kind}


def fingerprint(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]


def entity(kind, value):
    kind = kind.upper()
    if kind == 'NAME':
        kind = 'PERSON'
    value = str(value)
    if kind in ('DOMAIN', 'IP'):
        value = value.lower()
    return {'id': fingerprint(kind, value), 'type': kind, 'value': value}


def finding(title, source, original, detail, *, severity='INFO', confidence='HIGH',
            reference='', relation='OBSERVED', object_type=None, object_value=None,
            remediation='Review the evidence and validate relevance before taking action.', path=None):
    subject = entity(original['type'], original['value'])
    obj = entity(object_type or original['type'], object_value if object_value is not None else original['value'])
    evidence = {'provider': source, 'timestamp': now(), 'reference': reference,
                'original_target': dict(path[0] if path else original), 'pivot_path': path or [dict(original)], 'raw': detail}
    return {'id': fingerprint(title, subject['id'], obj['id'], relation), 'title': title,
            'source': source, 'severity': severity, 'confidence': confidence,
            'subject': subject, 'object': obj, 'relation': relation,
            'summary': str(detail.get('summary', title)), 'remediation': remediation,
            'evidence': [evidence], 'created': evidence['timestamp']}


def merge_finding(case, item):
    for old in case['findings']:
        if old['id'] == item['id']:
            for ev in item['evidence']:
                if ev not in old['evidence']:
                    old['evidence'].append(ev)
            if CONFIDENCE[item['confidence']] > CONFIDENCE[old['confidence']]:
                old['confidence'] = item['confidence']
            return False
    case['findings'].append(item)
    return True


class CaseStore:
    def __init__(self, root=APP_DIR):
        self.root = Path(root)
        for name in ('cases', 'reports', 'config', 'logs', 'cache', 'tools', 'assets', 'data'):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def settings(self):
        result = dict(DEFAULTS)
        result['connectors'] = list(DEFAULTS['connectors'])
        p = self.root / 'config/settings.json'
        if p.exists():
            data = json.loads(p.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('Settings must be a JSON object.')
            result.update(data)
        for key in ('timeout', 'retries', 'pivot_depth'):
            if type(result[key]) is not int or result[key] < (1 if key == 'timeout' else 0):
                raise ValueError('Invalid setting: ' + key)
        for key in ('shodan_api_key', 'hibp_api_key', 'spiderfoot_url'):
            if not isinstance(result[key], str):
                raise ValueError('Invalid setting: ' + key)
        if not isinstance(result['connectors'], list):
            raise ValueError('Invalid connector selection.')
        for key in ('spiderfoot_enabled', 'auto_pivot', 'developer_mode'):
            if type(result[key]) is not bool:
                raise ValueError('Invalid setting: ' + key)
        return result

    def save_settings(self, settings):
        atomic_json(self.root / 'config/settings.json', settings)

    def create(self, name, client='', authorization=''):
        if not name.strip():
            raise ValueError('A case name is required.')
        c = {'schema': 1, 'id': str(uuid.uuid4()), 'name': name.strip(), 'client': client.strip(),
             'authorization': authorization.strip(), 'created': now(), 'updated': now(),
             'archived': False, 'targets': [], 'findings': [], 'scans': [], 'reports': []}
        self.save(c)
        return c

    def save(self, case):
        uuid.UUID(case['id'])
        case['updated'] = now()
        atomic_json(self.root / 'cases' / (case['id'] + '.json'), case)

    def load(self, path):
        c = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(c, dict) or c.get('schema') != 1:
            raise ValueError('Unsupported case format.')
        uuid.UUID(c['id'])
        for key in ('targets', 'findings', 'scans', 'reports'):
            if not isinstance(c.get(key), list):
                raise ValueError('Invalid case: ' + key)
        for key in ('name', 'client', 'authorization', 'created', 'updated'):
            if not isinstance(c.get(key), str):
                raise ValueError('Invalid case: ' + key)
        if type(c.get('archived')) is not bool:
            raise ValueError('Invalid archive state.')
        for t in c['targets']:
            if not isinstance(t, dict) or not isinstance(t.get('value'), str) or not isinstance(t.get('type'), str):
                raise ValueError('Invalid target.')
            target(t['value'], t['type'])
        ids = set()
        for f in c['findings']:
            if not isinstance(f, dict) or not all(k in f for k in ('id', 'title', 'source', 'severity', 'confidence', 'subject', 'object', 'relation', 'summary', 'remediation', 'evidence')):
                raise ValueError('Invalid evidence record.')
            if f['confidence'] not in CONFIDENCE or not isinstance(f['evidence'], list):
                raise ValueError('Invalid evidence confidence.')
            if f['severity'] not in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                raise ValueError('Invalid evidence severity.')
            for key in ('id', 'title', 'source', 'summary', 'remediation', 'relation'):
                if not isinstance(f[key], str):
                    raise ValueError('Invalid evidence text.')
            if f['id'] in ids:
                raise ValueError('Duplicate finding ID.')
            ids.add(f['id'])
            for key in ('subject', 'object'):
                if not isinstance(f[key], dict) or not all(isinstance(f[key].get(k), str) for k in ('id', 'type', 'value')):
                    raise ValueError('Invalid graph entity.')
            for ev in f['evidence']:
                if not isinstance(ev, dict) or not all(isinstance(ev.get(k), str) for k in ('provider', 'timestamp', 'reference')):
                    raise ValueError('Invalid evidence provenance.')
                if not isinstance(ev.get('raw'), dict) or not isinstance(ev.get('pivot_path'), list):
                    raise ValueError('Invalid raw evidence.')
                for t in ev['pivot_path']:
                    if not isinstance(t, dict) or not all(isinstance(t.get(k), str) for k in ('value', 'type')):
                        raise ValueError('Invalid pivot path.')
        for s in c['scans']:
            if not isinstance(s, dict) or not all(isinstance(s.get(k), str) for k in ('status', 'started')):
                raise ValueError('Invalid scan history.')
            if not isinstance(s.get('warnings', []), list) or not all(isinstance(w, str) for w in s.get('warnings', [])):
                raise ValueError('Invalid scan warnings.')
        for r in c['reports']:
            if not isinstance(r, dict) or not all(isinstance(r.get(k), str) for k in ('name', 'created')):
                raise ValueError('Invalid report history.')
        return c

    def list(self):
        cases, errors = [], []
        for p in (self.root / 'cases').glob('*.json'):
            try:
                cases.append(self.load(p))
            except (ValueError, KeyError, TypeError, OSError) as exc:
                errors.append(p.name)
        return sorted(cases, key=lambda c: c['updated'], reverse=True), errors


def risk(case):
    counts = {s: sum(f['severity'] == s for f in case['findings']) for s in ('HIGH', 'MEDIUM', 'LOW', 'INFO')}
    score = min(100, counts['HIGH'] * 25 + counts['MEDIUM'] * 10 + counts['LOW'] * 3)
    return score, counts


def report_html(case):
    esc = lambda s: html.escape(str(s), quote=True)
    score, counts = risk(case)
    rows = []
    for f in case['findings']:
        evidence = ''.join('<li>' + esc(e['provider']) + ' · ' + esc(e['timestamp']) +
                           ' · ' + esc(e.get('reference', '')) + '<br>Path: ' +
                           esc(' → '.join(t['value'] for t in e.get('pivot_path', []))) + '</li>' for e in f['evidence'])
        rows.append(f"<section><span class='tag'>{esc(f['severity'])} · {esc(f['confidence'])}</span><h3>{esc(f['title'])}</h3>"
                    f"<p>{esc(f['summary'])}</p><p><b>Remediation:</b> {esc(f['remediation'])}</p><ul>{evidence}</ul>"
                    f"<details><summary>Raw evidence</summary><pre>{esc(json.dumps(f['evidence'], indent=2, ensure_ascii=False))}</pre></details></section>")
    relationships = ''.join('<li>' + esc(f['subject']['value']) + ' → ' + esc(f['relation']) + ' → ' + esc(f['object']['value']) + '</li>'
                            for f in case['findings'] if f['subject']['id'] != f['object']['id'])
    scans = ''.join('<li>' + esc(s.get('started', '')) + ' · ' + esc(s.get('status', '')) + ' · ' + esc('; '.join(s.get('warnings', []))) + '</li>' for s in case['scans'])
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><title>SPECTRA · {esc(case['name'])}</title>
<style>body{{font:15px/1.6 Segoe UI,Arial;background:#f3f5fa;color:#182338;max-width:1040px;margin:40px auto;padding:0 24px}}header{{background:#101c31;color:white;padding:32px;border-radius:14px}}h1{{letter-spacing:5px}}section{{background:white;padding:24px;margin:16px 0;border:1px solid #dce3ee;border-radius:10px}}.tag{{color:#356483;font-weight:bold}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}li{{overflow-wrap:anywhere}}@media print{{body{{background:white;margin:0}}details{{display:block}}section{{break-inside:avoid}}}}</style>
<header><h1>SPECTRA</h1><p>Digital Exposure &amp; OSINT Auditor · Powered by Dhruv Kaushik</p><h2>{esc(case['name'])}</h2><p>Client: {esc(case['client'])} · Generated {esc(now())}</p></header>
<section><h2>Executive summary</h2><p>{len(case['targets'])} targets · {len(case['findings'])} findings · {counts['HIGH']} high priority · {counts['MEDIUM']} medium priority.</p>
<p>Observed exposure indicator: <b>{score}/100</b>. Heuristic: 25 per high, 10 per medium, 3 per low finding, capped at 100. This is not a probability or a completeness rating; zero does not establish safety.</p><p>Authorization: {esc(case['authorization'])}</p></section>
<section><h2>Methodology &amp; limitations</h2><p>Configured passive providers and local analysis only. Results represent observations at the recorded times. Public profiles and username matches do not establish personal identity. Missing API access, errors, cancelled scans, and source coverage limit conclusions. Open ports alone do not establish a vulnerability. No plaintext passwords are retained.</p><h3>Scan coverage</h3><ul>{scans or '<li>No scans recorded.</li>'}</ul></section>
<section><h2>Relationships</h2><ul>{relationships or '<li>No relationships observed.</li>'}</ul></section>
<h2>Findings, evidence &amp; remediation</h2>{''.join(rows) or '<section>No findings recorded.</section>'}</html>'''
