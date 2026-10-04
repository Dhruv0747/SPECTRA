"""Provider adapters. All network work is called by a background worker."""
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from PIL import Image, ExifTags
from .core import APP_DIR, finding, target


class ProviderError(Exception):
    pass


def request_json(url, headers=None, timeout=12, data=None):
    req = urllib.request.Request(url, data=data, headers={'User-Agent': 'SPECTRA/1.0', **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise ProviderError('RATE LIMITED — retry later.') from None
        raise ProviderError(f'HTTP {exc.code}; verify provider access and configuration.') from None
    except (OSError, ValueError):
        raise ProviderError('Provider unavailable or returned an invalid response.') from None


def pwned_password_check(password, timeout=12):
    if not password:
        return {'status': 'empty'}
    digest = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    req = urllib.request.Request('https://api.pwnedpasswords.com/range/' + digest[:5],
                                 headers={'User-Agent': 'SPECTRA/1.0', 'Add-Padding': 'true'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            text = response.read().decode('utf-8')
        count = next((int(line.split(':')[1]) for line in text.splitlines()
                      if line.partition(':')[0] == digest[5:]), 0)
        return {'status': 'ok', 'exposed': count > 0, 'count': count}
    except (OSError, ValueError):
        return {'status': 'error', 'message': 'Password service unavailable; please retry later.'}


def image_metadata(path):
    p = Path(path)
    digest = hashlib.sha256()
    with p.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    with Image.open(p) as img:
        img.load()
        exif = {ExifTags.TAGS.get(k, str(k)): str(v) for k, v in img.getexif().items()}
        grey = img.convert('L')
        small = list(grey.resize((8, 8), Image.Resampling.LANCZOS).get_flattened_data())
        average = sum(small) / len(small)
        ahash = sum((pixel > average) << i for i, pixel in enumerate(small))
        wide = list(grey.resize((9, 8), Image.Resampling.LANCZOS).get_flattened_data())
        dhash = sum((wide[y * 9 + x] > wide[y * 9 + x + 1]) << (y * 8 + x) for y in range(8) for x in range(8))
        pixels = list(grey.resize((32, 32), Image.Resampling.LANCZOS).get_flattened_data())
        cosines = [[math.cos((2*x + 1) * u * math.pi / 64) for x in range(32)] for u in range(8)]
        transformed = [[sum(pixels[y*32+x] * cosines[u][x] for x in range(32)) for u in range(8)] for y in range(32)]
        coefficients = [sum(transformed[y][u] * cosines[v][y] for y in range(32)) for v in range(8) for u in range(8)]
        median = statistics.median(coefficients[1:])
        phash = sum((v > median) << i for i, v in enumerate(coefficients))
        return {'filename': p.name, 'size_bytes': p.stat().st_size, 'sha256': digest.hexdigest(),
                'width': img.width, 'height': img.height, 'format': img.format, 'exif': exif,
                'ahash': f'{ahash:016x}', 'dhash': f'{dhash:016x}', 'phash': f'{phash:016x}',
                'summary': f'{p.name}: {img.width} × {img.height} pixels; local hashes and metadata only.'}


CATALOG = [
    ('DNS', 'Domain, URL, Email', 'FREE API', 'Public addresses, mail servers, nameservers and domain policies'),
    ('InternetDB', 'IP', 'FREE API', 'Shodan InternetDB observed services and vulnerability references'),
    ('GitHub', 'Username', 'FREE API', 'Public GitHub profile; does not establish identity'),
    ('HIBP', 'Email', 'API KEY REQUIRED', 'Have I Been Pwned breach-account exposure'),
    ('Shodan', 'IP', 'API KEY REQUIRED', 'Shodan host enrichment'),
    ('Image', 'Image', 'FREE / LOCAL', 'SHA-256, perceptual hashes, dimensions and EXIF'),
    ('SpiderFoot', 'Name, Email, Phone, Username, Domain, IP', 'LOCAL ENGINE', 'Passive scans, progress, evidence ingestion and stop'),
]


class Engine:
    """Own only the process we launch. Never terminate an existing external server."""
    def __init__(self, root=APP_DIR):
        self.root = Path(root)
        self.process = None
        self.lock = threading.Lock()
        self.closed = False

    def ensure(self, base, timeout=12):
        base = base.rstrip('/')
        if not base:
            raise ProviderError('SpiderFoot URL is not configured.')
        try:
            ping = request_json(base + '/ping', timeout=2)
            if isinstance(ping, list) and ping[0] == 'SUCCESS':
                return
        except ProviderError:
            pass
        parsed = urllib.parse.urlsplit(base)
        if parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.scheme != 'http':
            raise ProviderError('Configured SpiderFoot server is unavailable.')
        engine = self.root / 'tools/spiderfoot'
        exe = engine / 'SpiderFoot.exe'
        py = engine / 'runtime/python.exe'
        if exe.exists():
            command = [str(exe), '-l', f'127.0.0.1:{parsed.port or 5001}']
        elif py.exists() and (engine / 'sf.py').exists():
            command = [str(py), str(engine / 'sf.py'), '-l', f'127.0.0.1:{parsed.port or 5001}']
        else:
            raise ProviderError('SpiderFoot is not bundled. Configure an existing server or install the engine bundle.')
        with self.lock:
            if self.closed:
                raise ProviderError('Engine manager is closing.')
            if not self.process or self.process.poll() is not None:
                env = os.environ.copy()
                env.update(SPIDERFOOT_DATA=str(self.root / 'data/spiderfoot'),
                           SPIDERFOOT_CACHE=str(self.root / 'cache/spiderfoot'),
                           SPIDERFOOT_LOGS=str(self.root / 'logs/spiderfoot'))
                self.process = subprocess.Popen(command, cwd=engine, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL, env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for _ in range(40):
            if self.process.poll() is not None:
                raise ProviderError('Bundled SpiderFoot exited during startup.')
            try:
                ping = request_json(base + '/ping', timeout=1)
                if isinstance(ping, list) and ping[0] == 'SUCCESS':
                    return
            except ProviderError:
                time.sleep(.5)
        raise ProviderError('SpiderFoot did not become ready; check engine installation.')

    def close(self):
        with self.lock:
            self.closed = True
            if self.process and self.process.poll() is None:
                # Windows taskkill /T cleans up owned scanner descendants too.
                subprocess.run(['taskkill', '/PID', str(self.process.pid), '/T', '/F'],
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                self.process.wait(timeout=10)
            self.process = None


class Scanner:
    def __init__(self, settings, emit, cancel, engine=None):
        self.settings = dict(settings)
        self.emit = emit
        self.cancel = cancel
        self.timeout = int(settings.get('timeout', 12))
        self.engine = engine or Engine()
        self.visited = set()
        self.warnings = []
        self.sf_scans = []
        self.images = []
        self.completed_providers = 0
        self.coverage = []
        self.finding_count = 0

    def warn(self, provider, message):
        text = provider + ': ' + message
        self.warnings.append(text)
        self.emit('warning', text)

    def json(self, url, headers=None, data=None):
        for attempt in range(int(self.settings.get('retries', 1)) + 1):
            if self.cancel.is_set():
                raise ProviderError('Cancelled')
            try:
                return request_json(url, headers, self.timeout, data)
            except ProviderError as exc:
                if 'RATE LIMITED' in str(exc) or attempt >= int(self.settings.get('retries', 1)):
                    raise
                if self.cancel.wait(.5):
                    raise ProviderError('Cancelled')

    def add(self, title, source, t, raw, path, **kwargs):
        self.finding_count += 1
        self.emit('finding', finding(title, source, t, raw, path=path, **kwargs))

    def run(self, targets):
        pending = [(t, [t], 0) for t in targets]
        try:
            while pending and not self.cancel.is_set():
                t, path, depth = pending.pop(0)
                key = (t['type'], t['value'])
                if key in self.visited:
                    continue
                self.visited.add(key)
                self.emit('target', t)
                pivots = []
                kind = t['type']
                jobs = []
                if kind in ('domain', 'url', 'email'):
                    jobs.append(('DNS', self.dns))
                if kind == 'ip':
                    jobs.extend([('InternetDB', self.internetdb), ('Shodan', self.shodan)])
                if kind == 'email':
                    jobs.append(('HIBP', self.hibp))
                if kind == 'username':
                    jobs.append(('GitHub', self.github))
                if kind == 'image':
                    jobs.append(('Image', self.image))
                if self.settings.get('spiderfoot_enabled') and kind != 'image':
                    jobs.append(('SpiderFoot', self.spiderfoot))
                ran = False
                for name, operation in jobs:
                    if self.cancel.is_set():
                        break
                    coverage = {'provider': name, 'target': dict(t), 'status': 'DISABLED', 'findings': 0}
                    self.coverage.append(coverage)
                    if name != 'SpiderFoot' and name not in self.settings.get('connectors', []):
                        continue
                    before = self.finding_count
                    started = time.monotonic()
                    coverage['status'] = 'RUNNING'
                    ran = True
                    self.emit('provider', name)
                    try:
                        pivots.extend(operation(t, path) or [])
                        coverage['status'] = 'COMPLETED'
                        self.completed_providers += 1
                        self.emit('provider_done', name)
                    except Exception as exc:
                        coverage['status'] = 'CANCELLED' if self.cancel.is_set() else 'FAILED'
                        # Never propagate raw transport exceptions containing tokens/URLs.
                        if not self.cancel.is_set():
                            self.warn(name, str(exc) if isinstance(exc, ProviderError) else 'Provider failed; no results assumed.')
                    finally:
                        if self.cancel.is_set(): coverage['status'] = 'CANCELLED'
                        coverage['findings'] = self.finding_count - before
                        coverage['seconds'] = round(time.monotonic() - started, 1)
                if not ran:
                    self.warn('Coverage', f'No enabled provider supports {kind}. Target saved without fabricated findings.')
                if self.settings.get('auto_pivot') and depth < int(self.settings.get('pivot_depth', 1)):
                    pending.extend((p, path + [p], depth + 1) for p in pivots)
                self.emit('progress', {'visited': len(self.visited), 'pending': len(pending)})
        except Exception:
            self.warn('Scan', 'Investigation interrupted by an unexpected error; partial evidence retained.')
        finally:
            status = ('CANCELLED' if self.cancel.is_set() else
                      'FAILED' if self.warnings and not self.completed_providers else
                      'COMPLETED WITH WARNINGS' if self.warnings else 'COMPLETED')
            self.emit('done', {'status': status,
                               'warnings': self.warnings, 'coverage': self.coverage})

    def dns(self, t, path):
        domain = urllib.parse.urlsplit(t['value']).hostname if t['type'] == 'url' else t['value']
        if t['type'] == 'email': domain = t['value'].rsplit('@', 1)[1]
        domain = domain.encode('idna').decode('ascii').lower().rstrip('.')
        dt = target(domain, 'Domain')
        if t['type'] == 'url':
            self.add('URL host', 'DNS', t, {'summary': f'URL host is {domain}.'}, path,
                     relation='HOSTED_ON', object_type='DOMAIN', object_value=domain)
        pivots, failures = [], []
        for qtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'DMARC'):
            name = '_dmarc.' + domain if qtype == 'DMARC' else domain
            number = {'A': 1, 'AAAA': 28, 'MX': 15, 'NS': 2, 'TXT': 16, 'DMARC': 16}[qtype]
            url = 'https://dns.google/resolve?' + urllib.parse.urlencode({'name': name, 'type': number, 'edns_client_subnet': '0.0.0.0/0'})
            try:
                data = self.json(url)
                if data.get('Status') not in (0, 3) or data.get('TC'):
                    raise ProviderError('DNS resolver could not complete the query.')
            except ProviderError:
                if self.cancel.is_set(): raise
                failures.append(qtype)
                continue
            matched = [r for r in data.get('Answer', []) if r.get('type') == number]
            if not matched:
                self.add('DNS ' + qtype + ' coverage', 'DNS', dt,
                         {'summary': f'No {qtype} records returned for {name}; mailbox existence and ownership are not established.'}, path,
                         reference=url, object_type='DNS_QUERY', object_value=name + '/' + qtype)
            for row in matched:
                if row.get('type') in (2, 15, 16):
                    value = str(row['data'])
                    self.add('DNS ' + qtype + ' record', 'DNS', dt,
                             {'summary': f'{domain}: {qtype} {value}', 'record_value': value,
                              'ttl_seconds': row.get('TTL'), 'dnssec_validated': bool(data.get('AD'))}, path,
                             reference=url, relation='PUBLISHES', object_type='DNS_RECORD', object_value=value,
                             remediation='Domain records do not verify a mailbox, its owner, or security posture.')
                if row.get('type') in (1, 28):
                    ip = str(ipaddress.ip_address(row['data']))
                    self.add('DNS address', 'DNS', dt, {'summary': f'{domain} resolves to {ip}.', 'record': row}, path,
                             reference=url, relation='RESOLVES_TO', object_type='IP', object_value=ip,
                             remediation='Confirm that this infrastructure belongs in the assessment scope.')
                    pivots.append(target(ip, 'IP'))
        if failures:
            raise ProviderError('Incomplete DNS coverage: ' + ', '.join(failures) + '. Successful records retained.')
        return pivots

    def internetdb(self, t, path):
        if not ipaddress.ip_address(t['value']).is_global:
            raise ProviderError('Public InternetDB lookup skipped for a non-public IP.')
        url = 'https://internetdb.shodan.io/' + urllib.parse.quote(t['value'], safe='')
        try:
            data = self.json(url)
        except ProviderError as exc:
            if 'HTTP 404' in str(exc):
                self.add('No InternetDB observation', 'InternetDB', t, {'summary': 'No observation returned. This does not establish safety.'}, path, reference=url)
                return []
            raise
        ports = data.get('ports', [])
        self.add('Public service observations', 'InternetDB', t,
                 {'summary': 'Observed ports: ' + (', '.join(map(str, ports)) or 'none listed'), 'record': data}, path,
                 reference=url, severity='LOW' if ports else 'INFO',
                 remediation='Verify exposed services are intended and restrict unnecessary access.')
        for port in ports:
            self.add('Observed service', 'InternetDB', t, {'summary': f'Provider observed port {port}; current reachability is not tested.'}, path,
                     reference=url, relation='EXPOSES', object_type='SERVICE', object_value=f"{t['value']}:{port}")
        for vuln in data.get('vulns', []):
            self.add('Potential vulnerability reference', 'InternetDB', t, {'summary': f'{vuln} reported by the provider; validate applicability.'}, path,
                     severity='MEDIUM', confidence='MEDIUM', reference=url, relation='ASSOCIATED_WITH', object_type='VULNERABILITY', object_value=vuln,
                     remediation='Verify affected software and version before prioritizing patching. No exploit was attempted.')
        return []

    def github(self, t, path):
        url = 'https://api.github.com/users/' + urllib.parse.quote(t['value'], safe='')
        try:
            data = self.json(url, {'Accept': 'application/vnd.github+json'})
        except ProviderError as exc:
            if 'HTTP 404' in str(exc):
                self.add('No GitHub profile returned', 'GitHub', t, {'summary': 'No public GitHub account was returned for this username.'}, path, reference=url)
                return []
            raise
        profile = data.get('html_url', '')
        self.add('Public GitHub profile', 'GitHub', t,
                 {'summary': f"Public account {data.get('login')}; matching username alone does not prove identity.",
                  'login': data.get('login'), 'name': data.get('name'), 'bio': data.get('bio'),
                  'public_repos': data.get('public_repos'), 'profile': profile,
                  'avatar_url': data.get('avatar_url'), 'website': data.get('blog'),
                  'account_created': data.get('created_at'), 'followers': data.get('followers'),
                  'match_basis': 'Exact username lookup; ownership by the client is not verified.'},
                 path, reference=url, confidence='LOW', relation='POSSIBLE_PROFILE', object_type='PROFILE', object_value=profile,
                 remediation='Verify ownership using independent evidence before attributing this profile to a person.')
        social_url = url + '/social_accounts'
        social = self.json(social_url, {'Accept': 'application/vnd.github+json'})
        if not isinstance(social, list):
            raise ProviderError('Public profile retained; linked social accounts returned an invalid response.')
        for row in social:
            link = row.get('url', '')
            if not isinstance(link, str) or urllib.parse.urlsplit(link).scheme not in ('http', 'https'):
                continue
            self.add('Publicly linked social account', 'GitHub', t,
                     {'summary': f"The GitHub profile links to {row.get('provider') or 'another platform'}: {link}.",
                      'profile': link, 'linked_from': profile,
                      'match_basis': 'Link published on the GitHub profile; destination ownership is not independently verified.'},
                     path, reference=social_url, confidence='LOW', relation='LINKED_PROFILE',
                     object_type='PROFILE', object_value=link,
                     remediation='Review the source profile and destination before attributing either account to the client.')
        return []

    def hibp(self, t, path):
        key = self.settings.get('hibp_api_key', '')
        if not key:
            raise ProviderError('NOT CONFIGURED — add a HIBP API key in Settings.')
        url = 'https://haveibeenpwned.com/api/v3/breachedaccount/' + urllib.parse.quote(t['value'], safe='') + '?truncateResponse=false'
        try:
            data = self.json(url, {'hibp-api-key': key})
        except ProviderError as exc:
            if 'HTTP 404' in str(exc):
                data = []
            else:
                raise
        if not data:
            self.add('No breach returned', 'HIBP', t, {'summary': 'No breach found in the accessible HIBP corpus; other exposure may exist.'}, path, reference='https://haveibeenpwned.com/')
        for row in data:
            raw = {k: row.get(k) for k in ('Name', 'Domain', 'BreachDate', 'DataClasses', 'IsVerified')}
            raw['summary'] = f"{row.get('Name')} ({row.get('BreachDate')}): {', '.join(row.get('DataClasses', []))}"
            self.add('Breach exposure', 'HIBP', t, raw, path, severity='HIGH', confidence='HIGH' if row.get('IsVerified') else 'MEDIUM',
                     reference='https://haveibeenpwned.com/', relation='APPEARED_IN', object_type='BREACH', object_value=row.get('Name'),
                     remediation='Change reused passwords, enable MFA, and watch for targeted phishing. Never retrieve leaked plaintext credentials.')
        return []

    def shodan(self, t, path):
        key = self.settings.get('shodan_api_key', '')
        if not key:
            raise ProviderError('NOT CONFIGURED — add a Shodan API key in Settings.')
        if not ipaddress.ip_address(t['value']).is_global:
            raise ProviderError('Public Shodan lookup skipped for a non-public IP.')
        data = self.json('https://api.shodan.io/shodan/host/' + urllib.parse.quote(t['value'], safe='') + '?key=' + urllib.parse.quote(key, safe=''))
        raw = {k: data.get(k) for k in ('ip_str', 'org', 'isp', 'country_name', 'ports', 'hostnames', 'domains', 'last_update')}
        raw['summary'] = f"Organization: {data.get('org') or 'unknown'}; observed ports: {data.get('ports', [])}"
        self.add('Shodan host observation', 'Shodan', t, raw, path, severity='LOW',
                 reference='https://www.shodan.io/host/' + urllib.parse.quote(t['value'], safe=''),
                 remediation='Review the provider timestamp and validate whether each exposed service is intended.')
        return []

    def image(self, t, path):
        raw = image_metadata(t['value'])
        self.add('Image fingerprint and metadata', 'Image', t, raw, path, confidence='CONFIRMED',
                 remediation='Review EXIF for sensitive location or device metadata before sharing images.')
        for previous, metadata in self.images:
            exact = raw['sha256'] == metadata['sha256']
            distance = (int(raw['phash'], 16) ^ int(metadata['phash'], 16)).bit_count()
            if exact or distance <= 8:
                self.add('Exact image duplicate' if exact else 'Possible similar image', 'Image', t,
                         {'summary': ('Identical file bytes: ' if exact else 'Perceptual similarity candidate: ') + metadata['filename'],
                          'phash_distance': distance, 'sha256_equal': exact}, path,
                         confidence='CONFIRMED' if exact else 'LOW', relation='IDENTICAL_TO' if exact else 'SIMILAR_TO',
                         object_type='IMAGE', object_value=previous['value'],
                         remediation='Perceptual similarity is a heuristic. Visually compare both images; it is not identity evidence.')
        self.images.append((dict(t), raw))
        return []

    def spiderfoot(self, t, path):
        base = self.settings.get('spiderfoot_url', '').rstrip('/')
        self.engine.ensure(base, self.timeout)
        value = t['value']
        if t['type'] == 'url':
            value = urllib.parse.urlsplit(value).hostname
        elif t['type'] in ('name', 'username'):
            value = '"' + value.replace('"', '') + '"'
        elif t['type'] == 'phone':
            value = '+' + re.sub(r'\D', '', value)
        payload = urllib.parse.urlencode({'scanname': 'SPECTRA-' + str(time.time_ns()), 'scantarget': value,
                                         'modulelist': '', 'typelist': '', 'usecase': 'Passive'}).encode()
        # Starting scans is non-idempotent: do not retry the POST.
        result = request_json(base + '/startscan', {'Accept': 'application/json'}, max(30, self.timeout), payload)
        if not isinstance(result, list) or len(result) < 2 or result[0] != 'SUCCESS':
            reason = 'Unexpected response from the engine.'
            if isinstance(result, list) and len(result) >= 2 and result[0] == 'ERROR':
                # Preserve actionable upstream validation errors without reflecting
                # arbitrary server content, targets or credentials into diagnostics.
                message = str(result[1]).lower()
                if 'no modules' in message:
                    reason = 'No modules matched the selected scan profile.'
                elif 'target type' in message:
                    reason = 'The engine did not recognize this target type.'
                elif 'scan target was not specified' in message:
                    reason = 'The engine received an empty target.'
            raise ProviderError('Scan rejected: ' + reason)
        scan_id = str(result[1])
        self.emit('engine_scan', {'id': scan_id, 'server': base})
        seen = set()
        completed = False
        try:
            while not self.cancel.is_set():
                status = self.json(base + '/scanstatus?' + urllib.parse.urlencode({'id': scan_id}))
                if not isinstance(status, list) or len(status) < 6:
                    raise ProviderError('SpiderFoot returned an invalid scan status.')
                rows = self.json(base + '/scaneventresults?' + urllib.parse.urlencode({'id': scan_id, 'eventType': 'ALL'}))
                for row in rows:
                    if not isinstance(row, list) or len(row) < 11:
                        continue
                    signature = json.dumps(row, sort_keys=True)
                    if signature in seen:
                        continue
                    seen.add(signature)
                    value = html.unescape(str(row[1]))
                    event_type = str(row[10])
                    if event_type == 'ROOT':
                        continue
                    self.add('SpiderFoot: ' + event_type, 'SpiderFoot', t,
                             {'summary': value, 'event': row, 'scan_id': scan_id}, path, confidence='LOW',
                             reference=base + '/scaninfo?' + urllib.parse.urlencode({'id': scan_id}),
                             relation='ENGINE_OBSERVATION', object_type=event_type, object_value=value,
                             remediation='Verify this engine observation and its source before attributing identity or risk.')
                self.emit('provider', 'SpiderFoot · ' + str(status[5]))
                if status[5] in ('FINISHED', 'ABORTED', 'ERROR-FAILED') or str(status[5]).startswith('ERROR'):
                    completed = True
                    if status[5] != 'FINISHED':
                        raise ProviderError('Engine ended with status ' + str(status[5]))
                    break
                self.cancel.wait(2)
        finally:
            if not completed:
                try:
                    request_json(base + '/stopscan', timeout=self.timeout,
                                 data=urllib.parse.urlencode({'id': scan_id}).encode())
                except ProviderError:
                    self.warn('SpiderFoot', 'Stop request could not be confirmed; check the engine scan ' + scan_id)
        return []
