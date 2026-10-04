import copy
import hashlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from PIL import Image
from spectra.core import CaseStore, DEFAULTS, classify_target, target, finding, merge_finding, report_html, risk
from spectra.providers import Scanner, ProviderError, Engine, pwned_password_check, image_metadata


class CoreTests(unittest.TestCase):
    def test_classification_and_override(self):
        samples = {'': 'unknown', 'john12345678': 'username', '+1 (555) 123-4567': 'phone',
                   'example.com': 'domain', 'person@example.com': 'email', '192.0.2.1': 'ip',
                   '2001:db8::1': 'ip', 'https://example.com/a': 'url', 'Jane Doe': 'name'}
        for value, kind in samples.items(): self.assertEqual(classify_target(value), kind)
        self.assertEqual(target('Alice', 'Name')['type'], 'name')
        with self.assertRaises(ValueError): target('bad', 'IP')
        with self.assertRaises(ValueError): target('https://user:secret@example.com', 'URL')

    def test_case_roundtrip_and_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            store = CaseStore(folder)
            c = store.create('Example', 'Client', 'Authorized domain assessment')
            c['targets'].append(target('example.com'))
            c['archived'] = True
            store.save(c)
            loaded = store.load(Path(folder)/'cases'/f"{c['id']}.json")
            self.assertEqual(c, loaded)
            (Path(folder)/'cases/bad.json').write_text('{}')
            cases, errors = store.list()
            self.assertEqual(len(cases), 1)
            self.assertEqual(errors, ['bad.json'])
            self.assertFalse(list((Path(folder)/'cases').glob('*.tmp')))

    def test_deduplication_preserves_sources_and_paths(self):
        c = {'findings': []}
        t = target('example.com')
        a = finding('DNS address', 'one', t, {'summary': 'address'}, object_type='IP', object_value='192.0.2.1', relation='RESOLVES_TO')
        b = finding('DNS address', 'two', t, {'summary': 'address'}, object_type='IP', object_value='192.0.2.1', relation='RESOLVES_TO', path=[t, target('192.0.2.1')])
        self.assertTrue(merge_finding(c, a))
        self.assertFalse(merge_finding(c, b))
        self.assertEqual(len(c['findings']), 1)
        self.assertEqual(len(c['findings'][0]['evidence']), 2)

    def test_report_escapes_evidence_and_excludes_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            store = CaseStore(folder)
            store.save_settings(dict(DEFAULTS, shodan_api_key='secret-token'))
            c = store.create('<script>alert(1)</script>', 'Client', 'Scope')
            merge_finding(c, finding('Example', 'local', target('example.com'), {'summary': '<img src=x onerror=alert(1)>'}, severity='HIGH'))
            report = report_html(c)
            self.assertNotIn('<script>', report)
            self.assertNotIn('<img', report)
            self.assertNotIn('secret-token', report)
            self.assertIn('&lt;script&gt;', report)
            self.assertEqual(risk(c)[0], 25)


class ProviderTests(unittest.TestCase):
    def scanner(self, **settings):
        self.events = []
        config = dict(DEFAULTS, spiderfoot_enabled=False)
        config.update(settings)
        return Scanner(config, lambda a, b: self.events.append((a, b)), threading.Event())

    def test_provider_failure_does_not_end_scan(self):
        scanner = self.scanner(connectors=['InternetDB', 'Shodan'])
        with patch.object(scanner, 'internetdb', side_effect=ProviderError('unavailable')), patch.object(scanner, 'shodan', return_value=[]) as shodan:
            scanner.run([target('8.8.8.8')])
        shodan.assert_called_once()
        self.assertEqual(self.events[-1][1]['status'], 'COMPLETED WITH WARNINGS')

    def test_cancellation_skips_pending_work(self):
        scanner = self.scanner()
        scanner.cancel.set()
        with patch.object(scanner, 'dns') as dns:
            scanner.run([target('example.com')])
        dns.assert_not_called()
        self.assertEqual(self.events[-1][1]['status'], 'CANCELLED')

    def test_pivot_deduplicates_targets(self):
        scanner = self.scanner(auto_pivot=True, pivot_depth=3, connectors=['DNS', 'InternetDB'])
        with patch.object(scanner, 'dns', return_value=[target('8.8.8.8'), target('8.8.8.8')]), patch.object(scanner, 'internetdb', return_value=[target('example.com')]) as lookup:
            scanner.run([target('example.com')])
        lookup.assert_called_once()
        self.assertEqual(len(scanner.visited), 2)

    def test_password_only_sends_prefix(self):
        password = 'synthetic-test-only-password'
        digest = hashlib.sha1(password.encode()).hexdigest().upper()
        response = io.BytesIO((digest[5:] + ':12\n').encode())
        with patch('spectra.providers.urllib.request.urlopen', return_value=response) as call:
            result = pwned_password_check(password)
        req = call.call_args.args[0]
        self.assertTrue(req.full_url.endswith(digest[:5]))
        self.assertNotIn(password, req.full_url)
        self.assertNotIn(digest, req.full_url)
        self.assertEqual(result, {'status': 'ok', 'exposed': True, 'count': 12})
        self.assertNotIn(password, json.dumps(result))

    def test_image_hashes_and_dimensions(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/'sample.png'
            Image.new('RGB', (64, 32), '#aabbcc').save(p)
            data = image_metadata(p)
            self.assertEqual(data['sha256'], hashlib.sha256(p.read_bytes()).hexdigest())
            self.assertEqual((data['width'], data['height']), (64, 32))
            for key in ('ahash', 'dhash', 'phash'): self.assertEqual(len(data[key]), 16)

    def test_spiderfoot_ingests_completed_scan(self):
        scanner = self.scanner(spiderfoot_enabled=True)
        scanner.engine = Mock()
        row = ['2026-01-01', 'example.com', 'seed', 'module', 1, 1, 1, 1, 0, 0, 'DOMAIN_NAME']
        with patch('spectra.providers.request_json', return_value=['SUCCESS', 'scan-1']), patch.object(scanner, 'json', side_effect=[['n','t','c','s','e','FINISHED'], [row]]):
            scanner.spiderfoot(target('example.com'), [target('example.com')])
        findings = [v for e,v in self.events if e == 'finding']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['confidence'], 'LOW')
        self.assertEqual(findings[0]['evidence'][0]['raw']['scan_id'], 'scan-1')

    def test_spiderfoot_stop_on_cancellation(self):
        scanner = self.scanner(spiderfoot_enabled=True)
        scanner.engine = Mock()
        def start(*args, **kwargs):
            scanner.cancel.set()
            return ['SUCCESS', 'scan-2']
        with patch('spectra.providers.request_json', side_effect=start) as call:
            scanner.spiderfoot(target('example.com'), [target('example.com')])
        self.assertIn('/stopscan', call.call_args.args[0])

    def test_external_engine_is_not_owned(self):
        engine = Engine()
        with patch('spectra.providers.request_json', return_value=['SUCCESS', '4.0']), patch('spectra.providers.subprocess.Popen') as popen:
            engine.ensure('http://127.0.0.1:5001')
        self.assertIsNone(engine.process)
        popen.assert_not_called()


if __name__ == '__main__': unittest.main()
