import threading
import unittest
from urllib.parse import parse_qs, urlsplit
from spectra.core import DEFAULTS, target
from spectra.providers import Scanner, ProviderError


class SearchTests(unittest.TestCase):
    def scanner(self):
        events = []
        scanner = Scanner({**DEFAULTS, 'spiderfoot_enabled': False, 'connectors': ['DNS']},
                          lambda event, value: events.append((event, value)), threading.Event())
        return scanner, events

    def test_email_checks_domain_only_and_records_coverage(self):
        scanner, events = self.scanner()
        urls = []
        def response(url, *args):
            urls.append(url)
            query = parse_qs(urlsplit(url).query)
            number = int(query['type'][0])
            return {'Status': 0, 'Answer': [{'type': number, 'data': '10 mail.example.org.'}]} if number == 15 else {'Status': 0}
        scanner.json = response
        scanner.run([target('person@example.org')])
        self.assertEqual(len(urls), 6)
        self.assertTrue(all('person' not in url for url in urls))
        self.assertTrue(any('_dmarc.' in url for url in urls))
        findings = [v for e, v in events if e == 'finding']
        self.assertTrue(any(f['title'] == 'DNS MX record' for f in findings))
        coverage = events[-1][1]['coverage']
        self.assertEqual(coverage[0]['status'], 'COMPLETED')
        self.assertEqual(coverage[1]['status'], 'DISABLED')

    def test_partial_dns_failure_retains_other_evidence(self):
        scanner, events = self.scanner()
        def response(url, *args):
            if 'type=1&' in url: raise ProviderError('Unavailable')
            return {'Status': 0}
        scanner.json = response
        scanner.run([target('example.org')])
        self.assertEqual(events[-1][1]['coverage'][0]['status'], 'FAILED')
        self.assertEqual(events[-1][1]['coverage'][0]['findings'], 5)
        self.assertIn('Incomplete DNS coverage', events[-1][1]['warnings'][0])

    def test_cancel_does_not_report_success(self):
        scanner, events = self.scanner()
        scanner.cancel.set()
        scanner.run([target('example.org')])
        self.assertEqual(events[-1][1]['status'], 'CANCELLED')
