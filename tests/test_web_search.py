import json
import threading
import unittest
from unittest.mock import patch
from spectra.core import DEFAULTS, target
from spectra.providers import Scanner, ProviderError
from spectra.presentation import client_card, client_summary


class WebSearchTests(unittest.TestCase):
    def scanner(self):
        self.events = []
        return Scanner({**DEFAULTS, 'serpapi_api_key':'private-key', 'spiderfoot_enabled':False,
                        'connectors':['Social Search', 'Photo Search']},
                       lambda k,v:self.events.append((k,v)), threading.Event())

    def test_social_filters_host_and_retains_provenance(self):
        s = self.scanner()
        response = {'search_metadata': {'status':'Success', 'url':'private-key'},
                    'organic_results':[{'title':'Test','snippet':'Public preview','link':'https://www.instagram.com/example/'},
                                       {'link':'https://instagram.com.evil.org/example'}]}
        with patch.object(s,'json',return_value=response): s.run([target('Example Person','Name')])
        findings = [v for k,v in self.events if k=='finding']
        self.assertEqual(len(findings),2)
        self.assertEqual(findings[0]['confidence'],'LOW')
        self.assertNotIn('private-key',json.dumps(self.events))
        self.assertIn('Public preview',client_card(findings[0]))

    def test_photo_modes_and_preview(self):
        s = self.scanner()
        responses = [{'exact_matches':[{'title':'Example','link':'https://example.org/page','thumbnail':'https://serpapi.com/searches/test/images/test.jpg'}]}, {'visual_matches':[]}]
        with patch.object(s,'json',side_effect=responses) as request:
            s.run([target('https://example.org/photo.jpg','Photo URL')])
        self.assertEqual(request.call_count,2)
        findings = [v for k,v in self.events if k=='finding']
        self.assertEqual(len(findings),3)
        self.assertIn('<img',client_card(findings[0]))
        self.assertEqual(findings[0]['relation'],'POSSIBLE_IMAGE_MATCH')
        self.assertNotIn('private-key',json.dumps(self.events))
        self.assertEqual(self.events[-1][1]['status'],'COMPLETED')

    def test_missing_key_is_failure_without_network(self):
        s = self.scanner(); s.settings['serpapi_api_key']=''
        with patch.object(s,'json') as request: s.run([target('Example','Name')])
        request.assert_not_called()
        self.assertEqual(self.events[-1][1]['status'],'FAILED')
        self.assertIn('NOT CONFIGURED',self.events[-1][1]['warnings'][0])

    def test_error_response_not_no_matches(self):
        s = self.scanner()
        with patch.object(s,'json',return_value={'error':'private-key quota details'}):
            s.run([target('Example','Name')])
        self.assertEqual(self.events[-1][1]['status'],'FAILED')
        self.assertNotIn('private-key',json.dumps(self.events))

    def test_photo_partial_results_survive_failure(self):
        s = self.scanner()
        with patch.object(s,'json',side_effect=[{'exact_matches':[]},ProviderError('RATE LIMITED')]):
            s.run([target('https://example.org/photo.jpg','Photo URL')])
        self.assertEqual(self.events[-1][1]['coverage'][0]['status'],'FAILED')
        self.assertTrue(any(k=='finding' for k,v in self.events))

    def test_local_photo_urls_rejected(self):
        for url in ['file:///photo.jpg','https://127.0.0.1/x','https://localhost/x','https://user:pass@example.org/x']:
            with self.assertRaises(ValueError): target(url,'Photo URL')

    def test_report_distinguishes_attempt_and_not_searched(self):
        self.assertIn('were not performed',client_summary([]))
        text=client_summary([], [{'coverage':[{'provider':'Photo Search','status':'FAILED'}]}])
        self.assertIn('FAILED',text)
        self.assertNotIn('were not performed',text)
