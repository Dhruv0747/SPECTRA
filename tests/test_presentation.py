import threading
import unittest
from unittest.mock import patch
from spectra.core import DEFAULTS, finding, target
from spectra.providers import Scanner, ProviderError
from spectra.presentation import client_card, client_summary, safe_url


class PresentationTests(unittest.TestCase):
    def profile(self, avatar='https://avatars.githubusercontent.com/u/1'):
        return finding('Public profile', 'GitHub', target('example', 'Username'),
                       {'summary': '<script>bad</script>', 'avatar_url': avatar, 'bio': 'Public biography'},
                       relation='POSSIBLE_PROFILE', object_type='PROFILE', object_value='https://github.com/example')

    def test_cards_escape_and_restrict_remote_images(self):
        card = client_card(self.profile())
        self.assertIn('referrerpolicy="no-referrer"', card)
        self.assertNotIn('<script>', card)
        self.assertIn('not confirmed as the client', card)
        self.assertNotIn('<img', client_card(self.profile('https://example.org/tracker')))
        self.assertEqual(safe_url('javascript:alert(1)'), '')
        self.assertEqual(safe_url('https://user:password@example.org'), '')

    def test_empty_report_does_not_claim_images_were_searched(self):
        text = client_summary([])
        self.assertIn('were not performed', text)
        self.assertIn('Public profiles (0)', text)

    def test_social_accounts_keep_actual_published_links(self):
        events = []
        s = Scanner(DEFAULTS, lambda k,v: events.append((k,v)), threading.Event())
        with patch.object(s, 'json', side_effect=[{'login':'example', 'html_url':'https://github.com/example',
                           'avatar_url':'https://avatars.githubusercontent.com/u/1'},
                          [{'provider':'instagram','url':'https://www.instagram.com/example/'},
                           {'provider':'bad','url':'javascript:alert(1)'}]]):
            s.github(target('example','Username'), [])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1][1]['relation'], 'LINKED_PROFILE')
        self.assertEqual(events[1][1]['confidence'], 'LOW')
        self.assertIn('linked_from', events[1][1]['evidence'][0]['raw'])

    def test_social_api_failure_preserves_profile(self):
        events = []
        s = Scanner(DEFAULTS, lambda k,v: events.append((k,v)), threading.Event())
        with patch.object(s, 'json', side_effect=[{'login':'example','html_url':'https://github.com/example'}, ProviderError('RATE LIMITED')]):
            with self.assertRaises(ProviderError): s.github(target('example','Username'), [])
        self.assertEqual(len(events), 1)
