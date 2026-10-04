"""Offline GUI integration: real Tk, background image scan, persistence and graph."""
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from PIL import Image
from spectra.app import SpectraApp
from spectra.core import target, report_html
from spectra.providers import ProviderError


class GuiTests(unittest.TestCase):
    def test_failed_investigation_shows_provider_reason(self):
        with tempfile.TemporaryDirectory() as folder:
            app = SpectraApp(start_engine=False, root=folder)
            try:
                app.case = app.store.create('Failure coverage', '', '')
                app.case['targets'] = [target('Jane Doe', 'Name')]
                app.settings['spiderfoot_enabled'] = True
                with patch('spectra.providers.Engine.ensure', side_effect=ProviderError('No modules matched the selected scan profile.')):
                    app.run_scan()
                    deadline = time.monotonic() + 5
                    while app.busy() and time.monotonic() < deadline:
                        app.update()
                        time.sleep(.01)
                self.assertFalse(app.busy())
                self.assertEqual(app.case['scans'][-1]['status'], 'FAILED')
                self.assertIn('No modules matched', app.scan_notice.get())
                self.assertEqual(app.status.get(), 'FAILED')
            finally:
                app.on_close()

    def test_case_image_scan_graph_and_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            app = SpectraApp(start_engine=False, root=folder)
            errors = []
            app.report_callback_exception = lambda *args: errors.append(args)
            try:
                app.case = app.store.create('GUI smoke', 'Test', 'Local synthetic images only')
                for name in ('a.png', 'b.png'):
                    path = Path(folder)/name
                    Image.new('RGB', (32, 24), '#18aabb').save(path)
                    app.case['targets'].append(target(str(path), 'Image'))
                app.refresh()
                app.run_scan()
                deadline = time.monotonic() + 10
                while app.busy() and time.monotonic() < deadline:
                    app.update()
                    time.sleep(.01)
                self.assertFalse(app.busy(), 'Worker did not complete')
                self.assertEqual(app.case['scans'][-1]['status'], 'COMPLETED')
                self.assertEqual(len(app.case['findings']), 3)
                self.assertTrue(any(f['relation'] == 'IDENTICAL_TO' for f in app.case['findings']))
                for page in app.pages:
                    app.show_page(page)
                    app.update()
                app.draw_graph()
                self.assertTrue(app.canvas.find_all())
                app.findings_tree.selection_set(app.case['findings'][0]['id'])
                app.show_finding()
                self.assertIn('Image', app.detail.get('1.0', 'end'))
                saved = app.store.load(Path(folder)/'cases'/f"{app.case['id']}.json")
                self.assertEqual(len(saved['findings']), 3)
                self.assertIn('Exact image duplicate', report_html(saved))
                app.show_page('Results')
                self.assertIn('Exact image duplicate', app.results_text.get('1.0', 'end'))
                app.results_query.set('Exact image duplicate')
                app.find_in_results()
                self.assertTrue(app.results_text.tag_ranges('match'))
                app.results_query.set('absent-search-text')
                app.find_in_results()
                self.assertEqual(app.results_match.get(), 'No match')
                self.assertEqual(saved['scans'][-1]['coverage'][0]['status'], 'COMPLETED')
                self.assertNotIn('/100', app.overview.get('1.0', 'end'))
                self.assertFalse(errors, errors)
            finally:
                app.on_close()


if __name__ == '__main__': unittest.main()
