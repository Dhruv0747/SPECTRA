import copy
import tempfile
import unittest
from spectra.core import CaseStore, finding, target, report_html, risk
from spectra.results import results, case_details, finding_details


def event(kind, value, module):
    t=target('jane@example.com','Email')
    return finding('SpiderFoot: '+kind,'SpiderFoot',t,{'summary':value,'event':['2026-10-04',value,'seed',module,1,1,1,1,0,0,kind]},confidence='LOW',object_type=kind,object_value=value)


class ResultTests(unittest.TestCase):
    def case(self):
        return {'name':'Example case','client':'Example client','authorization':'Test','targets':[target('jane@example.com')],
                'findings':[event('EMAILADDR','jane@example.com','SpiderFoot UI'),
                            event('EMAILADDR_COMPROMISED','jane@example.com [example.org]','sfp_citadel')], 'scans':[]}

    def test_legacy_exposure_is_reviewable_without_mutating_evidence(self):
        case=self.case()
        original=copy.deepcopy(case)
        items=results(case)
        self.assertEqual(len(items),1)
        f=items[0]
        self.assertEqual(f['severity'],'MEDIUM')
        self.assertEqual(f['confidence'],'LOW')
        self.assertEqual(f['exposure']['location'],'example.org')
        self.assertEqual(f['exposure']['categories'],[])
        self.assertEqual(case,original)
        self.assertEqual(risk(case)[1]['MEDIUM'],1)
        self.assertGreater(risk(case)[0],0)

    def test_all_details_on_page_without_invented_credentials(self):
        text=case_details(self.case())
        for expected in ['jane@example.com','example.org','Leak-Lookup','Unverified provider claim',
                         'Breach date: Not supplied','Exposed data categories: Not supplied','Secret credentials: not retrieved',
                         'ENTERED TARGETS (not discoveries)']:
            self.assertIn(expected,text)
        self.assertNotIn('SpiderFoot: EMAILADDR\n',text)

    def test_report_uses_same_classification_and_no_safety_score(self):
        report=report_html(self.case())
        self.assertIn('Needs review',report)
        self.assertIn('Unverified provider claim',report)
        self.assertIn('example.org',report)
        self.assertNotIn('/100',report)
        self.assertNotIn('SpiderFoot: EMAILADDR',report)

    def test_hibp_categories_are_only_shown_when_supplied(self):
        f=finding('Breach exposure','HIBP',target('jane@example.com'),
                  {'Name':'Example breach','DataClasses':['Email addresses','Passwords'], 'BreachDate':'2020-01-01','IsVerified':True},
                  relation='APPEARED_IN',object_type='BREACH',object_value='Example breach')
        text=finding_details(f)
        self.assertIn('Exposed data categories: Email addresses, Passwords',text)
        self.assertIn('Breach date: 2020-01-01',text)
        self.assertIn('Secret credentials: not retrieved',text)

    def test_result_view_loads_legacy_saved_case(self):
        with tempfile.TemporaryDirectory() as folder:
            store=CaseStore(folder)
            case=store.create('Example')
            case['findings']=self.case()['findings']
            store.save(case)
            from pathlib import Path
            loaded=store.load(Path(folder)/'cases'/(case['id']+'.json'))
            self.assertEqual(len(results(loaded)),1)
            self.assertEqual(len(loaded['findings']),2)


if __name__=='__main__': unittest.main()
