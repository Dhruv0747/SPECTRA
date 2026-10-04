"""Human-readable exposure views for current and earlier saved evidence."""
import copy
import re

PRIORITY = {'HIGH': 'High priority', 'MEDIUM': 'Needs review', 'LOW': 'Low priority', 'INFO': 'Context'}


def normalize_finding(item):
    f = copy.deepcopy(item)
    evidence = f.get('evidence', [])
    raw = evidence[0].get('raw', {}) if evidence else {}
    row = raw.get('event', [])
    if isinstance(row, list) and len(row) >= 11:
        module, event_type = str(row[3]), str(row[10])
        if module == 'SpiderFoot UI' or event_type == 'ROOT':
            f['record_role'] = 'input'
            return f
        if event_type == 'EMAILADDR_COMPROMISED':
            observation = str(row[1])
            match = re.fullmatch(r'(.*?)\s+\[([^\]]+)\]', observation)
            site = match.group(2) if match else 'Not supplied by source'
            identifier = match.group(1).strip() if match else f['subject']['value']
            provider = 'Leak-Lookup' if module == 'sfp_citadel' else 'SpiderFoot / ' + module
            f.update(title='Possible email exposure — ' + site, severity='MEDIUM', confidence='LOW',
                     source=provider, summary=f'{provider} reports {identifier} associated with {site}. This is an unverified source claim.',
                     remediation='Verify the association through a trusted breach-notification service. If relevant, change reused passwords, enable MFA and review account activity.')
            f['exposure'] = {'identifier': identifier, 'location': site, 'provider': provider,
                             'categories': [], 'date': '', 'verification': 'Unverified provider claim',
                             'reference': 'https://leak-lookup.com/' if module == 'sfp_citadel' else evidence[0].get('reference', '')}
        else:
            f['title'] = event_type.replace('_', ' ').capitalize()
    elif f.get('source') == 'HIBP' and f.get('relation') == 'APPEARED_IN':
        f['exposure'] = {'identifier': f['subject']['value'], 'location': raw.get('Name') or f['object']['value'],
                         'provider': 'Have I Been Pwned', 'categories': raw.get('DataClasses') or [],
                         'date': raw.get('BreachDate') or '',
                         'verification': 'Provider marks this breach verified' if raw.get('IsVerified') else 'Provider has not verified this breach',
                         'reference': 'https://haveibeenpwned.com/'}
    return f


def results(case):
    return [f for f in map(normalize_finding, case.get('findings', [])) if f.get('record_role') != 'input']


def finding_details(item):
    f = normalize_finding(item)
    exposure = f.get('exposure')
    lines = [f['title'], PRIORITY.get(f['severity'], f['severity']) + ' · Confidence: ' + f['confidence'],
             'Affected identifier: ' + f['subject']['value']]
    if exposure:
        lines += ['Reported site / collection: ' + exposure['location'],
                  'Reporting provider: ' + exposure['provider'],
                  'Verification: ' + exposure['verification'],
                  'Breach date: ' + (exposure['date'] or 'Not supplied by source'),
                  'Exposed data categories: ' + (', '.join(exposure['categories']) or 'Not supplied by source'),
                  'What is known: an identifier association was reported; this does not establish what other fields were exposed.',
                  'Secret credentials: not retrieved or displayed.',
                  'Provider reference: ' + exposure['reference']]
    lines += ['', f['summary'], '', 'Recommended action: ' + f['remediation'], '', 'Evidence and provenance:']
    for e in f['evidence']:
        raw = e.get('raw', {})
        lines += ['Observed: ' + e['timestamp'], 'Source: ' + e['provider'],
                  'Evidence reference: ' + (e.get('reference') or 'Local observation'),
                  'Investigation path: ' + ' → '.join(t['value'] for t in e.get('pivot_path', []))]
        if not exposure:
            for k, v in raw.items():
                if k in ('summary', 'event', 'scan_id'): continue
                if any(secret in k.lower() for secret in ('password', 'token', 'api_key', 'secret')): continue
                if isinstance(v, (str, int, float, bool)) or v is None:
                    lines.append(k.replace('_', ' ').capitalize() + ': ' + str(v))
                elif isinstance(v, list) and all(isinstance(x, (str, int, float)) for x in v):
                    lines.append(k.replace('_', ' ').capitalize() + ': ' + ', '.join(map(str, v)))
        lines.append('')
    return '\n'.join(lines)


def case_details(case):
    items = results(case)
    exposures = [f for f in items if f.get('exposure')]
    lines = [case['name'], 'Client / owner: ' + (case['client'] or 'Not specified'),
             'Case context only: entering a name, phone and email together does not prove they belong to the same person.',
             '', 'ENTERED TARGETS (not discoveries)']
    lines += [t['type'].capitalize() + ': ' + t['value'] for t in case['targets']]
    lines += ['', f'{len(items)} findings · {len(exposures)} reported exposure associations',
              'Exposure associations can refer to overlapping collections; they are not necessarily distinct breaches.']
    latest = case['scans'][-1] if case['scans'] else None
    lines += ['', 'LATEST SCAN', latest['status'] if latest else 'No scan recorded']
    if latest: lines += latest.get('warnings', [])
    lines += ['', 'ALL FINDING DETAILS', '']
    if not items: lines.append('No discoveries yet. Review source coverage; this is not evidence of safety.')
    for index, f in enumerate(items, 1):
        lines += [f'{index}. ' + finding_details(f), '─' * 65, '']
    return '\n'.join(lines)
