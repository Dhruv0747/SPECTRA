"""Source-backed client cards. External URLs are never trusted HTML."""
import html
from urllib.parse import urlsplit


def safe_url(value):
    if not isinstance(value, str): return ''
    try:
        u = urlsplit(value)
        if u.scheme in ('https', 'http') and u.hostname and not u.username and not u.password:
            return value
    except ValueError:
        pass
    return ''


def link(value, label='Open source'):
    url = safe_url(value)
    if not url: return ''
    return '<a target="_blank" rel="noopener noreferrer" href="' + html.escape(url, quote=True) + '">' + html.escape(label) + '</a>'


def category(f):
    if f.get('exposure'): return 'Exposure reports'
    if f.get('object', {}).get('type') == 'PROFILE': return 'Public profiles'
    if f.get('source') == 'Image': return 'Image analysis'
    return 'Other observations'


def client_card(f):
    esc = lambda v: html.escape(str(v), quote=True)
    raw = f['evidence'][0].get('raw', {}) if f.get('evidence') else {}
    exposure = f.get('exposure')
    parts = ['<article class="client-card"><p class="tag">' + esc(category(f)) + '</p>',
             '<h3>' + esc(f['title']) + '</h3>', '<p>' + esc(f['summary']) + '</p>']
    if category(f) == 'Public profiles':
        parts += ['<p><b>Possible match—not confirmed as the client.</b></p>',
                  '<p>' + esc(raw.get('match_basis', 'Provider observation; independently verify account ownership.')) + '</p>']
        avatar = safe_url(raw.get('avatar_url'))
        if avatar and urlsplit(avatar).scheme == 'https' and urlsplit(avatar).hostname == 'avatars.githubusercontent.com':
            parts.append('<figure><img class="avatar" loading="lazy" referrerpolicy="no-referrer" src="' + esc(avatar) + '" alt="Public GitHub account avatar"><figcaption>Account avatar supplied by GitHub. Not a reverse-image match or identity proof. Requires internet access.</figcaption></figure>')
        for key, label in [('name', 'Public display name'), ('bio', 'Public bio'), ('account_created', 'Account created'), ('followers', 'Followers'), ('public_repos', 'Public repositories')]:
            if raw.get(key) is not None: parts.append('<p><b>' + label + ':</b> ' + esc(raw[key]) + '</p>')
        parts += ['<p>' + link(f['object']['value'], 'View public profile') + '</p>',
                  '<p>' + link(raw.get('linked_from'), 'Profile that published this link') + '</p>',
                  '<p>' + link(raw.get('website'), 'Website listed by the account') + '</p>']
    if exposure:
        parts.append('<dl>' + ''.join('<dt>' + label + '</dt><dd>' + esc(value) + '</dd>' for label, value in [
            ('Affected identifier', exposure['identifier']), ('Reported site / collection', exposure['location']),
            ('Verification', exposure['verification']), ('Breach date', exposure['date'] or 'Not supplied'),
            ('Data categories', ', '.join(exposure['categories']) or 'Not supplied by this source')]) + '</dl>')
    parts.append('<p><b>What to do:</b> ' + esc(f['remediation']) + '</p>')
    parts.append('<ul>' + ''.join('<li>' + esc(e['provider']) + ' · ' + esc(e['timestamp']) + ' · ' + link(e.get('reference')) + '</li>' for e in f['evidence']) + '</ul></article>')
    return ''.join(parts)


def client_summary(items):
    groups = ['Exposure reports', 'Public profiles', 'Image analysis', 'Other observations']
    sections = []
    for group in groups:
        selected = [f for f in items if category(f) == group]
        if group == 'Other observations':
            sections.append('<details><summary>Technical and other observations (' + str(len(selected)) + ')</summary>' + ''.join(client_card(f) for f in selected) + '</details>')
        else:
            empty = 'No findings returned in this category by the sources checked.'
            sections.append('<h2>' + group + ' (' + str(len(selected)) + ')</h2><div class="cards">' + (''.join(client_card(f) for f in selected) or '<p>' + empty + '</p>') + '</div>')
    return '<section><h2>What the investigation found</h2><p>These are source observations, separate from the identifiers supplied for the investigation. They are not necessarily new to the client or verified identity matches.</p><p>Image coverage: public GitHub avatars may appear below. Web-wide reverse-image search and Instagram photo collection were not performed.</p>' + ''.join(sections) + '</section>'
