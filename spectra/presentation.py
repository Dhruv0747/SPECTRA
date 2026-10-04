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
    title = ('Your email was mentioned in a leak report' if exposure else
             'An online account to check' if category(f) == 'Public profiles' else f['title'])
    parts = ['<article class="client-card"><h3>' + esc(title) + '</h3>']
    if not exposure: parts.append('<p><b>What we found:</b> ' + esc(f['summary']) + '</p>')
    if category(f) == 'Public profiles':
        parts += ['<p><b>Possible match—not confirmed as the client.</b></p>',
                  '<p><b>What this means:</b> This account may be relevant. A matching username or a linked account does not prove it belongs to you.</p>']
        avatar = safe_url(raw.get('avatar_url'))
        if avatar and urlsplit(avatar).scheme == 'https' and urlsplit(avatar).hostname == 'avatars.githubusercontent.com':
            parts.append('<figure><img class="avatar" loading="lazy" referrerpolicy="no-referrer" src="' + esc(avatar) + '" alt="Public GitHub account avatar"><figcaption>This picture is displayed on the GitHub account below. We have not established that it is your picture or searched for copies elsewhere. Internet access is needed to display it.</figcaption></figure>')
        for key, label in [('name', 'Public display name'), ('bio', 'Public bio'), ('account_created', 'Account created'), ('followers', 'Followers'), ('public_repos', 'Public repositories')]:
            if raw.get(key) is not None: parts.append('<p><b>' + label + ':</b> ' + esc(raw[key]) + '</p>')
        parts += ['<p>' + link(f['object']['value'], 'View public profile') + '</p>',
                  '<p>' + link(raw.get('linked_from'), 'Profile that published this link') + '</p>',
                  '<p>' + link(raw.get('website'), 'Website listed by the account') + '</p>']
    if exposure:
        parts.append('<dl>' + ''.join('<dt>' + label + '</dt><dd>' + esc(value) + '</dd>' for label, value in [
            ('Email checked', exposure['identifier']), ('Site or list named in the report', exposure['location']),
            ('Has it been checked?', exposure['verification']), ('When the leak happened', exposure['date'] or 'The source did not tell us'),
            ('Types of information involved', ', '.join(exposure['categories']) or 'The source did not tell us')]) + '</dl>')
        parts.append('<p><b>What this means:</b> ' + esc(exposure['provider']) + ' reports a connection between this email and the named site or list. This alone does not prove that someone can access your account today. Different lists may contain the same old leak.</p>')
    action = ('If you used this service, change any password you reused elsewhere and turn on two-step sign-in. Watch for suspicious messages.' if exposure else
              'Open the profile below. Confirm whether you recognize it before treating it as yours.' if category(f) == 'Public profiles' else f['remediation'])
    parts.append('<p><b>What you can do:</b> ' + esc(action) + '</p>')
    parts.append('<p><b>Where this came from:</b></p><ul>' + ''.join('<li>' + esc(e['provider']) + ' · Checked ' + esc(e['timestamp'][:10]) + ' · ' + link(e.get('reference'), 'See supporting source') + '</li>' for e in f['evidence']) + '</ul></article>')
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
    return '<section><h2>Your findings, explained simply</h2><p>Each card explains what was found, what it means, and your next step. Information you supplied is listed separately; it is not counted as something we found online.</p><h3>About the pictures</h3><p>A picture shown here comes directly from a public GitHub profile returned by the search. Open the profile link to see where it appears. It is not proof that the picture is yours.</p><p>Searching the internet for copies of your photo is a different check, called reverse-image search. Web-wide reverse-image search and Instagram photo collection were not performed. No picture shown does not mean your pictures are absent from the internet.</p>' + ''.join(sections) + '</section>'
