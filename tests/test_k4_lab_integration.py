"""Combined locale, recovery-origin, and password-generation regressions.

Use the Spanish HTTP fixture's real database, templates, and CSRF middleware.
The protocol-specific suites cover transports; these cases cover the shared
web paths where localization and password-session revocation meet.
"""
from datetime import datetime, timedelta
from unittest import mock
from urllib.parse import urlsplit

import pytest
from sqlalchemy.orm import Session

from anetbbs.models import PasswordResetToken, User, db
from tests.test_spanish_localization import (
    client, localized_app, make_user, _language, _post, _soup,
)


PASSWORD = 'localization-password'


def _login(browser, username, language):
    _language(browser, language)
    response = _post(browser, '/auth/login', {
        'username': username, 'password': PASSWORD,
    }, token_path='/auth/login')
    assert response.status_code == 302
    assert _soup(browser.get('/profile/change-password')).html['lang'] == language


def _copy_old_cookies(app, browser, language):
    """Keep the signed session and remember cookie on separate browsers."""
    stale = app.test_client()
    session_name = app.config['SESSION_COOKIE_NAME']
    stale.set_cookie(session_name, browser.get_cookie(session_name).value)
    remembered = app.test_client()
    remembered.set_cookie('remember_token', browser.get_cookie('remember_token').value)
    for copy in (stale, remembered):
        copy.set_cookie('anetbbs_language', language)
    return stale, remembered


def _assert_revoked(browser, language):
    response = browser.get('/profile/change-password')
    assert response.status_code == 302
    assert urlsplit(response.location).path == '/auth/login'
    assert _soup(browser.get(response.location)).html['lang'] == language


@pytest.mark.parametrize('language,success', [
    ('en', 'Password changed successfully!'),
    ('es', '¡Contraseña cambiada correctamente!'),
])
def test_localized_password_change_renews_current_browser_and_revokes_copies(
        localized_app, client, make_user, language, success):
    user_id, username, _ = make_user(language)
    _login(client, username, language)
    stale, remembered = _copy_old_cookies(localized_app, client, language)

    result = _soup(_post(client, '/profile/change-password', {
        'current_password': PASSWORD,
        'new_password': 'localized-replacement-password',
        'confirm_password': 'localized-replacement-password',
    }, token_path='/profile/change-password', follow_redirects=True))
    assert result.html['lang'] == language
    assert success in result.get_text(' ', strip=True)
    assert _soup(client.get('/profile/change-password')).html['lang'] == language
    with localized_app.app_context():
        user = db.session.get(User, user_id)
        assert user.check_password('localized-replacement-password')
        assert user.auth_version
        identifier = user.get_id()
    with client.session_transaction() as session:
        assert session['_user_id'] == identifier
        assert session['language'] == language

    _assert_revoked(stale, language)
    _assert_revoked(remembered, language)
    # The renewing browser's new remember cookie must work on its own too.
    fresh_remembered = localized_app.test_client()
    fresh_remembered.set_cookie(
        'remember_token', client.get_cookie('remember_token').value)
    assert _soup(fresh_remembered.get('/profile/change-password')).html['lang'] == language


@pytest.mark.parametrize('language,success', [
    ('en', 'Password updated. You can log in now.'),
    ('es', 'Contraseña actualizada. Ya puedes iniciar sesión.'),
])
def test_localized_reset_revokes_prior_session_and_remember_cookie(
        localized_app, client, make_user, language, success):
    user_id, username, _ = make_user(language)
    old_browser = localized_app.test_client()
    _login(old_browser, username, language)
    stale, remembered = _copy_old_cookies(localized_app, old_browser, language)
    token = f'combined-localized-reset-{user_id}'
    with localized_app.app_context():
        db.session.add(PasswordResetToken(
            user_id=user_id, token=token,
            expires_at=datetime.utcnow() + timedelta(hours=1)))
        db.session.commit()

    _language(client, language)
    path = '/auth/reset/' + token
    result = _soup(_post(client, path, {
        'password': 'localized-reset-password',
        'password2': 'localized-reset-password',
    }, token_path=path, follow_redirects=True))
    assert result.html['lang'] == language
    assert success in result.get_text(' ', strip=True)
    with localized_app.app_context():
        user = db.session.get(User, user_id)
        assert user.check_password('localized-reset-password')
        assert user.auth_version
        assert PasswordResetToken.query.filter_by(token=token).one().used_at is not None
    _assert_revoked(stale, language)
    _assert_revoked(remembered, language)


@pytest.mark.parametrize('language,canonical_host', [
    ('en', 'canonical-en.invalid:8443'),
    ('es', 'canonical-es.invalid:9443'),
])
def test_localized_forgot_uses_canonical_origin_and_rejects_poisoned_host(
        localized_app, client, make_user, monkeypatch, language, canonical_host):
    user_id, username, _ = make_user(language)
    canonical_domain = urlsplit('https://' + canonical_host).hostname
    client.set_cookie('anetbbs_language', language, domain=canonical_domain)
    original_open = client.open

    def canonical_request(*args, **kwargs):
        # Keep the shared CSRF helper while making real requests on a public
        # host distinct from the fixture's localhost development origin.
        kwargs.setdefault('base_url', 'http://' + canonical_host)
        return original_open(*args, **kwargs)

    monkeypatch.setattr(client, 'open', canonical_request)
    # The incoming request is HTTP. Configuration must choose HTTPS even
    # while untrusted forwarding headers name a different host and scheme.
    monkeypatch.setitem(localized_app.config, 'PUBLIC_BASE_URL', 'https://' + canonical_host)
    monkeypatch.setitem(client.environ_base, 'HTTP_X_FORWARDED_HOST', 'attacker.invalid')
    monkeypatch.setitem(client.environ_base, 'HTTP_X_FORWARDED_PROTO', 'http')
    monkeypatch.setitem(client.environ_base, 'HTTP_FORWARDED',
                        'host=attacker.invalid;proto=http')
    assert localized_app.config['WTF_CSRF_ENABLED']

    with mock.patch('anetbbs.mailer.smtp_enabled', return_value=True), \
            mock.patch('anetbbs.mailer.send_password_reset_email') as send, \
            mock.patch('anetbbs.web.auth.threading.Thread') as thread:
        result = _soup(_post(client, '/auth/forgot', {'identifier': username},
                             token_path='/auth/forgot'))
        assert result.html['lang'] == language
        thread.assert_called_once()
        callback = thread.call_args.kwargs
        callback['target'](*callback['args'])
        send.assert_called_once()
        parsed = urlsplit(send.call_args.args[1])
        assert (parsed.scheme, parsed.netloc) == ('https', canonical_host)
        assert parsed.path.startswith('/auth/reset/')
        with localized_app.app_context():
            assert PasswordResetToken.query.filter_by(user_id=user_id).count() == 1

        # Supply a valid CSRF session on the attacker host, so the request
        # reaches the recovery-origin guard instead of failing CSRF first.
        page = _soup(client.get('/auth/forgot'))
        csrf_token = page.select_one('input[name=csrf_token]')['value']
        session_name = localized_app.config['SESSION_COOKIE_NAME']
        client.set_cookie(session_name,
                          client.get_cookie(session_name, domain=canonical_domain).value,
                          domain='attacker.invalid')
        rejected = client.post('/auth/forgot',
                               headers={'Host': 'attacker.invalid'},
                               data={'identifier': username, 'csrf_token': csrf_token})
        assert rejected.status_code == 400
        assert 'Use the configured public host for password recovery.' in rejected.get_data(as_text=True)
        assert thread.call_count == send.call_count == 1
    with localized_app.app_context():
        assert PasswordResetToken.query.filter_by(user_id=user_id).count() == 1


@pytest.mark.parametrize('language,message', [
    ('en', 'Invalid username or password'),
    ('es', 'Nombre de usuario o contraseña incorrectos'),
])
def test_concurrent_reset_rejects_login_with_localized_message(
        localized_app, client, make_user, monkeypatch, language, message):
    user_id, username, _ = make_user(language)
    _language(client, language)
    with localized_app.app_context():
        engine = db.engine
    original_update = User.update_login
    reset_versions = []

    def reset_after_verified_login_commit(user):
        target_id = user.id
        original_update(user)
        if target_id == user_id:
            with Session(engine) as independent:
                target = independent.get(User, user_id)
                target.set_password('concurrent-localized-reset-password')
                reset_versions.append(target.auth_version)
                independent.commit()

    monkeypatch.setattr(User, 'update_login', reset_after_verified_login_commit)
    result = _soup(_post(client, '/auth/login', {
        'username': username, 'password': PASSWORD,
    }, token_path='/auth/login', follow_redirects=True))
    assert len(reset_versions) == 1
    assert result.html['lang'] == language
    assert message in result.get_text(' ', strip=True)
    with client.session_transaction() as session:
        assert '_user_id' not in session
    assert client.get_cookie('remember_token') is None
    _assert_revoked(client, language)
    with localized_app.app_context():
        user = db.session.get(User, user_id)
        assert user.auth_version == reset_versions[0]
        assert user.check_password('concurrent-localized-reset-password')


@pytest.mark.parametrize('language', ['en', 'es'])
def test_concurrent_reset_rejects_password_change_with_localized_message(
        localized_app, client, make_user, monkeypatch, language):
    from anetbbs.features.i18n import DEFAULT_TRANSLATIONS

    user_id, username, _ = make_user(language)
    _login(client, username, language)
    with localized_app.app_context():
        engine = db.engine
    original_set = User.set_password
    original_commit = db.session.commit
    pending = False
    reset_versions = []

    def replace_password(user, password):
        nonlocal pending
        original_set(user, password)
        if user.id == user_id and password == 'localized-replacement-password':
            pending = True

    def commit_then_reset():
        nonlocal pending
        original_commit()
        if pending:
            pending = False
            with Session(engine) as independent:
                target = independent.get(User, user_id)
                target.set_password('concurrent-localized-reset-password')
                reset_versions.append(target.auth_version)
                independent.commit()

    monkeypatch.setattr(User, 'set_password', replace_password)
    monkeypatch.setattr(db.session, 'commit', commit_then_reset)
    result = _soup(_post(client, '/profile/change-password', {
        'current_password': PASSWORD,
        'new_password': 'localized-replacement-password',
        'confirm_password': 'localized-replacement-password',
    }, token_path='/profile/change-password', follow_redirects=True))
    assert len(reset_versions) == 1
    assert result.html['lang'] == language
    message = 'Your password changed again. Please log in.'
    if language == 'es':
        translated = DEFAULT_TRANSLATIONS['es']['profile.password_changed_again']
        assert translated and translated != message
        message = translated
    assert message in result.get_text(' ', strip=True)
    with client.session_transaction() as session:
        assert '_user_id' not in session
    assert client.get_cookie('remember_token') is None
    _assert_revoked(client, language)
    with localized_app.app_context():
        user = db.session.get(User, user_id)
        assert user.auth_version == reset_versions[0]
        assert user.check_password('concurrent-localized-reset-password')
