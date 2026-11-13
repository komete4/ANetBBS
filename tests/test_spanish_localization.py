"""HTTP coverage for the Spanish UI, persisted preferences, and safe fallbacks.

Every request uses the real CSRF middleware, templates, and database. App data
and configuration live in a temporary directory; no checked-in DB is reused.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta
from itertools import count
import json
from pathlib import Path
import sys

from bs4 import BeautifulSoup
import pytest
from sqlalchemy import event

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anetbbs.models import (
    Board, EmailVerifyToken, MenuTranslation, PasswordRecoverySettings,
    PasswordResetToken, Post, PrivateMessage, SmtpConfig, User, db,
)

_client_addresses = count(1)


@pytest.fixture(scope='module')
def localized_app(tmp_path_factory):
    import anetbbs.config as cfg
    from anetbbs.web_app import create_app

    root = tmp_path_factory.mktemp('spanish-localization')
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('ANETBBS_SCHEMA_MIGRATE_ONLY', '1')
        patch.setattr(cfg.TestingConfig, 'SQLALCHEMY_DATABASE_URI',
                      f'sqlite:///{root / "bbs.sqlite"}')
        patch.setattr(cfg.TestingConfig, 'WTF_CSRF_ENABLED', True)
        patch.setattr(cfg.TestingConfig, 'SECRET_KEY', 'spanish-integration-tests')
        patch.setattr(cfg.TestingConfig, 'NUV_ENABLED', False)
        # Keep rendering tests independent of the public federation and IRC services.
        patch.setattr(cfg.TestingConfig, 'REGISTRY_URL', '')
        patch.setattr(cfg.TestingConfig, 'MRC_NETWORK_STATS_ENABLED', False)
        patch.setattr(cfg.TestingConfig, 'SBBSIMSG_AUTO_REFRESH', False)
        patch.setattr(cfg.TestingConfig, 'REGISTRATION_INVITE_CODE', '')
        patch.setattr(cfg.TestingConfig, 'PUBLIC_BASE_URL', 'http://localhost', raising=False)
        for name in ('DATA_DIR', 'UPLOADS_DIR', 'AVATARS_DIR', 'NETWORK_JOIN_DIR',
                     'GAMES_DATA_DIR', 'ECHOMAIL_DATA_DIR', 'DOWNLOADS_DIR',
                     'FILE_BULLETINS_DIR', 'TDF_FONTS_DIR'):
            path = root / name.lower()
            path.mkdir()
            patch.setattr(cfg.TestingConfig, name, str(path))
        patch.setattr(cfg.TestingConfig, 'LOG_FILE', str(root / 'bbs.log'))
        app = create_app('testing')
        with app.app_context():
            PasswordRecoverySettings.get().security_questions_enabled = False
            smtp = SmtpConfig.query.first()
            if smtp:
                smtp.enabled = False
                smtp.email_verify_enabled = False
            db.session.commit()
        yield app
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        for handler in list(app.logger.handlers):
            if getattr(handler, 'baseFilename', None) == str(root / 'bbs.log'):
                app.logger.removeHandler(handler)
                handler.close()


@pytest.fixture
def client(localized_app):
    browser = localized_app.test_client()
    # Registration's DB-backed per-IP limiter also needs request isolation.
    browser.environ_base['REMOTE_ADDR'] = f'2001:db8::{next(_client_addresses):x}'
    return browser


@pytest.fixture
def make_user(localized_app):
    serial = count()
    # A function-specific prefix avoids coupling cases through account data.
    import uuid
    prefix = 'locale' + uuid.uuid4().hex[:10]

    def create(language='en', **values):
        username = prefix + str(next(serial))
        with localized_app.app_context():
            user = User(username=username, email=f'{username}@example.com',
                        language=language, is_verified=True, **values)
            user.set_password('localization-password')
            db.session.add(user)
            db.session.commit()
            return user.id, user.username, user.email
    return create


def _soup(response):
    assert response.status_code == 200, response.get_data(as_text=True)[:1000]
    return BeautifulSoup(response.get_data(as_text=True), 'html.parser')


def _language(client, language):
    with client.session_transaction() as session:
        session['language'] = language


def _auth_identifier(client, user_id):
    with client.application.app_context():
        return db.session.get(User, user_id).get_id()


def _authenticate(client, user_id):
    identifier = _auth_identifier(client, user_id)
    with client.session_transaction() as session:
        session['_user_id'] = identifier
        session['_fresh'] = True


def _post(client, path, data, *, token_path='/', follow_redirects=False):
    page = _soup(client.get(token_path))
    token = page.select_one('input[name=csrf_token]')['value']
    return client.post(path, data={**data, 'csrf_token': token},
                       follow_redirects=follow_redirects)


@contextmanager
def _overrides(app, **texts):
    with app.app_context():
        old = {}
        for key, text in texts.items():
            row = MenuTranslation.query.filter_by(lang='es', key=key).first()
            old[key] = row.text if row else None
            if row:
                row.text = text
            else:
                db.session.add(MenuTranslation(lang='es', key=key, text=text))
        db.session.commit()
    try:
        yield
    finally:
        with app.app_context():
            for key, text in old.items():
                row = MenuTranslation.query.filter_by(lang='es', key=key).one()
                if text is None:
                    db.session.delete(row)
                else:
                    row.text = text
            db.session.commit()


@pytest.mark.parametrize('language,new_here,sign_up,home', [
    ('en', 'New here?', 'Sign up', 'Home'),
    ('es', '¿Es tu primera visita?', 'Crear cuenta', 'Inicio'),
])
def test_anonymous_home_and_navigation(client, language, new_here, sign_up, home):
    _language(client, language)
    page = _soup(client.get('/'))
    assert page.html['lang'] == language
    assert new_here in page.get_text(' ', strip=True)
    assert sign_up in [a.get_text(' ', strip=True) for a in page.select('a[href="/auth/register"]')]
    assert home in [a.get_text(' ', strip=True) for a in page.select('a[href="/"]')]
    picker = page.select_one('form[action="/language"]')
    assert picker['method'] == 'post'
    assert picker.select_one('input[name=csrf_token]')
    assert picker.select_one(f'option[value={language}]').has_attr('selected')


@pytest.mark.parametrize('language,title,code,add,save,delete', [
    ('es', 'Traducciones', 'Código de idioma', 'Añadir', 'Guardar', 'Eliminar'),
    ('en', 'Translations', 'Language code', 'Add', 'Save', 'Delete'),
])
def test_translation_editor_localizes_controls_but_keeps_catalogue_rows(
        client, make_user, language, title, code, add, save, delete):
    user_id, _, _ = make_user(language, is_admin=True)
    _authenticate(client, user_id)
    page = _soup(client.get('/admin/translations'))

    assert page.title.get_text(strip=True) == title
    assert page.select_one('h1').get_text(strip=True) == title
    assert page.select_one('label[for=translation-lang]').get_text(strip=True) == code
    assert page.select_one('form.card button').get_text(strip=True) == add
    rows = page.select('tbody tr')
    codes = {row.select_one('td:first-child').get_text(strip=True) for row in rows}
    if language == 'es':
        assert codes == {'es'}
        assert page.select_one('#translation-filter option[value=es]').has_attr('selected')
    else:
        assert codes >= {'es', 'de', 'pt'}
    all_languages = _soup(client.get('/admin/translations?lang='))
    assert all_languages.select_one('tbody input[value="Início"]')
    german = _soup(client.get('/admin/translations?lang=de'))
    assert {cell.get_text(strip=True) for cell in german.select('tbody td:first-child')} == {'de'}
    assert {button.get_text(strip=True) for button in page.select('tbody button')} == {save, delete}
    assert page.select_one('tbody input[name=text]').get('aria-label')


def test_translation_editor_crud_uses_admin_language(client, localized_app, make_user):
    user_id, _, _ = make_user('es', is_admin=True)
    _authenticate(client, user_id)
    path = '/admin/translations?lang=pt'
    data = {'action': 'add', 'lang': 'pt', 'key': 'test.editor', 'text': 'Olá'}
    page = _soup(_post(client, path, data, token_path=path, follow_redirects=True))
    assert 'Traducción añadida.' in page.get_text(' ', strip=True)
    page = _soup(_post(client, path, data, token_path=path, follow_redirects=True))
    assert 'Ya existe una traducción para pt/test.editor.' in page.get_text(' ', strip=True)
    with localized_app.app_context():
        row_id = MenuTranslation.query.filter_by(lang='pt', key='test.editor').one().id
    page = _soup(_post(client, path, {
        'action': 'edit', 'row_id': row_id, 'text': 'Bem-vindo',
    }, token_path=path, follow_redirects=True))
    assert 'Traducción actualizada.' in page.get_text(' ', strip=True)
    assert page.select_one('input[value="Bem-vindo"]')
    response = _post(client, path, {'action': 'delete', 'row_id': row_id}, token_path=path)
    assert response.status_code == 302
    with localized_app.app_context():
        assert db.session.get(MenuTranslation, row_id) is None


def test_admin_hub_preserves_urls_and_uses_localized_card_labels(
        client, localized_app, make_user):
    from anetbbs.features.i18n import DEFAULT_TRANSLATIONS
    from anetbbs.web.admin import ADMIN_HUB_SECTIONS

    user_id, _, _ = make_user('es', is_admin=True)
    _authenticate(client, user_id)
    catalogue = DEFAULT_TRANSLATIONS['es']
    for section, config in ADMIN_HUB_SECTIONS.items():
        page = _soup(client.get(f'/admin/hub/{section}'))
        assert page.select_one('h1').get_text(strip=True) == catalogue[f'admin.hub.section.{section}']
        cards = {node.select_one('.card-title').get_text(strip=True):
                 node.select_one('.card-text').get_text(strip=True)
                 for node in page.select('a:has(.card-title)')}
        for endpoint, _, _, _, *fragment in config['tools']:
            if endpoint == 'hub_admin.index' and not localized_app.config.get('REGISTRY_MODE_ENABLED'):
                # The hub card is hidden on non-hub installations.
                continue
            key = 'admin.hub.tool.' + '.'.join([endpoint, *fragment])
            assert cards[catalogue[f'{key}.label']] == catalogue[f'{key}.description']
    settings = _soup(client.get('/admin/hub/settings'))
    assert settings.select_one('a[href="/admin/translations"] .card-title').get_text(strip=True) == 'Traducciones'
    users = _soup(client.get('/admin/hub/users'))
    nodespy = users.select_one('a[href$="#nodespy"] .card-title')
    assert nodespy.get_text(strip=True) == 'NodeSpy (desconectar usuarios)'


@pytest.mark.parametrize('language,username,password,register,identifier,send', [
    ('en', 'Username', 'Password', 'Register', 'Username or Email', 'Send Reset Link'),
    ('es', 'Nombre de usuario', 'Contraseña', 'Registrarse',
     'Nombre de usuario o correo electrónico', 'Enviar enlace de recuperación'),
])
def test_authentication_and_recovery_form_labels(client, language, username, password,
                                                 register, identifier, send):
    _language(client, language)
    login = _soup(client.get('/auth/login'))
    assert login.select_one('label[for=username]').get_text(strip=True) == username
    assert login.select_one('label[for=password]').get_text(strip=True) == password
    registration = _soup(client.get('/auth/register'))
    assert registration.select_one('input[type=submit]')['value'] == register
    forgot = _soup(client.get('/auth/forgot'))
    assert forgot.select_one('label[for=identifier]').get_text(strip=True) == identifier
    assert forgot.select_one('form:not([action]) button').get_text(strip=True) == send


@pytest.mark.parametrize('language,required,invalid_credentials,invalid_email,mismatch', [
    # Spanish first catches accidental mutation of shared WTForms validators
    # when the following English request binds the same form class.
    ('es', 'Este campo es obligatorio.', 'Nombre de usuario o contraseña incorrectos',
     'Dirección de correo electrónico no válida.', 'Las contraseñas deben coincidir'),
    ('en', 'This field is required.', 'Invalid username or password',
     'Invalid email address.', 'Passwords must match'),
])
def test_auth_validation_uses_request_language(client, language, required,
                                              invalid_credentials, invalid_email, mismatch):
    _language(client, language)
    empty = _soup(_post(client, '/auth/login', {}, token_path='/auth/login'))
    assert required in empty.get_text(' ', strip=True)
    bad_login = _soup(_post(client, '/auth/login', {
        'username': 'no-such-localized-user', 'password': 'incorrect',
    }, token_path='/auth/login', follow_redirects=True))
    assert invalid_credentials in bad_login.get_text(' ', strip=True)
    invalid = _soup(_post(client, '/auth/register', {
        'username': 'valid-localized-name', 'email': 'not-an-email',
        'password': 'password-one', 'password2': 'password-two',
    }, token_path='/auth/register'))
    text = invalid.get_text(' ', strip=True)
    assert invalid_email in text
    assert mismatch in text


def test_anonymous_cookie_resolution_and_session_priority(localized_app):
    client = localized_app.test_client()
    client.set_cookie('anetbbs_language', 'es')
    assert _soup(client.get('/')).html['lang'] == 'es'
    _language(client, 'en')
    assert _soup(client.get('/')).html['lang'] == 'en'
    other = localized_app.test_client()
    other.set_cookie('anetbbs_language', 'unsupported')
    assert _soup(other.get('/')).html['lang'] == 'en'


def test_language_picker_requires_csrf_and_persists_secure_cookie(localized_app, client, monkeypatch):
    rejected = client.post('/language', data={'language': 'es'})
    assert rejected.status_code == 400
    with client.session_transaction() as session:
        assert 'language' not in session
        assert '_user_id' not in session
    monkeypatch.setitem(localized_app.config, 'SESSION_COOKIE_SECURE', True)
    response = _post(client, '/language', {'language': 'es', 'return_to': '/auth/login'})
    assert response.status_code == 302
    assert response.headers['Location'] == '/auth/login'
    cookie = client.get_cookie('anetbbs_language')
    assert cookie.value == 'es'
    assert cookie.max_age == 365 * 24 * 60 * 60
    assert cookie.http_only and cookie.secure and cookie.same_site == 'Lax'
    assert cookie.path == '/' and cookie.expires is not None
    with client.session_transaction() as session:
        assert session['language'] == 'es'
        assert '_user_id' not in session
    # The preference survives losing the login/session cookie.
    client.delete_cookie(localized_app.config['SESSION_COOKIE_NAME'])
    assert _soup(client.get('/auth/login')).html['lang'] == 'es'


def test_language_picker_rejects_unknown_values(client):
    for language in ('de', 'pt', '../es', ''):
        response = _post(client, '/language', {'language': language})
        assert response.status_code == 400
    with client.session_transaction() as session:
        assert 'language' not in session


@pytest.mark.parametrize('target', [
    'https://example.net/evil', '//example.net/evil', '/\\example.net/evil',
    'https://[broken', '/boards/\nLocation: https://example.net',
])
def test_language_picker_refuses_external_or_malformed_redirects(client, target):
    response = _post(client, '/language', {'language': 'es', 'return_to': target})
    assert response.status_code == 302
    assert response.headers['Location'] == '/'


def test_language_picker_preserves_relative_query_and_fragment(client):
    target = '/boards/?search=some%20text&page=2#recent'
    response = _post(client, '/language', {'language': 'es', 'return_to': target})
    assert response.status_code == 302
    assert response.headers['Location'] == target


@pytest.mark.parametrize('preferred,anonymous', [('es', 'en'), ('en', 'es')])
def test_login_account_preference_wins_and_survives_logout(client, make_user, preferred, anonymous):
    user_id, username, _ = make_user(preferred)
    _language(client, anonymous)
    response = _post(client, '/auth/login', {
        'username': username, 'password': 'localization-password',
    }, token_path='/auth/login', follow_redirects=True)
    assert _soup(response).html['lang'] == preferred
    with client.session_transaction() as session:
        assert session['_user_id'] == _auth_identifier(client, user_id)
        assert session['language'] == preferred
    assert client.get_cookie('anetbbs_language').value == preferred
    # An authenticated account also wins over stale browser preferences.
    _language(client, anonymous)
    client.set_cookie('anetbbs_language', anonymous)
    assert _soup(client.get('/')).html['lang'] == preferred
    logged_out = _soup(client.get('/auth/logout', follow_redirects=True))
    assert logged_out.html['lang'] == preferred
    with client.session_transaction() as session:
        assert '_user_id' not in session
        assert session['language'] == preferred
    relogged = _soup(_post(client, '/auth/login', {
        'username': username, 'password': 'localization-password',
    }, token_path='/auth/login', follow_redirects=True))
    assert relogged.html['lang'] == preferred


@pytest.mark.parametrize('language', ['en', 'es'])
def test_registration_inherits_anonymous_preference(localized_app, client, language):
    import uuid
    username = 'registered' + uuid.uuid4().hex[:10]
    _language(client, language)
    response = _post(client, '/auth/register', {
        'username': username, 'email': f'{username}@example.com',
        'password': 'registered-password', 'password2': 'registered-password',
    }, token_path='/auth/register', follow_redirects=True)
    assert _soup(response).html['lang'] == language
    with localized_app.app_context():
        user = User.query.filter_by(username=username).one()
        assert user.language == language
        user_id = user.id
    with client.session_transaction() as session:
        assert session['_user_id'] == _auth_identifier(client, user_id)
        assert session['language'] == language


def test_email_verification_restores_account_language(localized_app, client, make_user):
    user_id, _, _ = make_user('es')
    with localized_app.app_context():
        user = db.session.get(User, user_id)
        user.is_verified = False
        db.session.add(EmailVerifyToken(user_id=user_id, token='spanish-verify-token',
                                       expires_at=datetime.utcnow() + timedelta(hours=1)))
        db.session.commit()
    _language(client, 'en')
    page = _soup(client.get('/auth/verify/spanish-verify-token'))
    assert page.html['lang'] == 'es'
    assert '¡Correo electrónico verificado!' in page.get_text(' ', strip=True)
    with client.session_transaction() as session:
        assert session['language'] == 'es'
        assert session['_user_id'] == _auth_identifier(client, user_id)


@pytest.mark.parametrize('language,new_password,updated', [
    ('en', 'New Password', 'Password updated. You can log in now.'),
    ('es', 'Nueva contraseña', 'Contraseña actualizada. Ya puedes iniciar sesión.'),
])
def test_recovery_reset_form_and_success(localized_app, client, make_user, language,
                                        new_password, updated):
    user_id, _, _ = make_user()
    token = f'localized-reset-{user_id}'
    with localized_app.app_context():
        db.session.add(PasswordResetToken(user_id=user_id, token=token,
                                         expires_at=datetime.utcnow() + timedelta(hours=1)))
        db.session.commit()
    _language(client, language)
    path = '/auth/reset/' + token
    page = _soup(client.get(path))
    assert page.select_one('label[for=password]').get_text(strip=True) == new_password
    result = _soup(_post(client, path, {'password': 'new-password', 'password2': 'new-password'},
                         token_path=path, follow_redirects=True))
    assert updated in result.get_text(' ', strip=True)
    with localized_app.app_context():
        assert db.session.get(User, user_id).check_password('new-password')
        assert PasswordResetToken.query.filter_by(token=token).one().used_at is not None


@pytest.mark.parametrize('language,heading,subject_label,created,replied', [
    ('en', 'Message Boards', 'Subject', 'Post created successfully!', 'Reply posted successfully!'),
    ('es', 'Tablones de mensajes', 'Asunto', '¡Mensaje publicado correctamente!',
     '¡Respuesta publicada correctamente!'),
])
def test_board_list_read_create_and_reply_preserve_content(localized_app, client, make_user,
                                                          language, heading, subject_label,
                                                          created, replied):
    user_id, _, _ = make_user(language)
    _authenticate(client, user_id)
    board_name = f'Local board {user_id} <script>alert("board")</script>'
    with localized_app.app_context():
        board = Board(name=board_name, description='User description <b>verbatim</b>',
                      min_access_level=0)
        db.session.add(board)
        db.session.commit()
        board_id = board.id
    listing = _soup(client.get('/boards/'))
    assert heading in listing.h1.get_text(' ', strip=True)
    assert board_name in listing.get_text(' ', strip=True)
    assert '<script>alert("board")</script>' not in str(listing)
    board_page = _soup(client.get(f'/boards/{board_id}'))
    assert board_name in board_page.get_text(' ', strip=True)
    path = f'/boards/{board_id}/new'
    form = _soup(client.get(path))
    assert form.select_one('label[for=subject]').get_text(strip=True) == subject_label
    invalid = _soup(_post(client, path, {'subject': '', 'content': ''}, token_path=path))
    assert ('Este campo es obligatorio.' if language == 'es' else 'This field is required.') in invalid.get_text()
    subject = 'Original subject <img src=x onerror=alert(1)>'
    content = 'Original message <script>alert("post")</script> & café.'
    page = _soup(_post(client, path, {'subject': subject, 'content': content},
                       token_path=path, follow_redirects=True))
    assert created in page.get_text(' ', strip=True)
    assert subject in page.get_text(' ', strip=True)
    assert '<script>alert("post")</script>' not in str(page)
    assert page.select_one('#postBodyPlain').get_text() == content
    with localized_app.app_context():
        post = Post.query.filter_by(board_id=board_id, parent_id=None).one()
        assert (post.subject, post.content) == (subject, content)
        post_id = post.id
    reply = 'User reply <b>unaltered</b> & español.'
    page = _soup(_post(client, f'/boards/post/{post_id}/reply', {'content': reply},
                       token_path=f'/boards/post/{post_id}', follow_redirects=True))
    assert replied in page.get_text(' ', strip=True)
    assert '<b>unaltered</b>' not in str(page)
    assert reply in [
        body.get_text() for body in page.select('.ansi-body')
    ]
    with localized_app.app_context():
        assert Post.query.filter_by(parent_id=post_id).one().content == reply


@pytest.mark.parametrize('language,inbox,compose,recipient_label,sent,quote', [
    ('en', 'Inbox', 'Compose Message', 'To (username)', 'Message sent!', 'wrote:'),
    ('es', 'Bandeja de entrada', 'Redactar mensaje', 'Para (nombre de usuario)',
     '¡Mensaje enviado!', 'escribió:'),
])
def test_private_message_inbox_read_compose_and_quote_reply(localized_app, client, make_user,
                                                           language, inbox, compose,
                                                           recipient_label, sent, quote):
    user_id, username, _ = make_user(language)
    sender_id, sender, _ = make_user()
    body = 'Original PM <script>alert("pm")</script> & ñáéü.'
    subject = 'User PM <b>subject</b>'
    with localized_app.app_context():
        pm = PrivateMessage(sender_id=sender_id, recipient_id=user_id,
                            subject=subject, body=body)
        db.session.add(pm)
        db.session.commit()
        message_id = pm.id
    _authenticate(client, user_id)
    page = _soup(client.get('/messages/'))
    assert page.h1.get_text(' ', strip=True) == inbox
    assert subject in page.get_text(' ', strip=True)
    assert '<b>subject</b>' not in str(page)
    read = _soup(client.get(f'/messages/{message_id}'))
    assert '<script>alert("pm")</script>' not in str(read)
    # PMs are already decoded Unicode. The read view must keep accents intact
    # rather than interpreting their code points as legacy CP437 bytes.
    assert read.select_one('#bodyPlain').get_text() == body
    with localized_app.app_context():
        stored = db.session.get(PrivateMessage, message_id)
        assert stored.read_at is not None
        assert stored.body == body
    quote_path = f'/messages/compose/{sender}?quote={message_id}'
    form = _soup(client.get(quote_path))
    assert form.h1.get_text(' ', strip=True) == compose
    assert form.select_one('label[for=recipient]').get_text(strip=True) == recipient_label
    assert form.select_one('input[name=recipient]')['value'] == sender
    assert form.select_one('input[name=subject]')['value'] == f'Re: {subject}'
    assert form.select_one('textarea[name=content]').get_text().strip() == f'{sender} {quote}\n> {body}'
    reply = 'Original reply <img src=x onerror=alert(1)> & ñáéü.'
    result = _soup(_post(client, f'/messages/compose/{sender}', {
        'recipient': sender, 'subject': f'Re: {subject}', 'content': reply,
    }, token_path=quote_path, follow_redirects=True))
    assert sent in result.get_text(' ', strip=True)
    with localized_app.app_context():
        pm = PrivateMessage.query.filter_by(sender_id=user_id, recipient_id=sender_id).one()
        assert (pm.subject, pm.body) == (f'Re: {subject}', reply)


@pytest.mark.parametrize('language', ['en', 'es'])
def test_private_message_unicode_preserves_ansi_escaping_and_plain_links(
        localized_app, client, make_user, language):
    recipient_id, _, _ = make_user(language)
    sender_id, _, _ = make_user()
    url = 'https://example.net/image.png'
    body = f'PM \x1b[31mrojo\x1b[0m ñáéü <script>evil</script> {url}'
    with localized_app.app_context():
        message = PrivateMessage(sender_id=sender_id, recipient_id=recipient_id,
                                 subject='ANSI and Unicode', body=body)
        db.session.add(message)
        db.session.commit()
        message_id = message.id
    _authenticate(client, recipient_id)
    page = _soup(client.get(f'/messages/{message_id}'))
    rendered = page.select_one('#bodyPlain')
    assert rendered.get_text() == f'PM rojo ñáéü <script>evil</script> {url}'
    colored = [span for span in rendered.select('span')
               if span.get_text() == 'rojo' and 'color:' in span.get('style', '')]
    assert colored
    assert rendered.select_one('script, img') is None
    assert rendered.select_one('a')['href'] == url
    with localized_app.app_context():
        assert db.session.get(PrivateMessage, message_id).body == body


@pytest.mark.parametrize('initial,target,label,placeholder', [
    ('en', 'es', 'Language', 'Your display name'),
    ('es', 'en', 'Idioma', 'Tu nombre visible'),
])
def test_profile_language_change_updates_account_session_and_cookie(localized_app, client,
                                                                    make_user, initial,
                                                                    target, label, placeholder):
    user_id, username, email = make_user(initial)
    _authenticate(client, user_id)
    page = _soup(client.get('/profile/edit'))
    assert page.select_one('label[for=language]').get_text(strip=True) == label
    assert page.select_one('input[name=display_name]')['placeholder'] == placeholder
    assert {o['value'] for o in page.select('#language option')} == {'en', 'es', 'de', 'pt'}
    result = _soup(_post(client, '/profile/edit', {
        'email': email, 'language': target, 'theme_id': '0',
        'display_name': 'Untranslated <b>name</b>', 'bio': 'User bio <script>example</script>',
    }, token_path='/profile/edit', follow_redirects=True))
    assert result.html['lang'] == target
    assert '<b>name</b>' not in str(result)
    with localized_app.app_context():
        user = db.session.get(User, user_id)
        assert user.language == target
        assert user.display_name == 'Untranslated <b>name</b>'
        assert user.bio == 'User bio <script>example</script>'
    with client.session_transaction() as session:
        assert session['language'] == target
    assert client.get_cookie('anetbbs_language').value == target


def test_profile_preserves_existing_custom_language(localized_app, client, make_user):
    user_id, _, email = make_user('eo')
    _authenticate(client, user_id)
    page = _soup(client.get('/profile/edit'))
    custom = page.select_one('#language option[value=eo]')
    assert custom is not None and custom.has_attr('selected')
    assert page.select_one('#site-language option[value=eo]').has_attr('selected')
    unchanged = _post(client, '/language', {'language': 'eo', 'return_to': '/profile/edit'},
                      token_path='/profile/edit')
    assert unchanged.status_code == 302
    rejected = _post(client, '/language', {'language': 'unknown'}, token_path='/profile/edit')
    assert rejected.status_code == 400
    result = _post(client, '/profile/edit', {'email': email, 'language': 'eo', 'theme_id': '0'},
                   token_path='/profile/edit')
    assert result.status_code == 302
    with localized_app.app_context():
        assert db.session.get(User, user_id).language == 'eo'
    logged_out = _soup(client.get('/auth/logout', follow_redirects=True))
    assert logged_out.select_one('#site-language option[value=eo]').has_attr('selected')
    unchanged = _post(client, '/language', {'language': 'eo'}, token_path='/auth/login')
    assert unchanged.status_code == 302


def test_picker_updates_authenticated_account(localized_app, client, make_user):
    user_id, _, _ = make_user('en')
    _authenticate(client, user_id)
    rejected = client.post('/language', data={'language': 'es'})
    assert rejected.status_code == 400
    with localized_app.app_context():
        assert db.session.get(User, user_id).language == 'en'
    response = _post(client, '/language', {'language': 'es', 'return_to': '/profile/edit'})
    assert response.status_code == 302
    with localized_app.app_context():
        assert db.session.get(User, user_id).language == 'es'
    assert _soup(client.get('/profile/edit')).html['lang'] == 'es'


def test_custom_overrides_are_preserved_escaped_and_fall_back_safely(localized_app, client, make_user):
    from anetbbs.features.i18n import seed_default_translations, translate
    from flask import render_template_string, session

    hostile = '<img src=x onerror="alert(1)">'
    with _overrides(localized_app, **{
        'nav.home': hostile,
        'test.format': 'Incorrect {missing}',
        'test.malformed': 'Incorrect {name',
        'test.position': 'Incorrect {0}',
        'test.attribute': 'Incorrect {name.missing}',
        'test.subscript': 'Incorrect {name[bad]}',
        'test.named': 'Hola {name}',
    }):
        with localized_app.app_context():
            seed_default_translations()
            assert MenuTranslation.query.filter_by(lang='es', key='nav.home').one().text == hostile
        _language(client, 'es')
        page = _soup(client.get('/'))
        assert hostile in [a.get_text(' ', strip=True) for a in page.select('a[href="/"]')]
        assert page.select_one('img[onerror]') is None
        with localized_app.test_request_context('/'):
            session['language'] = 'es'
            for key in ('test.format', 'test.malformed', 'test.position',
                        'test.attribute', 'test.subscript'):
                assert translate(key, 'Hello {name}', name='Ana') == 'Hello Ana'
            assert translate('test.missing', 'First fallback') == 'First fallback'
            assert translate('test.missing', 'Second fallback') == 'Second fallback'
            rendered = render_template_string("{{ t('test.named', 'Hello {name}', name=name) }}",
                                              name=hostile)
            assert BeautifulSoup(rendered, 'html.parser').get_text() == 'Hola ' + hostile
            assert '<img' not in rendered


@pytest.mark.parametrize('language,expected', [('en', 0), ('es', 1)])
def test_translation_catalogue_is_loaded_once_per_request(localized_app, client, language, expected):
    _language(client, language)
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        if 'from menu_translations' in ' '.join(statement.lower().split()):
            statements.append(statement)

    with localized_app.app_context():
        engine = db.engine
        event.listen(engine, 'before_cursor_execute', capture)
    try:
        for path in ('/', '/auth/register'):
            statements.clear()
            assert client.get(path).status_code == 200
            assert len(statements) == expected
    finally:
        event.remove(engine, 'before_cursor_execute', capture)


@pytest.mark.parametrize('override,expected', [
    ('Entre %(minimum)d y %(max)d caracteres.',
     'Field must be between 3 and 80 characters long.'),
    ('Entre %(min)z y %(max)d caracteres.',
     'Field must be between 3 and 80 characters long.'),
    ('Al menos %(min)d caracteres.',
     'Field must be between 3 and 80 characters long.'),
    ('Entre %(min)d y %(max)d caracteres (100%%).',
     'Entre 3 y 80 caracteres (100%).'),
])
def test_validation_override_preserves_percent_markers(localized_app, client, override, expected):
    _language(client, 'es')
    with _overrides(localized_app, **{'validation.length_range': override}):
        page = _soup(_post(client, '/auth/login', {
            'username': 'ab', 'password': 'invalid-form-only',
        }, token_path='/auth/login'))
        assert expected in page.get_text(' ', strip=True)
        assert page.select_one('label[for=password]').get_text(strip=True) == 'Contraseña'


@pytest.mark.parametrize('language,expected', [
    ('en', 'Security questions configured: 1'),
    ('es', 'Preguntas configuradas: 1'),
])
def test_one_security_question_uses_count_neutral_wording(
        localized_app, client, make_user, language, expected):
    from anetbbs.models import SecurityQuestion, UserSecurityAnswer
    user_id, _, _ = make_user(language)
    _authenticate(client, user_id)
    with localized_app.app_context():
        previous = PasswordRecoverySettings.get().security_questions_enabled
        PasswordRecoverySettings.get().security_questions_enabled = True
        question = SecurityQuestion.query.filter_by(is_active=True).first().text
        db.session.add(UserSecurityAnswer(user_id=user_id, question=question,
                                         answer_hash=UserSecurityAnswer.hash_answer('local answer')))
        db.session.commit()
    try:
        page = _soup(client.get('/profile/security-questions'))
        assert expected in page.select_one('.alert-success').get_text(' ', strip=True)
    finally:
        with localized_app.app_context():
            PasswordRecoverySettings.get().security_questions_enabled = previous
            db.session.commit()


@pytest.mark.parametrize('language, headings', [
    ('es', ('Panel de administración', 'Configuración del relé SMTP', 'Actualizaciones de ANetBBS')),
    ('en', ('Admin Dashboard', 'SMTP Relay Settings', 'ANetBBS Upgrades')),
])
def test_admin_dashboard_smtp_and_upgrades_localization(client, make_user, language, headings):
    user_id, _, _ = make_user(language, is_admin=True)
    _authenticate(client, user_id)
    for path, heading in zip(('/admin/', '/admin/smtp', '/admin/upgrades/'), headings):
        page = _soup(client.get(path))
        assert page.h1.get_text(strip=True) == heading
    dashboard = _soup(client.get('/admin/'))
    notes = dashboard.select_one('.markdown-body')
    assert notes is not None
    expected = 'Revocación de sesiones' if language == 'es' else 'Password-change session revocation'
    assert expected in notes.get_text(' ', strip=True)


def test_spanish_admin_settings_mrc_and_forbidden_page(client, make_user):
    admin_id, _, _ = make_user('es', is_admin=True)
    _authenticate(client, admin_id)
    settings = _soup(client.get('/admin/settings'))
    assert 'Nombre de la BBS' in settings.get_text(' ', strip=True)
    board = _soup(client.get('/admin/boards/add'))
    assert board.h1.get_text(strip=True) == 'Añadir tablón'
    assert board.select_one('input[name=submit]')['value'] == 'Guardar tablón'
    mrc = _soup(client.get('/mrc/'))
    assert mrc.html['lang'] == 'es'
    assert mrc.select_one('#join-panel h2').get_text(strip=True) == 'Entrar al chat MRC'

    user_id, _, _ = make_user('es')
    _authenticate(client, user_id)
    denied = client.get('/admin/')
    assert denied.status_code == 403
    assert '403 — Acceso denegado' in BeautifulSoup(denied.data, 'html.parser').h1.get_text(strip=True)


@pytest.mark.parametrize('language, verification, reset', [
    ('es', 'Confirma tu correo electrónico', 'Restablece tu contraseña'),
    ('en', 'Verify your email', 'Password reset'),
])
def test_account_mail_uses_recipient_language_without_a_request(
        localized_app, monkeypatch, language, verification, reset):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from anetbbs import mailer

    send = Mock(return_value=(True, ''))
    monkeypatch.setattr(mailer, 'send_email', send)
    user = SimpleNamespace(username='<Manu>', email='user@example.com', language=language)
    link = 'https://bbs.example.com/auth/link?a=1&b=2'
    with localized_app.app_context():
        assert mailer.send_verification_email(user, link) == (True, '')
        assert mailer.send_password_reset_email(user, link) == (True, '')
    for call, expected in zip(send.call_args_list, (verification, reset)):
        email, subject, plain, html = call.args
        assert email == user.email and subject.startswith(expected)
        assert '<Manu>' in plain and '&lt;Manu&gt;' in html
        assert link in plain and '&amp;b=2' in html


def test_spanish_about_bulletins_files_and_online_pages(client, make_user):
    user_id, _, _ = make_user('es')
    _authenticate(client, user_id)
    for path, heading in {
        '/about': 'Acerca de',
        '/bulletins/': 'Boletines',
        '/files/': 'Galería de archivos',
        '/who/': 'Quién está en línea',
    }.items():
        page = _soup(client.get(path))
        assert heading in page.title.get_text(strip=True)


def test_spanish_prelogin_connection_screen_uses_selected_language(
        client, localized_app, monkeypatch):
    monkeypatch.setitem(localized_app.config, 'WEB_MATRIX_ENABLED', True)
    _language(client, 'es')
    page = _soup(client.get('/'))
    assert page.html['lang'] == 'es'
    assert 'Elige cómo quieres conectarte.' in page.get_text(' ', strip=True)
    assert 'Continuar a la web' in page.get_text(' ', strip=True)


def test_spanish_games_lobby_translates_navigation_and_stock_categories(
        client, localized_app, monkeypatch):
    monkeypatch.setitem(localized_app.config, 'GAMES_ENABLED', True)
    _language(client, 'es')
    page = _soup(client.get('/games/?q=zyx-no-games'))
    assert 'Juegos' in page.title.get_text(strip=True)
    assert page.h1.get_text(strip=True) == 'JUEGOS'
    assert page.select_one('option[value="classic"]').get_text(strip=True) == 'Clásicos de DOS'
    assert 'No se encontraron juegos.' in page.get_text(' ', strip=True)
    scores = _soup(client.get('/games/scores?period=monthly'))
    assert scores.select_one('option[value="all"]').get_text(strip=True) == 'Desde el principio'
    assert scores.select_one('option[value="monthly"]').get_text(strip=True) == 'Este mes'


@pytest.mark.parametrize('language, connecting, launch, close, category', [
    ('es', 'Conectando…', 'Iniciar DOS Fixture', 'Cerrar pestaña y volver', 'Clásicos de DOS'),
    ('en', 'Connecting…', 'Launch DOS Fixture', 'Close Tab & Return', 'Classic DOS'),
])
def test_game_launcher_and_scoreboard_use_account_language(
        client, localized_app, make_user, language, connecting, launch, close, category):
    from anetbbs.models import Game, GameCategory, GameScore

    uid, _, _ = make_user(language)
    _authenticate(client, uid)
    with localized_app.app_context():
        custom = GameCategory(slug='fixture-category-' + language, name='Custom category')
        native = Game(name='Native Fixture', slug='native-fixture-' + language,
                      category=custom.slug, game_type='door_native', web_enabled=True)
        dos = Game(name='DOS Fixture', slug='dos-fixture-' + language, category='classic',
                   game_type='door_dos_browser', web_game_url='/fixture.zip', web_enabled=True)
        db.session.add_all([custom, native, dos])
        db.session.flush()
        db.session.add(GameScore(game_id=dos.id, user_id=uid, score=42))
        db.session.add(GameScore(game_id=native.id, user_id=uid, score=43))
        db.session.commit()

    terminal = _soup(client.get(f'/games/native-fixture-{language}/play'))
    assert terminal.select_one('#conn-status').get_text(strip=True) == connecting
    dos_page = _soup(client.get(f'/games/dos-fixture-{language}/play'))
    assert launch in dos_page.get_text(' ', strip=True)
    dos_frame = _soup(client.get(f'/games/dos-frame/dos-fixture-{language}'))
    assert dos_frame.html['lang'] == language
    assert close in dos_frame.select_one('.exit-btn').get_text(' ', strip=True)
    scores = _soup(client.get('/games/scoreboard'))
    assert category in scores.get_text(' ', strip=True)
    assert 'Custom category' in scores.get_text(' ', strip=True)


def test_public_watch_uses_visitor_language(client, localized_app, monkeypatch):
    monkeypatch.setitem(localized_app.config, 'PUBLIC_WATCH_ENABLED', True)
    _language(client, 'es')
    page = _soup(client.get('/watch/'))
    assert page.html['lang'] == 'es'
    assert 'en directo' in page.h1.get_text(' ', strip=True)
    assert 'Actividad' in page.thead.get_text(' ', strip=True)


def test_spanish_user_tools_render_and_report_validation(client, make_user):
    user_id, _, _ = make_user('es')
    _authenticate(client, user_id)
    pages = {
        '/help': 'Preguntas frecuentes',
        '/tour': 'Visita de bienvenida',
        '/tools/info': 'Información y ayuda',
        '/search?q=texto-sin-resultados-123': 'No se encontraron publicaciones.',
        '/contacts/': 'Libreta de direcciones',
        '/groups/': 'Grupos y clanes',
        '/polls/': 'Encuestas',
        '/notifications/settings': 'Configuración de notificaciones',
    }
    for path, label in pages.items():
        assert label in _soup(client.get(path)).get_text(' ', strip=True), path

    path = '/polls/new'
    response = _post(client, path, {'question': '', 'options': 'Uno\nDos'},
                     token_path=path, follow_redirects=True)
    assert 'Escribe una pregunta para la encuesta.' in _soup(response).get_text(' ', strip=True)


def test_spanish_admin_queue_and_security_render_locally(client, make_user, monkeypatch):
    from anetbbs.web import security_admin

    monkeypatch.setattr(security_admin, '_load_report', lambda: None)
    user_id, _, _ = make_user('es', is_admin=True)
    _authenticate(client, user_id)
    queue = _soup(client.get('/admin/file-queue/?status=rejected'))
    assert 'Cola de moderación de archivos' in queue.h1.get_text(strip=True)
    assert 'No hay entradas con estado «Rechazado».' in queue.get_text(' ', strip=True)
    security = _soup(client.get('/admin/security/'))
    assert 'Actualizaciones de seguridad' in security.h1.get_text(strip=True)
    assert 'Todavía no se ha ejecutado ningún análisis.' in security.get_text(' ', strip=True)
    assert 'Ejecutar análisis' in security.get_text(' ', strip=True)


@pytest.mark.parametrize('language, import_button, missing_list, missing_destination', [
    ('es', 'Importar áreas', 'Pega una lista de áreas de eco',
     'Introduce un nombre y un servidor.'),
    ('en', 'Import Areas', 'Paste an echolist', 'Name + hostname required.'),
])
def test_admin_import_and_dialout_validation_use_account_language(
        client, make_user, language, import_button, missing_list, missing_destination):
    user_id, _, _ = make_user(language, is_admin=True)
    _authenticate(client, user_id)
    import_path = '/admin/file-areas/bulk_import'
    page = _soup(_post(client, import_path, {}, token_path=import_path, follow_redirects=True))
    assert import_button in page.select_one('form[enctype="multipart/form-data"] button[type="submit"]').get_text(' ', strip=True)
    assert missing_list in page.get_text(' ', strip=True)
    dialout_path = '/admin/dialout'
    page = _soup(_post(client, dialout_path, {'action': 'add'}, token_path=dialout_path,
                      follow_redirects=True))
    assert missing_destination in page.get_text(' ', strip=True)


@pytest.mark.parametrize('language, downloads, pages, theme_description, upload_error', [
    ('es', 'Los archivos más recientes aparecen primero.', 'Hasta entonces, los archivos se guardan sin publicarse.',
     'Tema oscuro de alto contraste', 'Selecciona un archivo.'),
    ('en', 'Files are listed newest-first.', 'Until then, files you upload here are saved but not served.',
     'High-contrast dark theme', 'No file selected.'),
])
def test_visitor_downloads_and_account_pages_match_language(
        client, localized_app, make_user, monkeypatch, language, downloads, pages,
        theme_description, upload_error):
    from anetbbs.models import Theme

    for setting, value in {
        'DOWNLOADS_ENABLED': True,
        'DOWNLOADS_REQUIRE_LOGIN': False,
        'FILE_UPLOADS_ENABLED': True,
        'PERSONAL_PAGES_ENABLED': False,
        'PERSONAL_PAGES_STATIC_ORIGIN': '',
    }.items():
        monkeypatch.setitem(localized_app.config, setting, value)
    _language(client, language)
    assert downloads in _soup(client.get('/downloads/')).get_text(' ', strip=True)
    help_page = _soup(client.get('/help'))
    assert help_page.html['lang'] == language
    assert ('Chat MRC' if language == 'es' else 'MRC Chat') in help_page.get_text(' ', strip=True)

    user_id, _, _ = make_user(language)
    _authenticate(client, user_id)
    assert pages in _soup(client.get('/_pages/')).get_text(' ', strip=True)
    assert theme_description in _soup(client.get('/profile/themes')).get_text(' ', strip=True)
    with localized_app.app_context():
        theme = Theme.query.filter_by(name='modern-dark').one()
        original = theme.description
        theme.description = 'Tema de prueba <GKS>'
        db.session.commit()
    try:
        preview = _soup(client.get('/profile/themes'))
        assert 'Tema de prueba <GKS>' in preview.get_text(' ', strip=True)
        assert preview.find('gks') is None
    finally:
        with localized_app.app_context():
            Theme.query.filter_by(name='modern-dark').one().description = original
            db.session.commit()

    upload = '/file-areas/smart-upload'
    response = _post(client, upload, {}, token_path=upload, follow_redirects=True)
    assert upload_error in _soup(response).get_text(' ', strip=True)


def test_personal_pages_translate_confirmation_and_keep_filename(
        client, localized_app, make_user, monkeypatch):
    from io import BytesIO

    monkeypatch.setitem(localized_app.config, 'PERSONAL_PAGES_STATIC_ORIGIN',
                        'https://pages.example.test')
    user_id, _, _ = make_user('es')
    _authenticate(client, user_id)
    response = _post(client, '/_pages/upload',
                     {'file': (BytesIO(b'<p>GKS</p>'), 'index.html')},
                     token_path='/_pages/', follow_redirects=True)
    page = _soup(response)
    button_form = page.select_one('form[action$="/delete/index.html"]')
    assert button_form['data-confirm'] == '¿Eliminar este archivo?'
    assert page.select_one('a[href$="/index.html"]').get_text(strip=True) == 'index.html'


def test_wiki_edit_requirements_and_preview_use_spanish(
        client, localized_app, make_user, monkeypatch):
    user_id, _, _ = make_user('es')
    _authenticate(client, user_id)
    monkeypatch.setitem(localized_app.config, 'WIKI_MIN_POSTS', 2)
    monkeypatch.setitem(localized_app.config, 'WIKI_MIN_DAYS', 1)
    response = _soup(client.get('/wiki/home/edit', follow_redirects=True))
    assert ('Para editar la wiki necesitas al menos 2 publicaciones y una cuenta '
            'con al menos un día de antigüedad.') in response.get_text(' ', strip=True)

    monkeypatch.setitem(localized_app.config, 'WIKI_MIN_POSTS', 0)
    monkeypatch.setitem(localized_app.config, 'WIKI_MIN_DAYS', 0)
    response = _soup(client.get('/wiki/home/edit'))
    assert 'Guía rápida' in response.get_text(' ', strip=True)
    preview_script = next(script for script in response.find_all('script')
                          if 'async function loadPreview()' in script.get_text())
    assert 'No se pudo mostrar la vista previa:' in preview_script.get_text()


@pytest.mark.parametrize('language, inactive, bans, locked, online', [
    ('es', 'Último acceso', 'Intervalo (minutos)', 'Cuenta bloqueada.', 'No hay nadie en línea.'),
    ('en', 'Last login', 'Time window (minutes)', 'User locked.', 'Nobody online.'),
])
def test_daily_admin_labels_and_lock_feedback(
        client, make_user, monkeypatch, language, inactive, bans, locked, online):
    from anetbbs.models import WordFilter
    from anetbbs.web import control

    monkeypatch.setattr(control, 'KNOWN_UNITS', control.KNOWN_UNITS[:1])
    monkeypatch.setattr(control, '_unit_state', lambda unit: {
        'ActiveState': 'active', 'SubState': 'running', 'ActiveEnterTimestamp': '',
        'MainPID': '42', 'LoadState': 'loaded',
    })
    monkeypatch.setattr(control, '_probe_tcp', lambda port: True)
    monkeypatch.setattr(control, '_probe_udp', lambda port: False)
    monkeypatch.setattr(control, '_change_state', lambda unit, action: (True, '', ''))
    admin_id, _, _ = make_user(language, is_admin=True)
    target_id, target_name, _ = make_user(language)
    _authenticate(client, admin_id)
    assert inactive in _soup(client.get('/admin/inactive-users')).get_text(' ', strip=True)
    assert bans in _soup(client.get('/admin/ip-bans')).get_text(' ', strip=True)

    path = '/admin/users'
    response = _post(client, f'{path}/{target_id}/lock', {},
                     token_path=path, follow_redirects=True)
    assert locked in _soup(response).get_text(' ', strip=True)
    with client.application.app_context():
        assert db.session.get(User, target_id).is_locked

    filter_path = '/admin/word-filter'
    _post(client, filter_path, {'action': 'add', 'pattern': target_name},
          token_path=filter_path)
    filters = _soup(client.get(filter_path))
    row = next(row for row in filters.select('tbody tr') if target_name in row.get_text())
    remove = row.select_one('form:has(input[value="delete"])')
    response = _post(client, filter_path, {
        'action': remove.select_one('input[name=action]')['value'],
        'w_id': remove.select_one('input[name=w_id]')['value'],
    }, token_path=filter_path)
    assert response.status_code == 302
    with client.application.app_context():
        assert WordFilter.query.filter_by(pattern=target_name).first() is None

    services = _soup(client.get('/admin/control/'))
    scripts = [tag.get_text() for tag in services.find_all('script')]
    assert any(json.dumps(online) in code for code in scripts)
    restart = services.select_one('form[action$="/anetbbs-web/restart"] button')
    assert restart['data-confirm'] == (
        '¿Reiniciar anetbbs-web?' if language == 'es' else 'Restart anetbbs-web?')
    response = _post(client, '/admin/control/service/anetbbs-web/restart', {},
                     token_path='/admin/control/', follow_redirects=True)
    status = 'Reinicio de anetbbs-web: correcto' if language == 'es' else 'restart anetbbs-web: OK'
    assert status in _soup(response).get_text(' ', strip=True)


@pytest.mark.parametrize('language, brush, unsaved, title_required, invalid_json', [
    ('es', 'Lápiz', 'sin guardar', 'Introduce el nombre interno y el título.',
     'Los parámetros deben tener un formato JSON válido.'),
    ('en', 'Pencil', 'unsaved', 'Name and title are required.',
     'params_json is not valid JSON.'),
])
def test_admin_appearance_editors_and_validation(
        client, make_user, language, brush, unsaved, title_required, invalid_json):
    admin_id, name, _ = make_user(language, is_admin=True)
    _authenticate(client, admin_id)
    art = _soup(_post(client, '/admin/ansi/new', {
        'name': name, 'width': 20, 'height': 5,
    }, token_path='/admin/ansi/new', follow_redirects=True))
    assert art.select_one('[data-tool="pencil"]')['title'] == brush
    assert art.select_one('#saveStatus').get_text(strip=True) == unsaved
    assert [slot['value'] for slot in art.select('select[name=slot] option')] == [
        'welcome', 'goodbye', 'newuser',
    ]

    for path in ('/admin/bbs-menus/new', '/admin/petscii-menus/new'):
        response = _post(client, path, {}, token_path=path, follow_redirects=True)
        assert title_required in _soup(response).get_text(' ', strip=True)

    path = '/admin/login-modules/new'
    response = _post(client, path, {'params_json': '['}, token_path=path,
                     follow_redirects=True)
    module = _soup(response)
    assert invalid_json in module.get_text(' ', strip=True)
    assert [event['value'] for event in module.select('[name=event_type] option')] == [
        'logon', 'logoff',
    ]


def test_spanish_file_area_import_quota_and_tic(client, localized_app, make_user, tmp_path):
    from anetbbs.models import FileArea, FileQuotaTier

    admin_id, _, _ = make_user('es', is_admin=True)
    _authenticate(client, admin_id)
    path = '/admin/file-areas/bulk_import'
    response = _post(client, path, {'echolist': 'GKS_TEST - Archivos de prueba'},
                     token_path=path, follow_redirects=True)
    assert 'Áreas de archivos importadas: 1. Duplicadas omitidas: 0.' in _soup(response).get_text(' ', strip=True)
    tic = _soup(client.get('/admin/tic-log'))
    assert 'Aún no se han recibido archivos TIC.' in tic.get_text(' ', strip=True)
    cleanup = tic.select_one('form[action$="/clear-processed"]')
    assert 'más de {days} días' in cleanup['data-confirm']

    (tmp_path / 'gks.bin').write_bytes(b'GKS')
    with localized_app.app_context():
        area = FileArea.query.filter_by(tag='GKS_TEST').one()
        area.storage_path = str(tmp_path)
        tier = FileQuotaTier(min_access_level=10, daily_quota_bytes=2)
        db.session.add(tier)
        db.session.commit()
        area_id, tier_id = area.id, tier.id
    try:
        user_id, _, _ = make_user('es')
        _authenticate(client, user_id)
        response = client.get(f'/file-areas/{area_id}/gks.bin', follow_redirects=True)
        assert 'Hoy te quedan 2 de 2 bytes.' in _soup(response).get_text(' ', strip=True)
    finally:
        with localized_app.app_context():
            db.session.delete(db.session.get(FileQuotaTier, tier_id))
            db.session.delete(db.session.get(FileArea, area_id))
            db.session.commit()
