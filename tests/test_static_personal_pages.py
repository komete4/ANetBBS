import io
import tempfile
import unittest
from pathlib import Path

from flask import Flask, request
from flask_login import LoginManager, UserMixin
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader

from anetbbs.features.i18n import translate
from anetbbs.web.personal_pages import pages_bp, serve_root_page


class PageOwner(UserMixin):
    def __init__(self, user_id):
        self.id = user_id
        self.username = f'page-owner-{user_id}'


class StaticPersonalPagesTests(unittest.TestCase):
    def setUp(self):
        storage = tempfile.TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        self.data = Path(storage.name)
        self.static_files = self.data / 'personal_pages_public' / 'users'
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY='unit-test-key',
            DATA_DIR=str(self.data),
            PUBLIC_BASE_URL='https://bbs.example.test',
            PERSONAL_PAGES_ENABLED=True,
            PERSONAL_PAGES_PUBLISHING_ENABLED=True,
            PERSONAL_PAGES_STATIC_ORIGIN='http://127.0.0.1:8080',
        )
        self.app.jinja_loader = ChoiceLoader([
            DictLoader({'base.html': '{% block content %}{% endblock %}'}),
            FileSystemLoader(Path(__file__).resolve().parents[1] / 'anetbbs' / 'templates'),
        ])
        self.app.jinja_env.globals.update(csrf_token=lambda: 'unused-test-token', t=translate)
        login = LoginManager(self.app)
        login.user_loader(PageOwner)
        self.app.register_blueprint(pages_bp)

        @self.app.errorhandler(404)
        def legacy_fallback(_):
            return serve_root_page(request.path.lstrip('/')) or ('not found', 404)

    def client_for(self, user_id):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(user_id)
        return client

    def upload(self, client, filename, body):
        response = client.post('/_pages/upload', data={'file': (io.BytesIO(body), filename)})
        self.assertEqual(response.status_code, 302)

    def test_normal_accounts_manage_only_their_own_html_and_css(self):
        first = self.client_for(1)
        second = self.client_for(2)
        self.upload(first, 'index.html', '<h1>La página de Ana</h1>'.encode())
        self.upload(first, 'main.css', b'h1 { color: green; }')
        self.upload(first, 'notes.txt', b'ordinary text')
        self.assertEqual(sorted(p.name for p in (self.static_files / '1').iterdir()),
                         ['index.html', 'main.css'])
        self.assertIn(b'http://127.0.0.1:8080/users/1/main.css', first.get('/_pages/').data)
        self.assertNotIn(b'main.css', second.get('/_pages/').data)
        self.assertEqual(second.post('/_pages/delete/main.css').status_code, 404)
        self.upload(second, 'index.html', b'<h1>La pagina de Luis</h1>')
        self.assertIn('Ana', (self.static_files / '1' / 'index.html').read_text(encoding='utf-8'))
        self.assertIn('Luis', (self.static_files / '2' / 'index.html').read_text(encoding='utf-8'))
        self.assertEqual(first.post('/_pages/delete/main.css').status_code, 302)
        self.assertFalse((self.static_files / '1' / 'main.css').exists())

    def test_static_mode_turns_off_the_legacy_route(self):
        legacy = self.data / 'personal_pages' / 'users' / 'page-owner-1' / 'index.html'
        legacy.parent.mkdir(parents=True)
        legacy.write_text('<h1>Legacy page</h1>', encoding='utf-8')
        self.assertEqual(self.app.test_client().get('/~page-owner-1/index.html').status_code, 404)
        self.app.config['PERSONAL_PAGES_STATIC_ORIGIN'] = 'https://bbs.example.test'
        self.assertEqual(self.client_for(1).get('/_pages/').status_code, 503)
        self.assertEqual(self.app.test_client().get('/~page-owner-1/index.html').status_code, 404)


if __name__ == '__main__':
    unittest.main()
