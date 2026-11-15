from datetime import datetime, timedelta

import pytest


@pytest.fixture
def app(monkeypatch, tmp_path):
    from anetbbs.config import TestingConfig
    from anetbbs.models import db
    from anetbbs.web_app import create_app

    monkeypatch.setattr(TestingConfig, 'DATA_DIR', str(tmp_path))
    monkeypatch.setattr(TestingConfig, 'PUBLIC_BASE_URL', 'https://bbs.example.com')
    monkeypatch.setattr(TestingConfig, 'SQLALCHEMY_DATABASE_URI', 'sqlite:///:memory:')
    app = create_app('testing')
    yield app
    with app.app_context():
        db.engine.dispose()


def test_recovery_uses_canonical_origin(app):
    from anetbbs.web.auth import _password_recovery_origin

    with app.test_request_context(base_url='http://localhost:5000'):
        assert _password_recovery_origin() == 'https://bbs.example.com'
    assert app.test_client().get('/auth/forgot', base_url='https://bbs.example.com').status_code == 200


def test_password_change_revokes_tokens_and_open_terminal(app):
    from anetbbs.models import db, PasswordResetToken, User, UserSession
    from anetbbs.web.web_terminal import _TermSession
    from anetbbs.web_app import login_manager

    with app.app_context():
        user = User(username='Alice', email='alice@example.com')
        user.set_password('original password')
        db.session.add(user)
        db.session.flush()
        token = PasswordResetToken(user_id=user.id, token='existing-token',
                                   expires_at=datetime.utcnow() + timedelta(hours=1))
        presence = UserSession(user_id=user.id, session_key='existing-session')
        db.session.add_all([token, presence])
        db.session.commit()

        old_login_id = user.get_id()
        term = _TermSession('example', 'localhost', 2233, app=app, user_id=user.id,
                            auth_version=user.auth_version, presence_id=presence.id,
                            presence_key=presence.session_key)
        assert term.authorized()
        assert login_manager._user_callback(old_login_id) is user

        user.set_password('new password')
        db.session.commit()
        assert not token.is_valid
        assert not term.authorized()
        assert login_manager._user_callback(old_login_id) is None
        assert login_manager._user_callback(user.get_id()) is user


def test_newer_recovery_token_supersedes_earlier_request(app):
    from anetbbs.models import db, PasswordResetToken, User
    from anetbbs.web.auth import _issue_reset_token

    with app.test_request_context():
        user = User(username='Bob', email='bob@example.com')
        user.set_password('original password')
        db.session.add(user)
        db.session.commit()
        older = _issue_reset_token(user)
        newer = _issue_reset_token(user)

        assert not PasswordResetToken.query.filter_by(token=older).one().is_valid
        assert PasswordResetToken.query.filter_by(token=newer).one().is_valid


def test_signup_reservations_share_quota_across_clients(app):
    from anetbbs.core.registration import reserve_registration_attempt

    with app.app_context():
        ip = '203.0.113.4'
        assert reserve_registration_attempt(ip, 'Alice', 'Browser') is not None
        assert reserve_registration_attempt(ip, 'Bob', 'Terminal') is not None
        assert reserve_registration_attempt(ip, 'Carol', 'Browser') is not None
        assert reserve_registration_attempt(ip, 'Dave', 'Terminal') is None
