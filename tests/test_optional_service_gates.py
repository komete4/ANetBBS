"""Deployment switches reject direct requests and omit socket namespaces."""
import pytest


@pytest.mark.parametrize('enabled', [True, False])
def test_optional_service_gates(tmp_path, monkeypatch, enabled):
    from flask import url_for

    from anetbbs.config import TestingConfig
    from anetbbs.models import db
    from anetbbs.web_app import create_app, socketio

    monkeypatch.setattr(TestingConfig, 'SQLALCHEMY_DATABASE_URI', f'sqlite:///{tmp_path / "bbs.db"}')
    monkeypatch.setattr(TestingConfig, 'DATA_DIR', str(tmp_path))
    for flag in ('WEB_TERMINAL_ENABLED', 'EBOOKS_ENABLED', 'RSS_ENABLED', 'GAMES_ENABLED'):
        monkeypatch.setattr(TestingConfig, flag, enabled)

    app = create_app('testing')
    try:
        client = app.test_client()
        for path in ('/terminal/', '/games/ebooks/classics', '/rss/', '/admin/rss/',
                     '/games/meadowlark/saves', '/games/darkforces/saves',
                     '/admin/games/', '/admin/games-interbbs/', '/admin/door-networks/',
                     '/admin/door-errors/', '/admin/mud/'):
            assert client.get(path).status_code == (302 if enabled else 403), path
        assert client.get('/games/').status_code == (200 if enabled else 403)
        assert client.get('/r/987654321').status_code == (404 if enabled else 403)
        with app.test_request_context():
            assert url_for('web_terminal.index') == '/terminal/'
            assert url_for('rss.index') == '/rss/'

        handlers = socketio.server.handlers
        for namespace in ('/term', '/game', '/mlv-coop'):
            assert (namespace in handlers) == enabled
        assert '/irc' in handlers
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
