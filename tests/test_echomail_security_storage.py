"""Integration checks for durable mail quotas and legacy log redaction."""

import time
from contextlib import contextmanager

from flask import Flask

from anetbbs.echomail.binkp_server import _verify_peer_credentials
from anetbbs.echomail.transcript import redact_stored_transcripts
from anetbbs.models import EchomailNetwork, EchomailPollLog, ServiceRateBucket, db
from anetbbs.web import qwk_hub


@contextmanager
def _app(db_path):
    app = Flask(__name__)
    app.config.update(
        TESTING=True, SQLALCHEMY_DATABASE_URI=f'sqlite:///{db_path.as_posix()}',
        REGISTRY_MODE_ENABLED=True,
    )
    db.init_app(app)
    app.register_blueprint(qwk_hub.qwk_hub_bp)
    with app.app_context():
        db.create_all()
    try:
        yield app
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()


def test_binkp_source_allowance_survives_new_app(tmp_path):
    db_path = tmp_path / 'bbs.db'
    source = '192.0.2.10'
    with _app(db_path) as app, app.app_context():
        db.session.add(ServiceRateBucket(
            key=f'binkp:source:{source}', hits=6, expires_at=int(time.time()) + 240))
        db.session.commit()

    with _app(db_path) as app, app.app_context():
        secret = 'mock-peer-password'
        assert not _verify_peer_credentials(source, 'network:1', secret, secret, b'challenge')
        assert _verify_peer_credentials('192.0.2.11', 'network:1', secret, secret, b'challenge')


def test_qwk_application_quota_is_shared_by_workers(tmp_path, monkeypatch):
    monkeypatch.setattr(qwk_hub, '_rate_limit_check', lambda *args, **kwargs: True)
    monkeypatch.setattr('anetbbs.features.notify.notify_admins', lambda *args, **kwargs: None)
    db_path = tmp_path / 'bbs.db'
    with _app(db_path) as app:
        client = app.test_client()
        for number in range(4):
            result = client.post('/qwkhub/apply', json={
                'bbs_name': f'Test BBS {number}', 'packet_id': f'NODE{number}',
            })
            assert result.status_code == 200

    with _app(db_path) as app:
        client = app.test_client()
        result = client.post('/qwkhub/apply', json={
            'bbs_name': 'Another test BBS', 'packet_id': 'NODE4',
        })
        assert result.status_code == 429


def test_legacy_database_scrub_preserves_diagnostics_and_is_idempotent(tmp_path):
    with _app(tmp_path / 'bbs.db') as app, app.app_context():
        network = EchomailNetwork(name='Test network', network_type='binkp')
        db.session.add(network)
        db.session.flush()
        log = EchomailPollLog(
            network_id=network.id, status='success',
            transcript='11:22:33.123 << CMD PWD: example-only\n'
                       'example-continuation\n'
                       '11:22:33.124 >> CMD OK: secure',
        )
        db.session.add(log)
        db.session.commit()
        log_id = log.id
        db.session.remove()

        assert redact_stored_transcripts(db.engine) == 1
        assert redact_stored_transcripts(db.engine) == 0
        row = db.session.get(EchomailPollLog, log_id)
        assert row.status == 'success'
        assert row.transcript == ('11:22:33.123 << CMD PWD: [redacted]\n'
                                  '11:22:33.124 >> CMD OK: secure')
