"""Regression tests for two timing-oracle gaps found in a security
audit, both in web/auth.py, both the same short-circuited-auth shape
already fixed in login() (see tests/test_login_timing_side_channel.py):

- resend_verification(): `if user and user.check_password(pw) and not
  user.is_verified:` never called check_password() at all when `user`
  was None (nonexistent username/email), responding near-instantly vs.
  a real hash-verification delay for an existing account -- a timing
  side channel for username/email enumeration.
- security_question_verify(): `elif qa is not None and
  qa.check_answer(raw):` never called check_answer() (which wraps
  check_password_hash) for the decoy-question branch (qa is None,
  set up by forgot_password() for a nonexistent account or one with no
  security questions), so that branch was faster than a real qa with a
  wrong answer.

Both fixed by running a real hash verification against the fixed
_DUMMY_PASSWORD_HASH on the "nothing real to check against" path, so
every rejection path pays the same deliberately-slow cost. These tests
verify the MECHANISM (check_password_hash is actually called) rather
than wall-clock timing, matching this project's established pattern
for this exact bug class.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import anetbbs.config as cfg_mod


class ResendVerificationTimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_uri = cfg_mod.TestingConfig.SQLALCHEMY_DATABASE_URI
        cls._tmp_db = str(Path(__file__).resolve().parent
                          / '.resend_verification_timing_test.db')
        if os.path.exists(cls._tmp_db):
            os.remove(cls._tmp_db)
        cfg_mod.TestingConfig.SQLALCHEMY_DATABASE_URI = f'sqlite:///{cls._tmp_db}'
        os.environ['FLASK_ENV'] = 'testing'
        cfg_mod.TestingConfig.WTF_CSRF_ENABLED = False

        from anetbbs.web_app import create_app
        from anetbbs.models import db, User
        cls.app = create_app('testing')
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False
        with cls.app.app_context():
            db.create_all()
            u = User(username='resendtestuser', email='resendtestuser@example.com',
                    is_active=True, is_verified=True)
            u.set_password('correcthorsebatterystaple')
            db.session.add(u)
            db.session.commit()

    @classmethod
    def tearDownClass(cls):
        cfg_mod.TestingConfig.SQLALCHEMY_DATABASE_URI = cls._orig_db_uri
        for suffix in ('', '-wal', '-shm'):
            path = cls._tmp_db + suffix
            if os.path.exists(path):
                os.remove(path)

    def test_nonexistent_identifier_still_calls_check_password_hash(self):
        from anetbbs.web import auth as auth_mod
        client = self.app.test_client()
        with mock.patch.object(auth_mod, 'check_password_hash',
                               wraps=auth_mod.check_password_hash) as spy:
            resp = client.post('/auth/verify/resend', data={
                'identifier': 'this_identifier_does_not_exist_at_all',
                'password': 'whatever',
            })
        self.assertEqual(resp.status_code, 200)
        spy.assert_called_once()
        self.assertEqual(spy.call_args[0][0], auth_mod._DUMMY_PASSWORD_HASH)

    def test_existing_identifier_wrong_password_calls_check_password_hash_once(self):
        """Baseline -- the real-user path pays an equal, single hash
        cost via User.check_password()'s own check_password_hash()
        call."""
        import anetbbs.models as models_mod
        client = self.app.test_client()
        with mock.patch.object(models_mod, 'check_password_hash',
                               wraps=models_mod.check_password_hash) as spy:
            resp = client.post('/auth/verify/resend', data={
                'identifier': 'resendtestuser',
                'password': 'wrong-password',
            })
        self.assertEqual(resp.status_code, 200)
        spy.assert_called_once()

    def test_already_verified_correct_password_still_shows_error(self):
        """Guard against an over-eager fix breaking the existing
        already-verified-account behavior."""
        client = self.app.test_client()
        resp = client.post('/auth/verify/resend', data={
            'identifier': 'resendtestuser',
            'password': 'correcthorsebatterystaple',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Invalid credentials or account already verified.', resp.data)


class SecurityQuestionDecoyTimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_uri = cfg_mod.TestingConfig.SQLALCHEMY_DATABASE_URI
        cls._tmp_db = str(Path(__file__).resolve().parent
                          / '.security_question_decoy_timing_test.db')
        if os.path.exists(cls._tmp_db):
            os.remove(cls._tmp_db)
        cfg_mod.TestingConfig.SQLALCHEMY_DATABASE_URI = f'sqlite:///{cls._tmp_db}'
        os.environ['FLASK_ENV'] = 'testing'
        cfg_mod.TestingConfig.WTF_CSRF_ENABLED = False

        from anetbbs.web_app import create_app
        from anetbbs.models import db, User, UserSecurityAnswer
        cls.app = create_app('testing')
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False
        with cls.app.app_context():
            db.create_all()
            u = User(username='sqtestuser', email='sqtestuser@example.com',
                    is_active=True)
            u.set_password('correcthorsebatterystaple')
            db.session.add(u)
            db.session.commit()
            qa = UserSecurityAnswer(
                user_id=u.id, question='What is your favorite color?',
                answer_hash=UserSecurityAnswer.hash_answer('blue'))
            db.session.add(qa)
            db.session.commit()
            cls.real_qa_id = qa.id
            cls.real_user_id = u.id

    @classmethod
    def tearDownClass(cls):
        cfg_mod.TestingConfig.SQLALCHEMY_DATABASE_URI = cls._orig_db_uri
        for suffix in ('', '-wal', '-shm'):
            path = cls._tmp_db + suffix
            if os.path.exists(path):
                os.remove(path)

    def _set_decoy_session(self, client):
        result = client.post('/auth/forgot', data={'identifier': 'missing-sq-user'})
        self.assertEqual(result.status_code, 302)

    def _set_real_session(self, client):
        result = client.post('/auth/forgot', data={'identifier': 'sqtestuser'})
        self.assertEqual(result.status_code, 302)

    def test_decoy_branch_still_calls_check_password_hash(self):
        from anetbbs.web import auth as auth_mod
        client = self.app.test_client()
        self._set_decoy_session(client)
        with mock.patch.object(auth_mod, 'check_password_hash',
                               wraps=auth_mod.check_password_hash) as spy:
            resp = client.post('/auth/forgot/verify', data={'answer': 'whatever'})
        self.assertEqual(resp.status_code, 200)
        spy.assert_called_once()
        self.assertEqual(spy.call_args[0][0], auth_mod._DUMMY_PASSWORD_HASH)

    def test_real_qa_wrong_answer_calls_check_password_hash_once(self):
        """Baseline -- the real-qa-but-wrong-answer path pays an equal,
        single hash cost via UserSecurityAnswer.check_answer()'s own
        check_password_hash() call."""
        import anetbbs.models as models_mod
        client = self.app.test_client()
        self._set_real_session(client)
        with mock.patch.object(models_mod, 'check_password_hash',
                               wraps=models_mod.check_password_hash) as spy:
            resp = client.post('/auth/forgot/verify', data={'answer': 'wrong-answer'})
        self.assertEqual(resp.status_code, 200)
        spy.assert_called_once()

    def test_real_qa_correct_answer_still_works(self):
        """Guard against an over-eager fix breaking the happy path."""
        client = self.app.test_client()
        self._set_real_session(client)
        resp = client.post('/auth/forgot/verify', data={'answer': 'Blue'},
                           follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/auth/reset/', resp.headers['Location'])


if __name__ == '__main__':
    unittest.main()
