"""ANetBBS FTP server.

Maps each `FileArea` row onto a subdirectory under a single symlink-tree
root. Anonymous users see only public areas (active + not sysop-only);
authenticated users see all permitted areas and can upload to those whose
`upload_permission` allows it. Uploaded files get a `FileUpload` row
recorded so the web UI's file-area browser surfaces them too — which is
what gets you the FTN nodelist `IFC` flag (Internet File transfer
Capability) once you start advertising the service.

Auth uses the existing `User.check_password` (bcrypt) so the FTP login is
the same as the web/telnet/SSH login. Optional FTPS (AUTH TLS) reuses
whatever cert nginx already has, keyed off `FTP_TLS_CERTFILE` /
`FTP_TLS_KEYFILE` in the app config.

This module is `serve_forever`-style, intended to run inside the main
`anetbbs.service` process — the entry point `run()` is started in a
daemon thread by `anetbbs.main` when `FTP_ENABLED=true`.
"""
import errno
import hmac
import logging
import os
import shutil
import time
from urllib.parse import quote
from uuid import uuid4

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import DTPHandler, FTPHandler

from ..features.access_control import evaluate_access
from ..features.file_publish import (UploadRejected, check_staged_upload,
                                     file_identity, is_staging_path,
                                     open_staged_upload)

logger = logging.getLogger(__name__)


def _check_ip_and_rate_limit(app, ip):
    """Return True if this IP must be blocked from even attempting a
    password check (already banned, or just tripped the rate limit and
    got auto-banned here). Mirrors core/user_manager.py's
    UserManager._check_ip_and_rate_limit() -- same AutoBanConfig/IpBan/
    IpWhitelist models and policy, kept as its own local copy (own
    'ftp_login:<ip>' rate-limit bucket, separate from 'login' (web) and
    'terminal_login:<ip>' (telnet/SSH/rlogin)) rather than importing
    across package boundaries. Fails open on any infrastructure error,
    same posture as every other caller of these models.
    """
    if not ip:
        return False
    import ipaddress as _ipa
    from datetime import datetime, timedelta
    from ..models import db, IpBan, IpWhitelist, AutoBanConfig
    from ..features.rate_limit import _check as _rl_check

    def _cidr_match(ip_str, cidr_list):
        try:
            addr = _ipa.ip_address(ip_str)
        except ValueError:
            return False
        for entry in cidr_list:
            try:
                if addr in _ipa.ip_network(entry, strict=False):
                    return True
            except ValueError:
                if entry == ip_str:
                    return True
        return False

    try:
        with app.app_context():
            whitelisted_cidrs = [r.cidr for r in
                                 IpWhitelist.query.with_entities(IpWhitelist.cidr).all()]
            if _cidr_match(ip, whitelisted_cidrs):
                return False

            now = datetime.utcnow()
            banned_cidrs = [r.cidr for r in IpBan.query.all()
                            if not (r.expires_at and r.expires_at < now)]
            if _cidr_match(ip, banned_cidrs):
                return True

            cfg = AutoBanConfig.get()
            if not cfg.enabled:
                return False
            if _rl_check(f'ftp_login:{ip}', cfg.attempt_limit, cfg.window_seconds):
                return False

            if IpBan.query.filter_by(cidr=ip).first():
                return True
            expires_at = (now + timedelta(hours=cfg.ban_duration_hours)
                         if cfg.ban_duration_hours else None)
            db.session.add(IpBan(
                cidr=ip, banned_by_id=None, expires_at=expires_at,
                reason=f'Auto-ban: FTP login rate limit exceeded '
                       f'({cfg.attempt_limit} attempts / '
                       f'{cfg.window_seconds // 60 or 1} min)'))
            db.session.commit()
            return True
    except Exception:
        logger.exception('FTP: IP ban/rate-limit check failed for %s', ip)
        return False


def _can_read_area(user, area):
    return area.is_active and evaluate_access(
        user, area.min_access_level, is_sysop_only=area.is_sysop_only)


class SymlinkAwareFS(AbstractedFS):
    """Allow only mapped area symlinks and paths inside their current target."""

    def validpath(self, path):
        if is_staging_path(path) or is_staging_path(os.path.realpath(path)):
            return False
        handler = self.cmd_channel
        if handler._qwk_node_id is not None:
            return super().validpath(path)
        if os.path.abspath(path) == os.path.abspath(self.root):
            return True
        return handler._area_access(path) is not None

    def listdir(self, path):
        names = super().listdir(path)
        if self.cmd_channel._qwk_node_id is not None:
            return [name for name in names if not is_staging_path(name)]
        if os.path.abspath(path) == os.path.abspath(self.root):
            return self.cmd_channel._visible_area_names(names)
        area_name = os.path.relpath(path, self.root).split(os.sep, 1)[0]
        storage = os.path.realpath(os.path.join(self.root, area_name))
        return [name for name in names
                if not name.startswith('.')
                and _in_area(storage, os.path.join(path, name))]

    def lstat(self, path):
        # The authorized area root should appear as a directory in LIST.
        return os.stat(path)


def _build_symlink_tree(root_dir, areas, mode='user'):
    """Return an explicit mapping of each new symlink to its file area ID."""
    os.makedirs(root_dir, exist_ok=True)
    for name in os.listdir(root_dir):
        full = os.path.join(root_dir, name)
        if os.path.islink(full):
            try:
                os.unlink(full)
            except OSError as exc:
                logger.warning('FTP: cannot remove stale link %s: %s', full, exc)
    mapping = {}
    for area in areas:
        if not area.is_active:
            continue
        if mode == 'anon' and not _can_read_area(None, area):
            continue
        if mode == 'user' and area.is_sysop_only:
            continue
        if not area.storage_path or not os.path.isdir(area.storage_path):
            continue
        # The ID keeps case-insensitive filesystems and escaped tags unambiguous.
        link_name = f'{area.id}-{quote(area.tag, safe=".-_")}'
        link_path = os.path.join(root_dir, link_name)
        try:
            os.symlink(os.path.abspath(area.storage_path), link_path,
                       target_is_directory=True)
        except OSError as exc:
            logger.warning('FTP: could not create area link %s: %s', link_path, exc)
        else:
            mapping[link_name] = area.id
    return mapping


def _in_area(storage, path):
    target = os.path.realpath(path)
    try:
        return (os.path.commonpath((storage, target)) == storage
                and not is_staging_path(target))
    except ValueError:
        return False


class AnetbbsAuthorizer(DummyAuthorizer):
    """Authorizer backed by the User table *and* the QWKNode table.

    BBS users authenticate as before.  QWK nodes (packet_id / password)
    get a per-node home dir under `<data_dir>/qwk-hub/<PACKET_ID>/` where
    they can download their ANET.qwk and upload their <ID>.rep.
    """

    def __init__(self, app, anon_root, user_root, admin_root,
                 anon_enabled=True, qwk_root='', area_roots=None):
        super().__init__()
        self.app = app
        self.anon_root = anon_root
        self.user_root = user_root
        self.admin_root = admin_root
        self.qwk_root = qwk_root  # data/qwk-hub
        self.area_roots = area_roots or {}
        self.upload_day = None
        self.upload_bytes_by_account = {}
        if anon_enabled:
            # pyftpdlib quirk: the anonymous user is registered as
            # username 'anonymous' with an empty password.
            self.add_anonymous(homedir=anon_root, perm='elr')

    def validate_authentication(self, username, password, handler):
        # Real crash found live: pyftpdlib's ftp_USER stores self.username
        # verbatim from the wire (`self.username = line`, no case
        # normalization at all) -- but this method used to register the
        # DummyAuthorizer's user_table entry under a DIFFERENT case
        # (user.username, the DB's canonical stored case; or
        # node.packet_id.upper() for QWK nodes) than whatever case the
        # client actually typed. The DB lookups above are case-insensitive
        # (ilike), so a client typing "gatekeeper" against a DB/packet_id
        # of "GateKeeper"/"GATEKEEPER" authenticated fine here, but the
        # later get_home_dir(self.username) call -- keyed by the RAW
        # wire username, a plain dict lookup, case-sensitive -- raised an
        # unhandled KeyError and crashed the whole FTP session. Always
        # register under the exact `username` parameter (what the client
        # actually sent), never a normalized/canonical form, so the two
        # lookups always agree regardless of what case anyone typed.
        # Anonymous and QWK credentials cannot inherit a human session.
        handler._bbs_auth = None
        handler._qwk_node_id = None
        handler._qwk_packet_id = None
        if username == 'anonymous':
            return super().validate_authentication(username, password, handler)

        # Brute-force protection -- FTP had zero rate-limiting/lockout,
        # unlike web (AutoBanConfig/IpBan) and terminal (same models via
        # UserManager._check_ip_and_rate_limit). Checked before any DB
        # lookup so a banned/rate-limited IP can't even probe usernames.
        remote_ip = getattr(handler, 'remote_ip', None)
        if _check_ip_and_rate_limit(self.app, remote_ip):
            raise AuthenticationFailed('Too many attempts. Try again later.')

        from sqlalchemy import func
        from ..models import User, QWKNode
        with self.app.app_context():
            # 1. Try BBS user.
            user = User.query.filter(
                func.lower(User.username) == username.lower(),
                User.is_active.is_(True),
            ).first()
            if user is not None and user.check_password(password):
                # Same account-standing gates as web/auth.py's login() and
                # core/user_manager.py's authenticate() -- FTP previously
                # only checked is_active, so a locked-out or not-yet-
                # verified (NUV) account could still fully authenticate
                # and read/write every non-sysop file area over FTP.
                if getattr(user, 'is_locked', False):
                    raise AuthenticationFailed('This account is locked.')
                if not getattr(user, 'is_verified', True) and not user.is_admin:
                    raise AuthenticationFailed('Account awaiting verification/approval.')
                home = self.admin_root if user.is_admin else self.user_root
                if not self.app.config.get('FILE_UPLOADS_ENABLED', True):
                    perm = 'elr'
                else:
                    perm = 'elrdfmwMT' if user.is_admin else 'elrdfmw'
                if self.has_user(username):
                    self.remove_user(username)
                self.add_user(username, password=password,
                              homedir=home, perm=perm)
                handler._bbs_auth = (user.id, user.auth_version)
                return

            # 2. Try QWK node (packet_id as username, plaintext password).
            # hmac.compare_digest instead of `==` -- constant-time, avoids
            # a (low-value but real) timing side channel on the stored
            # plaintext secret. Storage itself stays plaintext by design,
            # same as BinkPNode.password: both are shared secrets the
            # server must read back verbatim (QWK/BinkP session auth,
            # AreaFix passthrough), not hashable login credentials.
            node = (QWKNode.query
                    .filter_by(is_active=True)
                    .filter(func.lower(QWKNode.packet_id) == username.lower())
                    .first())
            if node is not None and hmac.compare_digest(node.password, password):
                # self.qwk_root is ALREADY <DATA_DIR>/qwk-hub (set at
                # construction, see run() below) -- do NOT pass it to
                # ensure_node_dir(), which appends its own 'qwk-hub'
                # segment and expects the bare DATA_DIR instead. Doing
                # so here doubled the path (.../qwk-hub/qwk-hub/<ID>),
                # landing the FTP session's home dir one level away
                # from where on_login()'s generate_node_packet() (which
                # correctly receives the bare DATA_DIR) actually writes
                # the packet -- the client always saw an empty
                # directory no matter how successfully login went.
                # (node.packet_id.upper() below is the QWK packet-naming
                # convention -- unrelated to the FTP user_table key, which
                # must stay the raw `username` per the note above.)
                node_home = os.path.join(self.qwk_root, node.packet_id.upper())
                os.makedirs(node_home, exist_ok=True)
                handler._qwk_node_id = node.id
                handler._qwk_packet_id = node.packet_id.upper()
                if self.has_user(username):
                    self.remove_user(username)
                self.add_user(username, password=password,
                              homedir=node_home, perm='elrdfmw')
                return

            raise AuthenticationFailed('Invalid credentials.')

    def get_home_dir(self, username):
        # DummyAuthorizer raises KeyError on unknown users — for real users
        # that haven't yet been cached this is fine because validate_*
        # registers them before this is called (under the exact same
        # username key -- see validate_authentication's comment above).
        return super().get_home_dir(username)


class _BoundedUpload:
    def __init__(self, handler, staged, path, dest, access, replace, max_bytes):
        self.handler = handler
        self.staged = staged
        self.name = staged.name
        self.path = path
        self.dest = dest
        self.access = access
        self.auth = handler._bbs_auth
        self.replace = replace
        self.max_bytes = max_bytes
        self.bytes_written = 0
        self.published = False

    @property
    def closed(self):
        return self.staged.closed

    def close(self):
        self.staged.close()

    def write(self, data):
        if self.bytes_written + len(data) > self.max_bytes:
            raise OSError(errno.EFBIG, 'FTP upload limit exceeded')
        reserve = self.handler.app.config.get('FTP_MIN_FREE_BYTES', 64 * 1024 * 1024)
        if shutil.disk_usage(os.path.dirname(self.dest)).free < reserve + len(data):
            raise OSError(errno.ENOSPC, 'FTP storage reserve reached')
        self.handler._consume_upload_quota(self.access, len(data))
        written = self.staged.write(data)
        self.bytes_written += written
        self.handler._upload_bytes += written
        return written


class _PublishBeforeReply:
    def close(self):
        upload = self.file_obj
        if (not self._closed and self.receive and self.transfer_finished
                and isinstance(upload, _BoundedUpload)):
            try:
                upload.close()
                if not upload.published:
                    self.cmd_channel._publish_upload(upload)
                    upload.published = True
            except FileExistsError:
                self.transfer_finished = False
                self._resp = ('550 A file with that name already exists.', logger.info)
            except UploadRejected as exc:
                self.transfer_finished = False
                self._resp = (f'550 Upload rejected: {exc}', logger.info)
            except Exception:
                logger.exception('FTP: could not publish staged upload')
                self.transfer_finished = False
                self._resp = ('451 Could not publish upload.', logger.warning)
        return super().close()


class _AnetbbsDTPHandler(_PublishBeforeReply, DTPHandler):
    pass


class AnetbbsFTPHandler(FTPHandler):
    """Authorize file-area access, track published uploads and provide QWK FTP."""

    # Wired by `run()` at startup.
    app = None
    dtp_handler = _AnetbbsDTPHandler

    # Set by the authorizer during validate_authentication for QWK sessions.
    _qwk_node_id = None
    _qwk_packet_id = None
    _bbs_auth = None
    _bbs_transfer_auth = None
    _auth_recheck = None
    _staged_upload = None
    _upload_bytes = 0

    def _cancel_auth_recheck(self):
        if self._auth_recheck is not None:
            self._auth_recheck.cancel()
            self._auth_recheck = None

    def _recheck_auth(self):
        """Revoke human logins and their data channels after password change."""
        if self._closed:
            self._cancel_auth_recheck()
            return False
        transfer = self._bbs_transfer_auth
        if transfer is not None and (
                self.data_channel is not transfer[0] or transfer[0]._closed):
            self._bbs_transfer_auth = None
            transfer = None
        bindings = [self._bbs_auth] if self._bbs_auth is not None else []
        if transfer is not None:
            bindings.append(transfer[1])
        if not bindings:
            self._cancel_auth_recheck()
            return True
        try:
            from ..models import User, db
            with self.app.app_context():
                for user_id, version in bindings:
                    user = db.session.get(User, user_id, populate_existing=True)
                    if user is None or user.auth_version != version:
                        self.close()
                        return False
        except Exception:
            logger.exception('FTP: authentication recheck failed; closing session')
            self.close()
            return False
        return True

    def pre_process_command(self, line, cmd, arg):
        if not self._recheck_auth():
            return
        return super().pre_process_command(line, cmd, arg)

    def on_logout(self, username):
        # USER/REIN/QUIT may leave an active transfer running. Keep that
        # channel's original generation until it ends, including a later
        # login as an anonymous/QWK/different human account.
        if self._bbs_auth is not None and self.data_channel is not None:
            if (self._bbs_transfer_auth is None
                    or self._bbs_transfer_auth[0] is not self.data_channel):
                self._bbs_transfer_auth = (self.data_channel, self._bbs_auth)
        self._bbs_auth = None
        if self._bbs_transfer_auth is None:
            self._cancel_auth_recheck()

    def on_disconnect(self):
        self._cancel_auth_recheck()
        self._bbs_auth = None
        self._bbs_transfer_auth = None

    def on_connect(self):
        logger.info('FTP: connect from %s', self.remote_ip)

    def on_login(self, username):
        logger.info('FTP: login %s from %s', username, self.remote_ip)
        if ((self._bbs_auth is not None or self._bbs_transfer_auth is not None)
                and self._auth_recheck is None):
            self._auth_recheck = self.ioloop.call_every(5, self._recheck_auth)
        if self._qwk_node_id is None or self.app is None:
            return
        # QWK node logged in — generate their packet now so it's ready for RETR.
        try:
            with self.app.app_context():
                from ..models import QWKNode
                from ..echomail.qwk_hub_ftp import generate_node_packet, resolve_hub_id
                node = QWKNode.query.get(self._qwk_node_id)
                if node:
                    cfg = self.app.config
                    data_dir = cfg.get('DATA_DIR', 'data')
                    hub_id = resolve_hub_id(node)
                    generate_node_packet(node, data_dir, hub_id)
        except Exception:
            logger.exception('FTP: QWK packet generation failed for %s',
                             self._qwk_packet_id)

    def on_login_failed(self, username, password):
        logger.info('FTP: login failed for %r from %s',
                    username, self.remote_ip)

    def _current_bbs_user(self):
        from ..models import db, User

        if self._bbs_auth is None:
            return None
        user_id, auth_version = self._bbs_auth
        user = db.session.get(User, user_id, populate_existing=True)
        if (user is None or user.auth_version != auth_version
                or not user.is_active or user.is_locked
                or not (user.is_verified or user.is_admin)):
            return None
        return user

    def _area_mapping(self):
        return self.authorizer.area_roots.get(os.path.abspath(self.fs.root), {})

    def _visible_area_names(self, names):
        from ..models import FileArea

        mapping = self._area_mapping()
        with self.app.app_context():
            user = self._current_bbs_user()
            if user is None and self.username != 'anonymous':
                return []
            areas = {area.id: area for area in FileArea.query.filter(
                FileArea.id.in_(mapping.values())).all() if _can_read_area(user, area)}
            return [name for name in names if mapping.get(name) in areas
                    and self._area_path_matches(areas[mapping[name]], name,
                                                os.path.join(self.fs.root, name))]

    def _area_path_matches(self, area, name, path):
        if not area.storage_path:
            return False
        storage = os.path.realpath(area.storage_path)
        link = os.path.join(self.fs.root, name)
        return (os.path.islink(link) and os.path.realpath(link) == storage
                and _in_area(storage, path))

    def _area_access(self, path, *, write=False, mutate=False):
        from ..models import db, FileArea

        try:
            relative = os.path.relpath(path, self.fs.root)
            name, _, member = relative.partition(os.sep)
            if relative in ('.', '..') or name == '..':
                return None
            if any(part.startswith('.') for part in member.split(os.sep)):
                return None
            area_id = self._area_mapping().get(name)
            if area_id is None:
                return None
            with self.app.app_context():
                user = self._current_bbs_user()
                if user is None and self.username != 'anonymous':
                    return None
                area = db.session.get(FileArea, area_id)
                if (area is None or not _can_read_area(user, area)
                        or not self._area_path_matches(area, name, path)):
                    return None
                if write:
                    if not self.app.config.get('FILE_UPLOADS_ENABLED', True):
                        return None
                    permission = (area.upload_permission or 'users').lower()
                    if user is None or not member:
                        return None
                    if not (mutate and user.is_admin) and (
                            permission not in ('users', 'sysop')
                            or (permission == 'sysop' and not user.is_admin)
                            or not evaluate_access(user, area.min_write_level)
                            or (area.password and not user.is_admin)):
                        return None
                return area.id, user.id if user else None, bool(user and user.is_admin)
        except Exception:
            logger.exception('FTP: file-area policy lookup failed')
            return None

    def _upload_access(self, path):
        if self._qwk_node_id is None:
            return self._area_access(path, write=True)
        if (self.fs.validpath(path) and path.upper().endswith('.REP')
                and os.path.dirname(os.path.abspath(path)) == os.path.abspath(self.fs.root)):
            from ..models import db, QWKNode
            with self.app.app_context():
                node = db.session.get(QWKNode, self._qwk_node_id)
                if node is not None and node.is_active:
                    return None, node.id, False
        return None

    def _start_upload(self, path, cmd):
        if (self._staged_upload is not None or self._out_dtp_queue is not None
                or (self.data_channel is not None and self.data_channel.file_obj is not None)):
            self.respond('450 A data transfer is already in progress.')
            return
        access = self._upload_access(path)
        if access is None:
            self.respond('550 Upload is not permitted here.')
            return
        dest = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
        replace = self._qwk_node_id is not None
        if (os.path.islink(dest) or (os.path.lexists(dest) and
                (not replace or not os.path.isfile(dest)))):
            self.respond('550 A file with that name already exists.')
            return
        try:
            size = self.app.config.get('UPLOAD_MAX_SIZE', 100 * 1024 * 1024)
            session_size = self.app.config.get('FTP_SESSION_UPLOAD_MAX_BYTES') or 4 * size
            session_size -= self._upload_bytes
            if session_size <= 0:
                self.respond('552 Session upload limit reached.')
                return
            staged = open_staged_upload(dest)
        except OSError:
            logger.exception('FTP: could not stage upload')
            self.respond('550 Could not stage upload.')
            return
        upload = _BoundedUpload(self, staged, path, dest, access, replace,
                                min(size, session_size))
        self._staged_upload = upload
        code = 125 if self.data_channel is not None else 150
        detail = f'FILE: {os.path.basename(path)}' if cmd == 'STOU' else 'Opening data transfer.'
        self.respond(f'{code} {detail}')
        if self.data_channel is None:
            self._in_dtp_queue = (upload, cmd)
        else:
            self.data_channel.file_obj = upload
            self.data_channel.enable_receiving(self._current_type, cmd)
        return os.path.basename(path) if cmd == 'STOU' else path

    def _consume_upload_quota(self, access, size):
        day = int(time.time() // 86400)
        state = self.authorizer
        if state.upload_day != day:
            state.upload_day = day
            state.upload_bytes_by_account.clear()
        # A QWK node ID occupies a different namespace from a BBS user ID.
        key = (access[0] is None, access[1])
        limit = (self.app.config.get('FTP_DAILY_UPLOAD_MAX_BYTES') or
                 10 * self.app.config.get('UPLOAD_MAX_SIZE', 100 * 1024 * 1024))
        total = state.upload_bytes_by_account.get(key, 0) + size
        if total > limit:
            raise OSError(errno.EFBIG, 'FTP daily upload limit exceeded')
        state.upload_bytes_by_account[key] = total

    def ftp_STOR(self, file, mode='w'):
        if self._restart_position or mode != 'w':
            self._restart_position = 0
            self.respond('550 Upload resume and append are unavailable.')
            return
        return self._start_upload(file, 'STOR')

    def ftp_APPE(self, file):
        return self.ftp_STOR(file, mode='a')

    def ftp_STOU(self, line):
        if self._restart_position:
            self._restart_position = 0
            self.respond('550 Upload resume is unavailable.')
            return
        if not self.authorizer.has_perm(self.username, 'w'):
            self.respond('550 Upload not permitted.')
            return
        path = self.fs.ftp2fs(line) if line else os.path.join(
            self.fs.ftp2fs(self.fs.cwd), 'ftpd')
        base, ext = os.path.splitext(path)
        return self._start_upload(f'{base}-{uuid4().hex}{ext}', 'STOU')

    def _publish_upload(self, upload):
        if (self._bbs_auth != upload.auth or not self.authenticated
                or self._upload_access(upload.path) != upload.access
                or os.path.realpath(os.path.dirname(upload.path)) != os.path.dirname(upload.dest)):
            raise UploadRejected('Upload permission changed.')
        check_staged_upload(upload.name)
        if upload.replace:
            os.replace(upload.name, upload.dest)
        else:
            os.link(upload.name, upload.dest)
            os.unlink(upload.name)

    def on_file_received(self, file):
        upload = self._staged_upload
        if upload is None or upload.name != file:
            return
        try:
            if upload.replace:
                from ..echomail.qwk_hub_ftp import process_rep_upload
                process_rep_upload(upload.access[1], upload.dest, self.app)
                return
            with self.app.app_context():
                from ..models import db, FileArea, FileUpload
                area_id, user_id, _ = upload.access
                area = db.session.get(FileArea, area_id)
                name = os.path.basename(upload.dest)
                db.session.add(FileUpload(
                    uploader_id=user_id, filename=name, original_filename=name,
                    file_path=upload.dest, file_size=upload.bytes_written,
                    description='Uploaded via FTP',
                    is_public=bool(area and _can_read_area(None, area)),
                    file_area_id=area_id,
                    ftp_file_identity=file_identity(upload.dest),
                ))
                db.session.commit()
        except Exception:
            logger.exception('FTP: could not record successful upload')
        finally:
            self._clear_upload()

    def on_incomplete_file_received(self, file):
        if self._staged_upload is not None and self._staged_upload.name == file:
            self._clear_upload()

    def _clear_upload(self):
        staged = self._staged_upload
        self._staged_upload = None
        if staged is not None:
            staged.close()
            try:
                os.unlink(staged.name)
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception('FTP: could not remove staged upload')

    def close(self):
        self._cancel_auth_recheck()
        self._bbs_auth = None
        self._bbs_transfer_auth = None
        try:
            super().close()
        finally:
            self._clear_upload()

    def flush_account(self):
        # The library keeps established transfers on REIN/USER, and
        # on_logout remembers their original generation. A queued
        # upload has no open data channel and must be discarded.
        if self._in_dtp_queue is not None:
            self._clear_upload()
        self._qwk_node_id = self._qwk_packet_id = None
        super().flush_account()

    def ftp_ABOR(self, line):
        if self._staged_upload is not None and self._in_dtp_queue is not None:
            self._in_dtp_queue = None
            self._clear_upload()
        return super().ftp_ABOR(line)

    def process_command(self, cmd, *args, **kwargs):
        if self._staged_upload is not None and cmd in {
                'LIST', 'NLST', 'MLSD', 'RETR', 'STAT', 'REST'}:
            self.respond('450 An upload is already in progress.')
            return
        return super().process_command(cmd, *args, **kwargs)

    def _owned_upload(self, path, access):
        from ..models import FileUpload

        area_id, user_id, _ = access
        if not os.path.isfile(path) or os.path.islink(path):
            return None
        file_path = os.path.realpath(path)
        rows = FileUpload.query.filter_by(file_area_id=area_id, file_path=file_path,
                                          ftp_file_identity=file_identity(path)).all()
        if len(rows) == 1 and rows[0].uploader_id == user_id:
            return rows[0]
        return None

    def ftp_DELE(self, path):
        if self._qwk_node_id is not None:
            return super().ftp_DELE(path)
        access = self._area_access(path, write=True, mutate=True)
        if access is not None:
            with self.app.app_context():
                from ..models import db
                row = self._owned_upload(path, access)
                if access[2] or row is not None:
                    deleted = super().ftp_DELE(path)
                    if deleted and row is not None:
                        db.session.delete(row)
                        db.session.commit()
                    return deleted
        self.respond('550 Deletion is not permitted.')

    def ftp_RNFR(self, path):
        self._rnfr = None
        if self._qwk_node_id is not None:
            return super().ftp_RNFR(path)
        access = self._area_access(path, write=True, mutate=True)
        if access is not None:
            with self.app.app_context():
                if access[2] or self._owned_upload(path, access) is not None:
                    return super().ftp_RNFR(path)
        self.respond('550 Rename is not permitted.')

    def ftp_RNTO(self, path):
        if self._qwk_node_id is not None:
            return super().ftp_RNTO(path)
        source = self._rnfr
        self._rnfr = None
        if not source:
            self.respond('503 Use RNFR before RNTO.')
            return
        access = self._area_access(source, write=True, mutate=True)
        if access is not None and self._area_access(path, write=True, mutate=True) == access:
            with self.app.app_context():
                from ..models import db
                row = self._owned_upload(source, access)
                if (access[2] or row is not None) and not os.path.lexists(path):
                    try:
                        # Link the new name before removing the old one,
                        # with no implicit overwrite even across processes.
                        os.link(source, path)
                        os.unlink(source)
                    except OSError:
                        self.respond('550 Could not rename file.')
                        return
                    if row is not None:
                        row.file_path = os.path.realpath(path)
                        row.filename = os.path.basename(path)
                        row.original_filename = row.filename
                        row.ftp_file_identity = file_identity(path)
                        db.session.commit()
                    self.respond('250 Renaming ok.')
                    return source, path
        self.respond('550 Rename is not permitted.')

    def ftp_MKD(self, path):
        if self._qwk_node_id is not None:
            return super().ftp_MKD(path)
        access = self._area_access(path, write=True, mutate=True)
        if access and access[2]:
            return super().ftp_MKD(path)
        self.respond('550 Directory creation is not permitted.')

    def ftp_RMD(self, path):
        if self._qwk_node_id is not None:
            return super().ftp_RMD(path)
        access = self._area_access(path, write=True, mutate=True)
        if access and access[2]:
            return super().ftp_RMD(path)
        self.respond('550 Directory removal is not permitted.')

    def ftp_SITE_CHMOD(self, path, mode):
        access = self._area_access(path, write=True, mutate=True)
        if access and access[2]:
            return super().ftp_SITE_CHMOD(path, mode)
        self.respond('550 Changing mode is not permitted.')

    def ftp_MFMT(self, path, timeval):
        access = self._area_access(path, write=True, mutate=True)
        if access and access[2]:
            return super().ftp_MFMT(path, timeval)
        self.respond('550 Changing timestamps is not permitted.')

    def ftp_RETR(self, file):
        """Apply daily quota after the filesystem validates area access."""
        if (self.app is not None and self.username != 'anonymous'
                and self._qwk_node_id is None):
            try:
                with self.app.app_context():
                    from ..features.file_quota import check_quota
                    user = self._current_bbs_user()
                    if user is not None:
                        try:
                            size = os.path.getsize(file)
                        except OSError:
                            size = 0
                        ok, msg = check_quota(user, size)
                        if not ok:
                            self.respond(f'550 {msg}')
                            return
            except Exception:
                logger.exception('FTP: quota check failed for %s', self.username)
        return super().ftp_RETR(file)

    def on_file_sent(self, file):
        """Companion to ftp_RETR's pre-check -- records usage after a
        successful RETR. See ftp_RETR's docstring for the anon/QWK skip."""
        if (self.app is None or self.username == 'anonymous'
                or self._qwk_node_id is not None):
            return
        try:
            with self.app.app_context():
                from ..features.file_quota import consume_quota
                user = self._current_bbs_user()
                if user is not None:
                    try:
                        size = os.path.getsize(file)
                    except OSError:
                        size = 0
                    consume_quota(user, size)
        except Exception:
            logger.exception('FTP: on_file_sent quota hook failed')


def build_server(app, host, port, anon_enabled=True,
                 tls_certfile='', tls_keyfile='',
                 pasv_ports_range='40000-40050',
                 root_dir='data/ftp_root',
                 banner='ANetBBS FTP'):
    """Wire up an FTP server bound to (host, port). Returns the server
    instance — caller does `serve_forever()` or `close_all()`.
    """
    from ..models import FileArea
    from pyftpdlib.servers import FTPServer

    handler_cls = AnetbbsFTPHandler

    # FTPS soft-fail: we need both files to *exist AND be readable*. The
    # previous `os.path.exists` check passed for /etc/letsencrypt/live/
    # symlinks even when the linked archive/*.pem files were 0600 root-
    # only — TLS_FTPHandler then crashed during SSL context init and the
    # FTP listener died silently (the whole daemon thread, not just one
    # session). Now we test readability up front, log a clear warning,
    # and fall back to plain FTP instead of taking the listener down.
    def _tls_ready():
        if not (tls_certfile and tls_keyfile):
            return False
        for path, label in ((tls_certfile, 'cert'), (tls_keyfile, 'key')):
            if not os.path.exists(path):
                logger.warning('FTP: TLS %s missing (%s) — falling back '
                               'to plain FTP', label, path)
                return False
            if not os.access(path, os.R_OK):
                logger.warning(
                    'FTP: TLS %s unreadable by service user — falling '
                    'back to plain FTP. Fix: add this user to the '
                    'ssl-cert group OR copy the cert to a path the '
                    'service can read. (%s)', label, path)
                return False
            # Belt-and-braces: open the file. Catches stat-vs-open
            # divergence on weird filesystems (overlayfs, NFS root-squash).
            try:
                with open(path, 'rb') as _:
                    pass
            except OSError as exc:
                logger.warning('FTP: TLS %s open failed (%s) — falling '
                               'back to plain FTP', label, exc)
                return False
        return True

    if _tls_ready():
        # FTPS — AUTH TLS on the same port. Implicit FTPS would need 990.
        # ``TLS_FTPHandler`` is only exposed by pyftpdlib when pyOpenSSL
        # is importable; missing that dep used to crash the whole FTP
        # thread with ``ImportError: cannot import name 'TLS_FTPHandler'``.
        # Catch + downgrade to plain FTP with an actionable warning.
        try:
            from pyftpdlib.handlers import TLS_DTPHandler, TLS_FTPHandler
        except ImportError as exc:
            logger.warning(
                'FTP: TLS_FTPHandler unavailable (%s) — pyOpenSSL is '
                'probably not installed in the venv. Run '
                '`venv/bin/pip install pyopenssl` and restart anetbbs '
                'to enable FTPS. Falling back to plain FTP for now.',
                exc)
        else:
            class _TLSAnetbbsDTPHandler(_PublishBeforeReply, TLS_DTPHandler):
                pass

            class _TLSAnetbbsHandler(AnetbbsFTPHandler, TLS_FTPHandler):
                dtp_handler = _TLSAnetbbsDTPHandler
            handler_cls = _TLSAnetbbsHandler
            handler_cls.certfile = tls_certfile
            handler_cls.keyfile = tls_keyfile
            handler_cls.tls_control_required = False  # AUTH TLS optional
            handler_cls.tls_data_required = False
            logger.info('FTP: TLS enabled (%s)', tls_certfile)
    elif tls_certfile or tls_keyfile:
        # Either set, but soft-fail check kicked in — make the
        # downgrade explicit so the sysop sees one line per startup.
        logger.warning('FTP: starting without TLS (AUTH TLS clients '
                       'will fall back to plain). Clear FTP_TLS_CERTFILE/'
                       'FTP_TLS_KEYFILE in .env to silence this warning.')

    # Build three symlink trees — anon (read-only public), users (auth,
    # non-sysop-only), admin (sysop-only included). The authorizer maps
    # the right tree to each session at login.
    anon_root = os.path.join(root_dir, 'anon')
    user_root = os.path.join(root_dir, 'users')
    admin_root = os.path.join(root_dir, 'admin')
    with app.app_context():
        areas = FileArea.query.all()
        trees = {os.path.abspath(root): _build_symlink_tree(root, areas, mode)
                 for root, mode in ((anon_root, 'anon'), (user_root, 'user'),
                                    (admin_root, 'admin'))}

    logger.info('FTP: linked %d anon / %d user / %d admin visible areas',
                *(len(mapping) for mapping in trees.values()))

    qwk_root = os.path.join(app.config.get('DATA_DIR', 'data'), 'qwk-hub')
    os.makedirs(qwk_root, exist_ok=True)
    authorizer = AnetbbsAuthorizer(app, anon_root, user_root, admin_root,
                                   anon_enabled=anon_enabled,
                                   qwk_root=qwk_root, area_roots=trees)
    handler_cls.authorizer = authorizer
    handler_cls.abstracted_fs = SymlinkAwareFS
    handler_cls.app = app
    handler_cls.banner = banner

    # Passive-mode port range parsing — `start-end` form.
    try:
        lo, hi = pasv_ports_range.split('-', 1)
        handler_cls.passive_ports = range(int(lo), int(hi) + 1)
    except (ValueError, AttributeError):
        handler_cls.passive_ports = range(40000, 40051)

    server = FTPServer((host, port), handler_cls)
    server.max_cons = 256
    server.max_cons_per_ip = 8
    return server


def build_minimal_app():
    """Create a stripped-down Flask app — JUST enough for SQLAlchemy
    `app_context()` and User/FileArea queries. Skips blueprint
    registration, echomail/RSS pollers, MSP/SYSTAT bind attempts, and
    every other background subsystem.

    CRITICAL for FTP integration: the full `web_app.create_app()` starts
    threads that conflict with the asyncio loop in `anetbbs.main` and
    breaks telnet/SSH login with "cannot notify on un-acquired lock"
    errors. This minimal app sidesteps all of that.
    """
    from flask import Flask
    from ..config import get_config
    from ..models import db

    env = os.environ.get('FLASK_ENV', 'production')
    app = Flask(__name__)
    app.config.from_object(get_config(env))
    db.init_app(app)
    # The User model's bcrypt check + FileUpload write only need
    # `db.session`, which `db.init_app` is enough to bind. Inside the
    # FTP request handlers we wrap calls in `app.app_context():`.
    return app


def run(app):
    """Daemon-thread entry point. Pulls config off `app`, builds the
    server, and blocks on `serve_forever()`. Designed to be invoked from
    `anetbbs.main` when `FTP_ENABLED` is true."""
    cfg = app.config
    host = cfg.get('FTP_HOST', '0.0.0.0')
    port = int(cfg.get('FTP_PORT', 21))
    root = cfg.get('FTP_ROOT_DIR', 'data/ftp_root')
    if not os.path.isabs(root):
        root = os.path.join(cfg.get('BASE_DIR', '.'), root)

    server = build_server(
        app, host, port,
        anon_enabled=cfg.get('FTP_ANON_ENABLED', True),
        tls_certfile=cfg.get('FTP_TLS_CERTFILE', ''),
        tls_keyfile=cfg.get('FTP_TLS_KEYFILE', ''),
        pasv_ports_range=cfg.get('FTP_PASV_PORTS', '40000-40050'),
        root_dir=root,
        banner=cfg.get('FTP_BANNER', 'ANetBBS FTP'),
    )
    logger.info('FTP: serving %s:%d (root=%s, anon=%s)',
                host, port, root, cfg.get('FTP_ANON_ENABLED', True))
    try:
        server.serve_forever()
    finally:
        try: server.close_all()
        except Exception: pass
