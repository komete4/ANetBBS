# anetbbs/web/web_terminal.py
"""
Browser-based terminal — xterm.js front-end, socketio back-end.

Lets a web user open a raw TCP socket (optionally TLS-wrapped) to ANY
host:port (defaults to the local BBS's telnet port) right inside the
browser tab — no native client required. This is a plain telnet-style
pipe, not a protocol client: there's no telnet IAC option negotiation
and no SSH implementation, so it works well against telnet/rlogin-style
servers that just stream bytes but will not complete a real SSH
handshake. This is the closest analog to fTelnet / SyncTERM-in-browser.

Architecture:
    Browser <—socketio—> Flask process <—TCP—> Remote BBS

Each browser tab gets its own outbound TCP socket; bytes flow both ways
through the socketio namespace `/term`.
"""
import json
import os
import socket
import ssl as ssl_module
import threading
import time

from flask import Blueprint, abort, current_app, render_template, request, session
from flask_login import login_required, current_user
from flask_socketio import disconnect, emit

from ..core.net_safety import resolve_safe_destination as _resolve_safe_destination_impl
from ..models import User, UserSession, db


term_bp = Blueprint('web_terminal', __name__, url_prefix='/terminal')


@term_bp.before_request
def _require_enabled():
    if not current_app.config['WEB_TERMINAL_ENABLED']:
        abort(403)


# Per-socketio-sid outbound terminal state
_sessions = {}
_lock = threading.Lock()


def _own_service_ports():
    """This BBS's own telnet/SSH/rlogin ports -- the only ports this
    feature is allowed to reach on loopback, matching its documented
    intended use (dialing into our own terminal service from the
    browser). Any OTHER loopback/private-network port is refused."""
    ports = set()
    for env_name, default in (('TELNET_PORT', '2233'),
                               ('SSH_PORT', '2234'),
                               ('RLOGIN_PORT', '513')):
        try:
            ports.add(int(os.environ.get(env_name, default)))
        except (TypeError, ValueError):
            pass
    return ports


def _resolve_safe_destination(host, port):
    """SSRF guard: this feature (see module docstring) deliberately lets
    a logged-in user connect to ANY *external* host:port -- that's the
    whole point, it's a browser telnet client for dialing other BBSes.
    Without a check here, though, the exact same code path lets any
    logged-in user (not just admins) point the server at internal
    infrastructure instead: other hosts on a private LAN, other
    containers on the same Docker network, or a cloud metadata endpoint
    (169.254.169.254) -- turning this into an authenticated SSRF/port-
    scanning primitive. Rejects private/link-local/reserved/multicast
    destinations, with a narrow exception for loopback on one of this
    BBS's own service ports.

    Thin wrapper around the shared core.net_safety implementation
    (extracted this audit round so RSS's feed-URL and sixel-image
    fetches can share the exact same validation instead of each
    maintaining their own copy) -- this module keeps its own loopback-
    exception behavior via own_ports=_own_service_ports.

    Returns (family, sockaddr, None) on success, or
    (None, None, error_message) on rejection.
    """
    return _resolve_safe_destination_impl(host, port, own_ports=_own_service_ports)


class _TermSession:
    """One browser tab's terminal — spawned greenthread reads from the
    outbound socket and forwards bytes to the user via socketio."""

    def __init__(self, sid, host, port, use_ssl=False, *, app=None,
                 user_id=None, auth_version=None, presence_id=None,
                 presence_key=None):
        self.sid = sid
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.app = app
        self.user_id = user_id
        self.auth_version = auth_version
        self.presence_id = presence_id
        self.presence_key = presence_key
        self.sock = None
        self.connected = False

    def authorized(self):
        # A fresh app context reads committed state even when logout,
        # credential changes or a kick happened in a different process.
        if (self.app is None or not self.app.config.get('WEB_TERMINAL_ENABLED', True)
                or self.presence_id is None):
            return False
        with self.app.app_context():
            user = db.session.get(User, self.user_id)
            if (not user or not user.is_active or user.is_locked
                    or (not user.is_verified and not user.is_admin)
                    or user.auth_version != self.auth_version):
                return False
            presence = db.session.get(UserSession, self.presence_id)
            return bool(presence and presence.user_id == self.user_id
                        and presence.session_key == self.presence_key
                        and not presence.kick_requested)

    def open(self):
        # _resolve_safe_destination() (see its own docstring) is the
        # SSRF guard -- resolves once and hands back the exact address
        # to connect to, so this doesn't re-resolve self.host itself
        # (which would reopen a DNS-rebinding gap between the check
        # and the connect).
        family, sockaddr, error = _resolve_safe_destination(self.host, self.port)
        if error:
            self._emit('term_error', {'message': error})
            return False
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect(sockaddr)
            if self.use_ssl:
                ctx = ssl_module.create_default_context()
                ca_files = json.loads(self.app.config['WEB_TERMINAL_TLS_CA_FILES'])
                if not isinstance(ca_files, dict):
                    raise ValueError('WEB_TERMINAL_TLS_CA_FILES must be a JSON object')
                ca_file = ca_files.get(f'{self.host.lower()}:{self.port}')
                if ca_file:
                    ctx.load_verify_locations(cafile=ca_file)
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            self.sock = sock
            self.connected = True
            return True
        except (OSError, TypeError, ValueError) as exc:
            if sock is not None:
                sock.close()
            self._emit('term_error', {'message': f'Connect failed: {exc}'})
            return False

    def write(self, data):
        sock = self.sock
        if sock is None or not self.connected:
            return
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        try:
            sock.sendall(data)
        except OSError as exc:
            self._emit('term_error', {'message': f'Write failed: {exc}'})
            self.connected = False

    def close(self):
        sock, self.sock = self.sock, None
        self.connected = False
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def run(self):
        """Read loop — push everything we receive back to the browser as
        UTF-8 (browser side decodes / xterm.js writes it raw).

        Uses a recv timeout so we can interleave server→browser keepalive
        events when the remote BBS is idle. `socket.timeout` distinguishes
        idle-timeout from remote-close: timeout = continue, b'' = remote
        sent FIN, exception = error."""
        try:
            if self.sock is not None:
                self.sock.settimeout(3)
        except OSError:
            pass

        last_keepalive = time.monotonic()
        next_auth_check = last_keepalive

        try:
            while self.connected:
                now = time.monotonic()
                if now >= next_auth_check:
                    if not self.authorized():
                        break
                    next_auth_check = now + 3
                sock = self.sock  # snapshot so close()-racing can't None it mid-call
                if sock is None:
                    break
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    chunk = None  # idle — fall through to keepalive
                except OSError:
                    break
                now = time.monotonic()
                if now >= next_auth_check:
                    if not self.authorized():
                        break
                    next_auth_check = now + 3
                if chunk is not None:
                    if not chunk:
                        break  # remote closed cleanly
                    try:
                        text = chunk.decode('cp437', errors='replace')
                    except Exception:
                        text = chunk.decode('utf-8', errors='replace')
                    self._emit('term_output', {'data': text})
                if now - last_keepalive >= 20:
                    self._emit('term_keepalive', {'t': now})
                    last_keepalive = now
        finally:
            self.close()
            with _lock:
                # Real gap found in a security/performance audit: a
                # blind pop(self.sid) here can clobber a NEWER session
                # that has since replaced this one at the same sid --
                # e.g. two term_open events racing for the same sid
                # (a rapid reconnect racing a slow-connecting prior
                # open) each create their own _TermSession and each
                # eventually run() to completion; whichever's finally
                # block runs LAST would otherwise evict the dict entry
                # regardless of which session is actually current.
                # Only remove the entry if it still points at THIS
                # session.
                if _sessions.get(self.sid) is self:
                    _sessions.pop(self.sid, None)
                    notify = True
                else:
                    notify = False
            if notify:
                self._emit('term_disconnected', {})

    def _emit(self, event, payload):
        from ..web_app import socketio
        socketio.emit(event, payload, to=self.sid, namespace='/term')


@term_bp.route('/')
@login_required
def index():
    """xterm.js terminal page. Defaults to localhost:2233 (our telnet).

    Accepts optional ?host=&port= query params to pre-fill the form
    with a specific destination -- added so the ANetBBS Enhanced
    Client (a JSON-only protocol with no raw-byte terminal passthrough,
    see anetbbs/features/dialout.py) can link here for dial-out instead
    of trying to proxy arbitrary remote-BBS ANSI through its own
    protocol. Still just pre-fills the form; the user clicks Connect
    themselves -- no auto-connect, and this page's own @login_required
    (a separate Flask-Login web session from the terminal-protocols
    process's BBSSession) still applies, so a user who isn't also
    logged into the web UI in that browser hits a login prompt first.
    """
    default_host = os.environ.get('BBS_PUBLIC_HOST', 'localhost')
    default_port = int(os.environ.get('TELNET_PORT', '2233'))
    req_host = (request.args.get('host') or '').strip()
    if req_host:
        default_host = req_host
    req_port = request.args.get('port', '').strip()
    if req_port:
        try:
            default_port = int(req_port)
        except ValueError:
            pass
    return render_template('terminal/index.html',
                           default_host=default_host,
                           default_port=default_port)


def register_socketio_handlers(socketio):
    @socketio.on('connect', namespace='/term')
    def on_connect():
        if (not current_app.config['WEB_TERMINAL_ENABLED']
                or not current_user.is_authenticated):
            return False

    @socketio.on('disconnect', namespace='/term')
    def on_disconnect():
        sid = request.sid
        with _lock:
            sess = _sessions.pop(sid, None)
        if sess:
            sess.close()

    @socketio.on('term_open', namespace='/term')
    def on_open(data):
        if (not current_app.config['WEB_TERMINAL_ENABLED']
                or not current_user.is_authenticated):
            return False
        sid = request.sid
        if not isinstance(data, dict) or not isinstance(data.get('host', ''), str):
            return
        host = (data.get('host') or 'localhost').strip()
        try:
            port = int(data.get('port') or 23)
        except (TypeError, ValueError):
            emit('term_error', {'message': 'Invalid terminal port.'})
            return
        if not 1 <= port <= 65535:
            emit('term_error', {'message': 'Invalid terminal port.'})
            return
        use_ssl = bool(data.get('use_ssl'))
        presence_key = session.get('presence_session_key')
        presence = (UserSession.query.filter_by(
            user_id=current_user.id, session_key=presence_key,
        ).first() if presence_key else None)
        if presence is None or presence.kick_requested:
            emit('term_error', {'message': 'Reload the web terminal and sign in again.'})
            disconnect()
            return

        sess = _TermSession(
            sid, host, port, use_ssl, app=current_app._get_current_object(),
            user_id=current_user.id, auth_version=current_user.auth_version,
            presence_id=presence.id, presence_key=presence.session_key,
        )
        with _lock:
            existing = _sessions.get(sid)
            _sessions[sid] = sess
        if existing:
            existing.close()

        opened = sess.authorized() and sess.open() and sess.authorized()
        with _lock:
            still_current = _sessions.get(sid) is sess
            if still_current and not opened:
                _sessions.pop(sid)
        if not opened or not still_current:
            sess.close()
            return
        socketio.start_background_task(sess.run)
        emit('term_connected', {'host': host, 'port': port, 'use_ssl': use_ssl})

    @socketio.on('term_input', namespace='/term')
    def on_input(data):
        sid = request.sid
        with _lock:
            sess = _sessions.get(sid)
        if not sess:
            return
        if not sess.authorized():
            emit('term_disconnected', {})
            disconnect()
            return
        if isinstance(data, dict) and isinstance(data.get('data'), str):
            sess.write(data['data'])

    @socketio.on('term_close', namespace='/term')
    def on_close():
        sid = request.sid
        with _lock:
            sess = _sessions.pop(sid, None)
        if sess:
            sess.close()
            emit('term_disconnected', {})
