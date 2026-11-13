# anetbbs/web/personal_pages.py
"""
Personal web-pages server.

When `PERSONAL_PAGES_ENABLED=true`:
  - bbs.example.com/<dir>/        serves data/personal_pages/<dir>/index.html
                                  (or index.htm / default.html / default.htm /
                                   home.html — first one found)
  - bbs.example.com/<dir>/file    serves the file from that directory
  - bbs.example.com/~<user>/...   serves data/personal_pages/users/<user>/...
                                  so each registered user can publish.

Hooked via a Flask 404 handler so it never shadows real BBS routes —
only takes over when no other route matches.

With `PERSONAL_PAGES_STATIC_ORIGIN` configured, the authenticated editor
writes HTML and CSS to an independent tree for a static server. The BBS
does not serve either tree in this mode.
"""
import os
import re
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import Lock
from urllib.parse import urlsplit

from flask import (Blueprint, send_from_directory, abort, current_app,
                   render_template, redirect, url_for, request, flash)
from flask_login import login_required, current_user

from ..features.i18n import translate


pages_bp = Blueprint('personal_pages', __name__, url_prefix='/_pages')


@pages_bp.before_request
def _require_publishing():
    if not current_app.config.get('PERSONAL_PAGES_PUBLISHING_ENABLED', True):
        abort(404)
    if current_app.config.get('PERSONAL_PAGES_STATIC_ORIGIN') and not _static_origin():
        abort(503)


# Files to try in order when the URL ends with a /
INDEX_FILES = ('index.html', 'index.htm', 'default.html', 'default.htm',
               'home.html', 'home.htm')
STATIC_FILENAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.(?:html?|css)', re.I)
STATIC_MAX_BYTES = 512 * 1024
STATIC_MAX_FILES = 20
_static_files_lock = Lock()


def _static_origin():
    value = current_app.config.get('PERSONAL_PAGES_STATIC_ORIGIN')
    if not value:
        return None
    try:
        origin = urlsplit(value)
        port = origin.port
        bbs_hosts = (
            urlsplit(current_app.config.get('PUBLIC_BASE_URL') or '').hostname,
            urlsplit('//' + (current_app.config.get('BBS_DOMAIN') or '')).hostname,
            urlsplit('//' + request.host).hostname,
        )
    except ValueError:
        return None
    host = (origin.hostname or '').rstrip('.')
    if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*', host):
        return None
    if origin.scheme != 'https' and not (origin.scheme == 'http' and host in ('localhost', '127.0.0.1')):
        return None
    if origin.username is not None or origin.password is not None or port == 0:
        return None
    if origin.path not in ('', '/') or origin.query or origin.fragment:
        return None
    if any(host == bbs_host.rstrip('.') for bbs_host in bbs_hosts if bbs_host):
        return None
    return f'{origin.scheme}://{host}' + (f':{port}' if port is not None else '')


def _user_directory(static_origin):
    if not static_origin:
        return _root() / 'users' / current_user.username
    data = Path(current_app.config.get('DATA_DIR', 'data')).resolve()
    directory = data / 'personal_pages_public' / 'users' / str(int(current_user.id))
    if directory.resolve() != directory:
        abort(503)
    return directory


def _write_static_file(directory, uploaded):
    filename = uploaded.filename
    if not STATIC_FILENAME.fullmatch(filename):
        flash(translate('personal_pages.notice.invalid_extension', 'Use a simple filename ending in .html, .htm or .css.'), 'danger')
        return
    content = uploaded.stream.read(STATIC_MAX_BYTES + 1)
    if len(content) > STATIC_MAX_BYTES:
        flash(translate('personal_pages.notice.file_too_large', 'Personal page files can be at most 512 KB.'), 'danger')
        return
    try:
        content.decode('utf-8')
    except UnicodeDecodeError:
        flash(translate('personal_pages.notice.utf8_required', 'Save the file as UTF-8 before uploading.'), 'danger')
        return
    target = directory / filename
    with _static_files_lock:
        if target.is_symlink():
            abort(404)
        if not target.exists() and sum(p.is_file() for p in directory.iterdir()) >= STATIC_MAX_FILES:
            flash(translate('personal_pages.notice.file_limit', 'You can publish up to 20 personal page files.'), 'danger')
            return
        temporary = None
        try:
            with NamedTemporaryFile(dir=directory, suffix='.upload', delete=False) as staged:
                temporary = Path(staged.name)
                staged.write(content)
            temporary.chmod(0o644)
            temporary.replace(target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    flash(translate('personal_pages.notice.uploaded', 'Uploaded {filename}.', filename=filename), 'success')


def _root():
    """Absolute path to data/personal_pages/. Created on demand."""
    base = Path(current_app.config.get('DATA_DIR', 'data')) / 'personal_pages'
    base.mkdir(parents=True, exist_ok=True)
    (base / 'users').mkdir(exist_ok=True)
    return base


def _safe_resolve(base, rel_path):
    """Combine base + rel_path safely (no traversal). Returns Path or None."""
    try:
        target = (base / rel_path).resolve()
        if not str(target).startswith(str(base.resolve()) + os.sep) \
                and target != base.resolve():
            return None
        return target
    except Exception:
        return None


def _try_serve(target):
    """Given a Path, send it as a file or auto-index if it's a directory.
    Returns a Flask response or None if nothing matched."""
    if target is None or not target.exists():
        return None
    if target.is_file():
        return send_from_directory(target.parent, target.name)
    if target.is_dir():
        for idx in INDEX_FILES:
            candidate = target / idx
            if candidate.is_file():
                return send_from_directory(target, idx)
        return None
    return None


def serve_root_page(path):
    """Serve a path of the form '<dir>[/<rest>]' from personal_pages/.
    Returns a response or None if not handled."""
    if (current_app.config.get('PERSONAL_PAGES_STATIC_ORIGIN')
            or not current_app.config.get('PERSONAL_PAGES_ENABLED')):
        return None
    if not path:
        return None
    base = _root()

    # Reserved names we never let personal-pages claim — safety guard
    # in case a sysop creates a folder that conflicts with a real route.
    reserved = {
        'admin', 'auth', 'profile', 'boards', 'pm', 'files', 'echomail',
        'mrcweb', 'mrcws', 'mrc', 'irc', 'shoutbox', 'static', 'api',
        'who', 'polls', 'finger', 'telegram', 'peers', 'ansi', 'term',
        'stats', 'feed', 'gemini', 'notifications', 'calendar', 'groups',
        'leaderboard', 'oneliners', 'qwk', 'blocks', 'm', 'tour', 'help',
        'about', 'search', 'register', 'login', 'logout', 'healthz',
        'robots.txt', 'humans.txt', 'sitemap.xml', '_pages', 'saved',
        'site', 'bulletins', 'file-areas', 'netmail', 'nodelist',
        'contacts', 'games',
    }
    parts = path.split('/', 1)
    head = parts[0]
    rest = parts[1] if len(parts) > 1 else ''
    if head.lower() in reserved:
        return None

    if head.startswith('~'):
        # /~user/... -> data/personal_pages/users/<user>/...
        username = head[1:]
        if not re.fullmatch(r'[A-Za-z0-9._-]+', username):
            return None
        target_base = base / 'users' / username
        target = _safe_resolve(target_base, rest) if rest else target_base
        return _try_serve(target)

    # /folder/...
    # Real gap found in a security/performance audit: unlike the
    # `~user` branch just above (which regex-validates `username`
    # before ever touching the filesystem), `head` here was used
    # completely unvalidated. A path of '../<rest>' makes
    # target_base = base / '..' resolve to data/personal_pages/'s
    # PARENT (i.e. data/ itself), which .is_dir() happily confirms --
    # and _safe_resolve()'s own containment check is then evaluated
    # against that already-escaped target_base, so it passes trivially,
    # serving anything under data/ (including data/admin_password.txt,
    # the initial-admin plaintext password written on first boot) to
    # any request that reaches this 404 fallback. Resolving target_base
    # itself through the SAME containment check _safe_resolve() applies
    # to `rest` -- confirming it's still really inside `base` -- closes
    # this the same way the `~user` branch is already closed, instead
    # of trusting a bare .is_dir() truthiness check.
    target_base = _safe_resolve(base, head)
    if target_base is None or not target_base.is_dir():
        return None
    target = _safe_resolve(target_base, rest) if rest else target_base
    return _try_serve(target)


# ---------------------------------------------------------------------------
# Per-user file manager — drop files into your /~username/ space
# ---------------------------------------------------------------------------

@pages_bp.route('/')
@login_required
def my_pages():
    """List + manage the current user's personal-page files."""
    static_origin = _static_origin()
    base = _user_directory(static_origin)
    base.mkdir(parents=True, exist_ok=True)
    files = []
    for p in sorted(base.iterdir()):
        if static_origin and (p.is_symlink() or not STATIC_FILENAME.fullmatch(p.name)):
            continue
        if p.is_file():
            files.append({
                'name': p.name,
                'size': p.stat().st_size,
                'is_index': p.name == 'index.html' if static_origin else p.name.lower() in INDEX_FILES,
            })
    enabled = current_app.config.get('PERSONAL_PAGES_ENABLED', False)
    static_url = f'{static_origin}/users/{int(current_user.id)}/' if static_origin else None
    return render_template('personal_pages/index.html',
                           files=files, enabled=enabled,
                           username=current_user.username,
                           index_files=INDEX_FILES, static_url=static_url)


@pages_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    static_origin = _static_origin()
    base = _user_directory(static_origin)
    base.mkdir(parents=True, exist_ok=True)
    if static_origin:
        request.max_content_length = STATIC_MAX_BYTES + 32 * 1024
    f = request.files.get('file')
    if not f or not f.filename:
        flash(translate('personal_pages.notice.file_required', 'No file selected.'), 'danger')
        return redirect(url_for('personal_pages.my_pages'))
    if static_origin:
        _write_static_file(base, f)
        return redirect(url_for('personal_pages.my_pages'))
    safe_name = os.path.basename(f.filename)
    if not safe_name or safe_name.startswith('.'):
        flash(translate('personal_pages.notice.invalid_filename', 'Invalid filename.'), 'danger')
        return redirect(url_for('personal_pages.my_pages'))
    f.save(str(base / safe_name))
    flash(translate('personal_pages.notice.uploaded', 'Uploaded {filename}.', filename=safe_name), 'success')
    return redirect(url_for('personal_pages.my_pages'))


@pages_bp.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete(filename):
    static_origin = _static_origin()
    base = _user_directory(static_origin)
    if static_origin and (not STATIC_FILENAME.fullmatch(filename) or (base / filename).is_symlink()):
        abort(404)
    target = _safe_resolve(base, filename)
    if target is None or not target.is_file():
        abort(404)
    try:
        target.unlink()
        flash(translate('personal_pages.notice.deleted', 'Deleted {filename}.', filename=filename), 'success')
    except Exception as exc:
        flash(translate('personal_pages.notice.delete_failed', 'Delete failed: {exc}', exc=exc), 'danger')
    return redirect(url_for('personal_pages.my_pages'))
