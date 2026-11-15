"""Background RSS / Atom poller.

Periodically fetches every active RssFeed, parses with feedparser,
upserts items into RssItem (deduped by GUID).

The poller runs as a background daemon thread started from web_app.py
on app boot. Default interval is 1800 seconds (30 minutes) — tunable
via the ``RSS_POLL_INTERVAL`` env var.

For an immediate fetch (when sysop adds a new feed or hits "refresh"
in the admin UI), call :func:`fetch_one_now`.
"""
from http.client import parse_headers
from io import BytesIO
import os
import subprocess
import time
import logging
import threading
from datetime import datetime, timedelta
from html import unescape
from urllib.parse import urljoin, urlsplit
import re

logger = logging.getLogger(__name__)

_stop_event = threading.Event()
_thread = None
_HTML_TAG_RE = re.compile(r'<[^>]+>')

# Real gap found in a security/performance audit: feedparser.parse()
# has no timeout= parameter at all (confirmed against its real
# signature) and no connect/read deadline was ever applied around it
# -- a slow, unresponsive, or deliberately stalling feed server could
# hang this call indefinitely. Since _poll_loop below fetches feeds
# ONE AT A TIME on a single dedicated background thread, one hung feed
# blocked every OTHER active feed's refresh for as long as the hang
# lasted, with no upper bound at all. Bounding this caps the worst
# case for a full poll cycle at num_feeds * _FEED_FETCH_TIMEOUT
# instead of potentially forever.
_FEED_FETCH_TIMEOUT = 20


_FEED_MAX_BYTES = 5 * 1024 * 1024
_FEED_MAX_HEADERS = 64 * 1024
_FEED_MAX_REDIRECTS = 5
_REDIRECTS = {301, 302, 303, 307, 308}


def _curl_feed_response(url, host, port, ip, timeout):
    """Read a single HTTP response with bounded headers, body and run time."""
    pinned_ip = f'[{ip}]' if ':' in ip else ip
    args = [
        'curl', '--disable', '--silent', '--include', '--noproxy', '*',
        '--proto', '=http,https', '--max-time', str(timeout),
        '--max-filesize', str(_FEED_MAX_BYTES),
        '--user-agent', 'ANetBBS RSS reader (+https://github.com/anetonline/anetbbs)',
        '--resolve', f'{host}:{port}:{pinned_ip}', '--', url,
    ]
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        try:
            remaining = _FEED_MAX_HEADERS
            while remaining:
                status_line = proc.stdout.readline(remaining + 1)
                remaining -= len(status_line)
                fields = status_line.split(None, 2)
                if remaining <= 0 or len(fields) < 2 or not fields[0].startswith(b'HTTP/'):
                    code = proc.wait(timeout=timeout + 1) if not status_line else None
                    if code == 28:
                        raise TimeoutError('feed fetch timed out')
                    if code == 63:
                        raise ValueError('feed response exceeds the size limit')
                    raise ValueError('invalid feed HTTP response')
                status = int(fields[1])
                lines = []
                while remaining > 0:
                    line = proc.stdout.readline(remaining + 1)
                    remaining -= len(line)
                    if remaining <= 0 or not line:
                        raise ValueError('invalid or oversized feed response headers')
                    if line in (b'\r\n', b'\n'):
                        break
                    lines.append(line)
                if 100 <= status < 200:
                    continue
                break

            headers = parse_headers(BytesIO(b''.join(lines)))
            if status in _REDIRECTS:
                return status, headers.get('Location'), b''
            if status != 200:
                raise ValueError(f'feed returned HTTP {status}')
            body = proc.stdout.read(_FEED_MAX_BYTES + 1)
            if len(body) > _FEED_MAX_BYTES:
                raise ValueError('feed response exceeds the size limit')
            code = proc.wait(timeout=timeout + 1)
            if code == 28:
                raise TimeoutError('feed fetch timed out')
            if code == 63:
                raise ValueError('feed response exceeds the size limit')
            if code:
                raise ValueError(f'curl exited {code}')
            return status, None, body
        finally:
            if proc.poll() is None:
                proc.kill()


def _fetch_feed(url):
    """Validate and pin the destination of every hop, including redirects."""
    from ..core.net_safety import resolve_safe_destination

    deadline = time.monotonic() + _FEED_FETCH_TIMEOUT
    for _ in range(_FEED_MAX_REDIRECTS + 1):
        parsed = urlsplit(url or '')
        host = parsed.hostname
        if (parsed.scheme not in ('http', 'https') or not host
                or parsed.username is not None or parsed.password is not None):
            raise ValueError('feed URL must be an http(s) URL without credentials')
        host = host.encode('idna').decode('ascii')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        _, sockaddr, error = resolve_safe_destination(host, port)
        if error:
            raise ValueError(f'refused: {error}')
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise TimeoutError('feed fetch timed out')
        resolve_host = f'[{host}]' if ':' in host else host
        authority = resolve_host
        if parsed.port is not None:
            authority = f'{authority}:{port}'
        url = parsed._replace(netloc=authority, fragment='').geturl()
        status, location, body = _curl_feed_response(url, resolve_host, port, sockaddr[0], timeout)
        if status not in _REDIRECTS:
            return body
        if not location:
            raise ValueError('feed redirect has no Location')
        url = urljoin(url, location)
    raise ValueError('feed has too many redirects')


def _strip_html(text):
    """Strip HTML tags + collapse whitespace. Preserves the readable
    content for the summary preview without leaving raw markup in the
    listing pages."""
    if not text:
        return ''
    cleaned = _HTML_TAG_RE.sub(' ', text)
    cleaned = unescape(cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned


def _parse_published(entry):
    """Best-effort UTC datetime from a feedparser entry."""
    for field in ('published_parsed', 'updated_parsed', 'created_parsed'):
        t = getattr(entry, field, None)
        if t:
            try:
                return datetime(*t[:6])
            except (TypeError, ValueError):
                pass
    return None


def _import_one_feed(app, feed_id):
    """Fetch one feed and persist any new items. Returns count of inserted
    items. Updates feed.last_fetched_at and feed.last_error."""
    import feedparser
    from ..models import db, RssFeed, RssItem

    with app.app_context():
        feed = RssFeed.query.get(feed_id)
        if not feed or not feed.is_active:
            return 0
        url = feed.url

        try:
            content = _fetch_feed(url)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            feed.last_error = f'fetch failed: {exc}'
            feed.last_fetched_at = datetime.utcnow()
            db.session.commit()
            logger.warning('RSS fetch failed for %s: %s', feed.name, exc)
            return 0

        try:
            parsed = feedparser.parse(content)
        except Exception as exc:  # pylint: disable=broad-except
            feed.last_error = f'parse failed: {exc}'
            feed.last_fetched_at = datetime.utcnow()
            db.session.commit()
            logger.warning('RSS parse failed for %s: %s', feed.name, exc)
            return 0

        if parsed.bozo and not parsed.entries:
            feed.last_error = f'parse failed: {parsed.bozo_exception!r}'
            feed.last_fetched_at = datetime.utcnow()
            db.session.commit()
            logger.warning('RSS parse failed for %s: %s', feed.name,
                           parsed.bozo_exception)
            return 0

        # Pull site_url from the parsed feed if not set
        if not feed.site_url:
            site_link = parsed.feed.get('link') or ''
            if site_link:
                feed.site_url = site_link[:500]

        added = 0
        for entry in parsed.entries[:200]:   # cap at 200 per fetch
            guid = (entry.get('id')
                    or entry.get('guid')
                    or entry.get('link')
                    or entry.get('title') or '')[:500]
            if not guid:
                continue
            if RssItem.query.filter_by(feed_id=feed.id, guid=guid).first():
                continue
            html = _get_content_html(entry)
            raw_link = (entry.get('link') or '')[:1000]
            item = RssItem(
                feed_id=feed.id,
                guid=guid,
                title=(entry.get('title') or '')[:500],
                link=raw_link if _is_safe_http_url(raw_link) else '',
                author=(entry.get('author') or '')[:200] or None,
                summary=_strip_html(entry.get('summary') or '')[:4000] or None,
                content_html=html,
                image_url=_extract_image_url(entry, html),
                published_at=_parse_published(entry),
            )
            db.session.add(item)
            added += 1

        feed.last_fetched_at = datetime.utcnow()
        feed.last_error = None
        try:
            db.session.commit()
        except Exception as exc:  # pylint: disable=broad-except
            db.session.rollback()
            logger.warning('RSS commit failed for %s: %s', feed.name, exc)
            return 0
        if added:
            logger.info('RSS: %s — %d new item(s)', feed.name, added)
        return added


def _get_content_html(entry):
    """Extract the best-available HTML body from a feedparser entry."""
    contents = entry.get('content') or []
    if contents and isinstance(contents, list):
        for c in contents:
            value = c.get('value') if hasattr(c, 'get') else None
            if value:
                return value[:32000]
    summary = entry.get('summary') or ''
    if '<' in summary:
        return summary[:32000]
    return None


def _is_safe_http_url(url):
    """Reject anything that isn't a plain http(s) URL.

    Real Medium finding from a security/performance audit
    (2026-09-02): RssItem.link/image_url are rendered directly into
    href=/src= attributes with no scheme validation
    (anetbbs/templates/rss/item.html, feed.html, river.html) -- unlike
    this app's own board-post linkifier (web/render_msg.py's
    _linkify()), which only ever linkifies https?://. Both columns
    come straight from external, publisher-controlled feed content
    (not the sysop) with no allowlist. A malicious or compromised feed
    could set an item's link to a javascript: URI; a logged-in user
    clicking the article link would execute it same-origin. Applied at
    ingest time here so every template rendering RssItem.link/
    image_url is protected without needing its own copy of this check.
    """
    try:
        from urllib.parse import urlparse
        return urlparse((url or '').strip()).scheme in ('http', 'https')
    except Exception:
        return False


def _extract_image_url(entry, content_html):
    """Return the first image URL associated with this feed entry, or None."""
    # 1. media:thumbnail (e.g. YouTube, Flickr)
    thumbs = getattr(entry, 'media_thumbnail', None) or []
    for t in thumbs:
        url = (t.get('url') if hasattr(t, 'get') else None) or ''
        if url and _is_safe_http_url(url):
            return url[:1000]
    # 2. media:content with image/* type
    media = getattr(entry, 'media_content', None) or []
    for m in media:
        if not hasattr(m, 'get'):
            continue
        if m.get('type', '').startswith('image/'):
            url = m.get('url', '') or ''
            if url and _is_safe_http_url(url):
                return url[:1000]
    # 3. enclosures
    for enc in getattr(entry, 'enclosures', []):
        if not hasattr(enc, 'get'):
            continue
        if enc.get('type', '').startswith('image/'):
            url = enc.get('href', '') or enc.get('url', '') or ''
            if url and _is_safe_http_url(url):
                return url[:1000]
    # 4. first <img src> in HTML body
    if content_html:
        m = re.search(r'<img[^>]+src=["\']([^"\']{8,})', content_html, re.IGNORECASE)
        if m and _is_safe_http_url(m.group(1)):
            return m.group(1)[:1000]
    return None


def _prune_old_items(app):
    """Delete RssItem rows older than the retention window.

    Real gap found in a security/performance audit: nothing ever
    pruned RssItem -- every poll cycle (default every 30 minutes) can
    add up to 200 new items per active feed, deduped by (feed_id,
    guid) so no duplicate re-inserts, but old items just accumulate
    forever. Over a long-running install with several active feeds,
    this table grows unboundedly, slowing its own queries/indexes down
    over time along with routine backups. RSS_ITEM_RETENTION_DAYS
    (env var, default 90) bounds it -- same env-var-override
    convention as RSS_POLL_INTERVAL above.

    RssReadStatus.item_id has ondelete='CASCADE' declared in the model,
    but that's only enforced by the DB engine itself if SQLite foreign-
    key enforcement is turned on (PRAGMA foreign_keys=ON) -- this
    project never sets that -- AND a bulk .delete() query bypasses
    SQLAlchemy's own ORM-level relationship cascade regardless (that
    only fires for objects deleted via db.session.delete(obj), not a
    bulk query). Deletes matching RssReadStatus rows explicitly first
    so pruning an item can't leave orphaned read-marker rows behind.
    """
    from ..models import db, RssItem, RssReadStatus
    try:
        days = int(os.environ.get('RSS_ITEM_RETENTION_DAYS', '90'))
    except ValueError:
        days = 90
    if days <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(days=days)
    with app.app_context():
        try:
            stale_ids = [
                row[0] for row in
                db.session.query(RssItem.id).filter(
                    db.or_(
                        db.and_(RssItem.published_at.isnot(None),
                               RssItem.published_at < cutoff),
                        db.and_(RssItem.published_at.is_(None),
                               RssItem.fetched_at < cutoff),
                    )
                ).all()
            ]
            if not stale_ids:
                return
            (RssReadStatus.query
             .filter(RssReadStatus.item_id.in_(stale_ids))
             .delete(synchronize_session=False))
            (RssItem.query
             .filter(RssItem.id.in_(stale_ids))
             .delete(synchronize_session=False))
            db.session.commit()
            logger.info('RSS: pruned %d item(s) older than %d days',
                       len(stale_ids), days)
        except Exception as exc:  # pylint: disable=broad-except
            db.session.rollback()
            logger.warning('RSS item pruning failed: %s', exc)


def fetch_one_now(feed_id):
    """Trigger an immediate fetch for one feed. Used by admin ‘refresh’
    button and the add-feed flow so users see items right away.
    Returns count of new items."""
    from flask import current_app
    try:
        app = current_app._get_current_object()
    except Exception:
        return 0
    return _import_one_feed(app, feed_id)


def _poll_loop(app, interval):
    logger.info('RSS poller loop started — interval %ds', interval)
    # Slight initial delay so first run doesn't race app startup.
    _stop_event.wait(15)
    while not _stop_event.is_set():
        try:
            from ..models import RssFeed
            with app.app_context():
                feed_ids = [f.id for f in RssFeed.query.filter_by(
                    is_active=True).all()]
            for fid in feed_ids:
                if _stop_event.is_set():
                    break
                try:
                    _import_one_feed(app, fid)
                except Exception as exc:  # pylint: disable=broad-except
                    logger.exception('RSS poller: feed %d crashed: %s',
                                     fid, exc)
            if not _stop_event.is_set():
                _prune_old_items(app)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception('RSS poller loop error: %s', exc)
        # Wait until next tick. Wakes early if app is shutting down.
        _stop_event.wait(interval)


def start_poller(app):
    """Start the RSS background poller. Idempotent — calling twice is safe."""
    global _thread
    if _thread and _thread.is_alive():
        return
    try:
        interval = int(os.environ.get('RSS_POLL_INTERVAL', '1800'))
    except ValueError:
        interval = 1800
    if interval < 60:
        interval = 60
    _stop_event.clear()
    _thread = threading.Thread(target=_poll_loop, args=(app, interval),
                                daemon=True, name='rss-poller')
    _thread.start()


def stop_poller():
    """Signal the poller thread to exit."""
    _stop_event.set()
