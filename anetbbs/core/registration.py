"""Registration admission shared by the web and terminal entry points."""

import hashlib
import ipaddress
import random
import threading
import time
from datetime import datetime, timedelta

from flask import current_app

from ..models import RegistrationAttempt, db

REGISTER_LIMIT_COUNT = 3
REGISTER_LIMIT_WINDOW_MINUTES = 60


# In-memory country-lookup cache: ip -> (country_code, expiry_timestamp)
_geoip_cache: dict = {}
_geoip_lock = threading.Lock()
# Real gap found in a security/performance audit: entries here were
# written on every cache miss but never evicted -- expiry is only
# checked on READ, so a stale entry for an IP that never comes back
# just sits in the dict forever. On a long-running production process
# with BLOCKED_COUNTRIES set (this feature exists specifically to
# reject scanner/credential-stuffing traffic, so every distinct
# attacking source IP gets its own permanent entry), this is the same
# "quiet unbounded creep on a long-running worker" shape as the
# v1.0.21 incident, and structurally the same bug
# features/rate_limit.py's own _buckets dict already has a fix for
# (probabilistic sweep on write). Same pattern here.
_GEOIP_SWEEP_PROBABILITY = 500  # ~1-in-500 writes triggers a sweep


def _sweep_stale_geoip_entries():
    now = time.time()
    stale_ips = [ip for ip, (_country, expiry) in _geoip_cache.items()
                if expiry < now]
    for ip in stale_ips:
        del _geoip_cache[ip]


def _cidr_match(ip_str, cidr_list):
    """Return True if ip_str matches any entry in cidr_list (IP strings or CIDR strings)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in cidr_list:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if entry == ip_str:
                return True
    return False


def _ip_is_whitelisted(ip):
    """Return True if ip matches any IpWhitelist row."""
    if not ip:
        return False
    try:
        from ..models import IpWhitelist
        rows = IpWhitelist.query.with_entities(IpWhitelist.cidr).all()
        return _cidr_match(ip, [r.cidr for r in rows])
    except Exception:
        return False


def _ip_is_banned(ip):
    """Return True if `ip` matches any active IpBan row. Whitelisted IPs always return False."""
    if not ip:
        return False
    if _ip_is_whitelisted(ip):
        return False
    try:
        from ..models import IpBan
        # Real gap found in a security audit: this used to load EVERY
        # IpBan row ever created (expired ones included) on every
        # single login/registration request, then filter expiry in
        # Python. Because _auto_ban_ip() below inserts a new row every
        # time the login rate limiter trips, and a public BBS is a
        # routine target for scanners/credential-stuffing bots, this
        # table only grows -- and so did the per-request cost, the
        # same "quiet unbounded creep on a long-running worker" shape
        # as this project's own v1.0.21 production incident. Filtering
        # expiry in SQL means an expired row costs nothing once it's
        # actually expired, instead of being fetched and discarded
        # forever.
        now = datetime.utcnow()
        rows = (IpBan.query
                .filter(db.or_(IpBan.expires_at.is_(None), IpBan.expires_at >= now))
                .with_entities(IpBan.cidr).all())
        return _cidr_match(ip, [r.cidr for r in rows])
    except Exception:
        return False


def _ip_country_blocked(ip):
    """Return True if ip's country is in BLOCKED_COUNTRIES.
    Uses ip-api.com (free, no registration). Results cached in-memory for 1 hour.
    Fails open — returns False on any network error so a downed lookup never locks out users."""
    try:
        ip = str(ipaddress.ip_address(ip))
        blocked = current_app.config.get('BLOCKED_COUNTRIES', '')
        if not blocked:
            return False
        countries = {c.strip().upper() for c in blocked.split(',') if c.strip()}
        if not countries:
            return False

        now = time.time()
        with _geoip_lock:
            entry = _geoip_cache.get(ip)
            if entry and entry[1] > now:
                return entry[0] in countries

        import urllib.request, json as _json
        url = f'http://ip-api.com/json/{ip}?fields=countryCode'
        with urllib.request.urlopen(url, timeout=2) as resp:  # nosec B310 -- hardcoded ip-api.com host, only the query param varies
            data = _json.loads(resp.read())
        country = (data.get('countryCode') or '').upper()

        with _geoip_lock:
            _geoip_cache[ip] = (country, now + 3600)
            if random.randint(1, _GEOIP_SWEEP_PROBABILITY) == 1:
                _sweep_stale_geoip_entries()

        return country in countries
    except Exception:
        return False


def registration_block_reason(ip):
    if not current_app.config.get('REGISTRATION_OPEN', True):
        return 'auth.registration_closed', 'New account registration is currently closed.'
    if _ip_is_banned(ip):
        return 'auth.registration_ip_blocked', 'Registrations from your IP are not permitted.'
    if _ip_country_blocked(ip):
        return 'auth.registration_region_blocked', 'Registrations from your region are not permitted.'
    return None


def reserve_registration_attempt(ip, username='', user_agent=''):
    """Count one attempt before admitting work, and commit the reservation."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None

    if db.session.get_bind().dialect.name == 'postgresql':
        key = int.from_bytes(hashlib.sha256(ip.encode('ascii')).digest()[:8],
                             'big', signed=True)
        db.session.execute(db.select(db.func.pg_advisory_xact_lock(key)))

    attempt = RegistrationAttempt(
        ip_address=ip, username_attempted=username[:80], user_agent=user_agent[:255],
        success=False, error_reason='incomplete',
    )
    db.session.add(attempt)
    # SQLite serializes writers at the INSERT. PostgreSQL serializes writers
    # for this client IP using the transaction-scoped lock above.
    db.session.flush()
    recent = RegistrationAttempt.query.filter(
        RegistrationAttempt.ip_address == ip,
        RegistrationAttempt.created_at >= datetime.utcnow() - timedelta(
            minutes=REGISTER_LIMIT_WINDOW_MINUTES),
    ).count()
    if recent > REGISTER_LIMIT_COUNT:
        db.session.rollback()
        return None
    db.session.commit()
    return attempt
