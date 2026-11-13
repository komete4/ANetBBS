# anetbbs/mailer.py
"""
SMTP relay helper for ANetBBS.

Sends email via the sysop-configured relay server (SmtpConfig DB row).
Uses only Python stdlib smtplib — no extra deps.
Returns (ok: bool, error: str) so callers decide whether to flash/log.
"""
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

from flask import current_app, has_app_context

logger = logging.getLogger(__name__)


def _get_config():
    """Return the SmtpConfig row, or None if SMTP is disabled/unconfigured."""
    try:
        from .models import SmtpConfig
        cfg = SmtpConfig.query.first()
        if cfg and cfg.enabled and cfg.host and cfg.from_address:
            return cfg
    except Exception:
        pass
    return None


def smtp_enabled():
    """Fast check — True if SMTP relay is configured and enabled."""
    return _get_config() is not None


def _require_verified_tls():
    return has_app_context() and current_app.config.get('REGISTRATION_REQUIRE_VERIFIED_EMAIL', False)


def email_verify_enabled():
    """True if SMTP is ready AND email verification is turned on."""
    cfg = _get_config()
    return bool(cfg and cfg.email_verify_enabled
                and (not _require_verified_tls() or cfg.use_ssl or cfg.use_tls))


def send_email(to_address, subject, body_text, body_html=None):
    """Send one email via the configured SMTP relay.

    Args:
        to_address:  Recipient email address string.
        subject:     Subject line.
        body_text:   Plain-text body (always sent).
        body_html:   Optional HTML alternative body.

    Returns:
        (True, '') on success or (False, error_message) on failure.
    """
    cfg = _get_config()
    if not cfg:
        return False, 'SMTP relay not configured or disabled'
    require_verified_tls = _require_verified_tls()
    if require_verified_tls and not (cfg.use_ssl or cfg.use_tls):
        return False, 'The SMTP relay must use TLS'

    from_addr = cfg.from_address.strip()
    from_header = (f'{cfg.from_name} <{from_addr}>'
                   if cfg.from_name else from_addr)

    if body_html:
        msg = MIMEMultipart('alternative')
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
        msg.attach(MIMEText(body_html, 'html', 'utf-8'))
    else:
        msg = MIMEText(body_text, 'plain', 'utf-8')

    msg['Subject'] = subject
    msg['From'] = from_header
    msg['To'] = to_address

    try:
        tls_context = ssl.create_default_context() if require_verified_tls else None
        if cfg.use_ssl:
            server = smtplib.SMTP_SSL(cfg.host, cfg.port or 465, timeout=15, context=tls_context)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port or 587, timeout=15)
            if cfg.use_tls:
                server.ehlo()
                server.starttls(context=tls_context)
                server.ehlo()
        if cfg.username:
            server.login(cfg.username.strip(), cfg.password or '')
        server.sendmail(from_addr, [to_address], msg.as_string())
        server.quit()
        logger.info('Email sent to %s: %s', to_address, subject)
        return True, ''
    except Exception as exc:
        logger.warning('SMTP send failed to %s: %s', to_address, exc)
        return False, str(exc)


def _send_account_link(user, url, kind, subject, intro, action, expiry, ignore):
    from .features.i18n import translate

    bbs_name = current_app.config.get('BBS_NAME', 'This BBS')
    language = getattr(user, 'language', None) or 'en'
    prefix = f'mail.{kind}'
    subject = translate(f'{prefix}.subject', subject, _language=language, bbs=bbs_name)
    paragraphs = [
        translate('mail.greeting', 'Hi {name},', _language=language, name=user.username),
        translate(f'{prefix}.intro', intro, _language=language, bbs=bbs_name),
        translate(f'{prefix}.action', action, _language=language),
        url,
        translate(f'{prefix}.expiry', expiry, _language=language),
        translate(f'{prefix}.ignore', ignore, _language=language),
        translate('mail.signature', '— {bbs} Sysop', _language=language, bbs=bbs_name),
    ]
    link = escape(url)
    html = ''.join(
        f'<p><a href="{link}" style="font-size:1.1em;">{link}</a></p>'
        if index == 3 else f'<p>{escape(paragraph)}</p>'
        for index, paragraph in enumerate(paragraphs)
    )
    return send_email(user.email, subject, '\n\n'.join(paragraphs), html)


def send_verification_email(user, verify_url):
    """Send an email verification link to a newly registered user."""
    return _send_account_link(
        user, verify_url, 'verify',
        'Verify your email — {bbs}',
        'Thanks for registering at {bbs}!',
        'Please verify your email address by clicking the link below:',
        'This link expires in 24 hours.',
        'If you did not register, ignore this email.',
    )


def send_password_reset_email(user, reset_url):
    """Send a password reset link."""
    return _send_account_link(
        user, reset_url, 'reset',
        'Password reset — {bbs}',
        'A password reset was requested for your account at {bbs}.',
        'Click the link below to set a new password:',
        'This link expires in 2 hours.',
        'If you did not request a password reset, ignore this email.',
    )
