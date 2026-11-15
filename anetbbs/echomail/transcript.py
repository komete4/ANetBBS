"""Redact passwords from BinkP transcripts that predate frame redaction."""

import re

from sqlalchemy import or_, select, update

from ..models import EchomailPollLog

_TIMESTAMP = r'^\d\d:\d\d:\d\d\.\d+ '
_FRAME = re.compile(_TIMESTAMP)
_PASSWORD = re.compile(_TIMESTAMP + r'(?:>>|<<) CMD PWD(?::|$)')
_TRUNCATED = '...transcript truncated to last '


def redact_legacy_transcript(transcript):
    if not transcript:
        return transcript
    lines = transcript.split('\n')
    result = []
    # A legacy size cap may have cut the timestamp and command off a
    # password line. Discard any unframed prefix after the cap's marker.
    skipping = lines[0].startswith(_TRUNCATED)
    if skipping:
        result.append(lines.pop(0))
    for line in lines:
        password = _PASSWORD.match(line)
        if password:
            result.append(line[:password.end()].rstrip(':') + ': [redacted]')
            skipping = True
        elif _FRAME.match(line):
            skipping = False
            result.append(line)
        elif not skipping:
            result.append(line)
    return '\n'.join(result)


def redact_stored_transcripts(engine):
    """Update legacy rows in short transactions, without touching history metadata."""
    table = EchomailPollLog.__table__
    last_id = 0
    updated = 0
    while True:
        with engine.begin() as conn:
            if conn.dialect.name == 'sqlite':
                # SQLite ignores FOR UPDATE. Get a write lock before reading
                # so a poll checkpoint cannot interleave with a redaction.
                conn.exec_driver_sql('BEGIN IMMEDIATE')
            statement = (select(table.c.id, table.c.transcript)
                         .where(table.c.id > last_id, or_(
                             table.c.transcript.contains('CMD PWD:'),
                             table.c.transcript.startswith(_TRUNCATED)))
                         .order_by(table.c.id).limit(128).with_for_update())
            batch = conn.execute(statement).all()
            for row_id, transcript in batch:
                redacted = redact_legacy_transcript(transcript)
                if redacted != transcript:
                    conn.execute(update(table).where(table.c.id == row_id)
                                 .values(transcript=redacted))
                    updated += 1
            if len(batch) < 128:
                return updated
            last_id = batch[-1][0]
