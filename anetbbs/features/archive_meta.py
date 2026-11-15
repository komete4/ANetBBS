"""
Extract a human-readable description from an uploaded archive.

Pulls FILE_ID.DIZ if present (the BBS-standard short description, max
~10 lines × 45 chars), then falls back to README.* / DESCRIPT.ION /
.txt files in the root of the archive.

Extracts descriptions from ZIP and TAR. On Linux, it also supports
7z, RAR and LHA with bsdtar and prlimit. Returns an empty string when
no description is available.
"""
import logging
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import zipfile
from collections import namedtuple

logger = logging.getLogger(__name__)

# Mirrors virus_scan.py's ScanResult shape.
ArchiveTestResult = namedtuple('ArchiveTestResult', ['ok', 'message'])

# Filenames searched in priority order. Case-insensitive.
DESCRIPTION_CANDIDATES = (
    'FILE_ID.DIZ',
    'file_id.diz',
    'FILEID.DIZ',
    'README.MD',
    'README.md',
    'README.TXT',
    'README.txt',
    'README',
    'readme.txt',
    'readme.md',
    'readme',
    'DESCRIPT.ION',
    'descript.ion',
    'INFO.TXT',
    'info.txt',
)

# Cap the extracted text — descriptions over a few KB aren't really
# descriptions, they're docs. The BBS file gallery wants a short blurb.
MAX_DESCRIPTION_BYTES = 4096

# Real vulnerability found in a security/performance audit:
# test_archive_integrity() below used to hand every member straight to
# zf.testzip()/a full read-through loop with no size check at all --
# exactly the operation a decompression bomb (a small compressed file
# whose header declares/produces a wildly disproportionate amount of
# decompressed output, e.g. classic 42.zip-style payloads) is built to
# abuse. This runs on every uploaded file (web/files.py, web/
# file_areas.py) before an upload is accepted, so any user with upload
# access could hang/exhaust a request thread for minutes deflating a
# bomb well within the existing 100MB UPLOAD_MAX_SIZE. A zip's central
# directory declares each member's uncompressed size without needing to
# decompress anything to read it, and a tar member's header size is what
# actually bounds how many bytes extractfile().read() can ever produce
# for that member -- so both are checked against this cap BEFORE paying
# for (or, for zip, at all avoiding) the decompression.
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024  # 1GiB

_OPTIONAL_ARCHIVE_SUFFIXES = ('.7z', '.rar', '.lzh', '.lha')
_DECODER_SECONDS = 10
_MAX_LISTING_BYTES = 1024 * 1024
_MAX_TAR_MEMBERS = 10_000


class _DecoderLimit(ValueError):
    pass


def _bounded_archive_command(path, mode, max_bytes, match=None, retain=True):
    """Read bounded output from a resource-limited libarchive subprocess."""
    if sys.platform != 'linux':
        return None
    bsdtar = shutil.which('bsdtar')
    prlimit = shutil.which('prlimit')
    if not bsdtar or not prlimit:
        return None
    args = [prlimit, '--as=536870912', '--cpu=5:6', '--core=0', '--', bsdtar,
            mode, '-f', os.path.abspath(path)]
    if match is not None:
        args.extend(('--', match))
    deadline = time.monotonic() + _DECODER_SECONDS
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as proc:
        try:
            output = bytearray()
            remaining_bytes = max_bytes
            with selectors.DefaultSelector() as ready:
                ready.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0 or not ready.select(remaining_time):
                        raise _DecoderLimit('Archive inspection exceeded its time limit.')
                    chunk = os.read(proc.stdout.fileno(), min(65536, remaining_bytes + 1))
                    if not chunk:
                        break
                    remaining_bytes -= len(chunk)
                    if remaining_bytes < 0:
                        raise _DecoderLimit('Archive inspection exceeded its output limit.')
                    if retain:
                        output.extend(chunk)
            if proc.wait(timeout=max(0, deadline - time.monotonic())):
                raise _DecoderLimit('Archive decoder failed or exceeded its resource limits.')
            return bytes(output)
        except subprocess.TimeoutExpired as exc:
            raise _DecoderLimit('Archive inspection exceeded its time limit.') from exc
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def extract_archive_description(path):
    """Return a description string pulled from the archive at *path*.

    Returns '' if the file isn't a recognized archive, or if no
    description-style file is present, or on any extraction error.
    """
    if not os.path.isfile(path):
        return ''
    name_lower = path.lower()
    try:
        if name_lower.endswith(_OPTIONAL_ARCHIVE_SUFFIXES):
            listing = _bounded_archive_command(path, '-t', _MAX_LISTING_BYTES)
            if not listing:
                return ''
            match = _find_match(listing.decode('utf-8', errors='replace').splitlines())
            if match:
                data = _bounded_archive_command(path, '-xO', MAX_DESCRIPTION_BYTES, match)
                return _decode(data, match)
            return ''
        if zipfile.is_zipfile(path):
            return _extract_from_zip(path)
        if tarfile.is_tarfile(path) or name_lower.endswith(
                ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2',
                 '.tar.xz', '.txz')):
            return _extract_from_tar(path)
    except _DecoderLimit:
        return ''
    except Exception:
        logger.exception('archive description extraction failed for %s', path)
    return ''


def test_archive_integrity(path):
    """Test whether the archive at *path* is internally consistent.

    Returns an ArchiveTestResult. `ok=True` covers three distinct cases a
    caller should treat the same way (let the upload through): the
    archive tested clean, the format is excluded from automatic inspection,
    or the file is not a recognized archive.
    """
    if not os.path.isfile(path):
        return ArchiveTestResult(True, 'file not found')
    name_lower = path.lower()
    try:
        if name_lower.endswith(_OPTIONAL_ARCHIVE_SUFFIXES):
            output = _bounded_archive_command(
                path, '-xO', MAX_ARCHIVE_UNCOMPRESSED_BYTES, retain=False)
            if output is None:
                return ArchiveTestResult(True, 'not tested (bounded decoder not available)')
            return ArchiveTestResult(True, 'clean')
        if zipfile.is_zipfile(path):
            return _test_zip(path)
        if tarfile.is_tarfile(path) or name_lower.endswith(
                ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2',
                 '.tar.xz', '.txz')):
            return _test_tar(path)
    except _DecoderLimit as exc:
        return ArchiveTestResult(False, str(exc))
    except Exception as exc:
        logger.exception('archive integrity test crashed for %s', path)
        return ArchiveTestResult(True, f'test crashed, allowing through: {exc}')
    return ArchiveTestResult(True, 'not a recognized archive format')


def _test_zip(path):
    with zipfile.ZipFile(path, 'r') as zf:
        # Declared uncompressed size, straight from the central
        # directory -- free to read, no decompression required. Check
        # it BEFORE testzip() below ever touches the compressed data.
        total = sum(info.file_size for info in zf.infolist())
        if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            return ArchiveTestResult(
                False,
                f'archive declares {total:,} bytes uncompressed (over the '
                f'{MAX_ARCHIVE_UNCOMPRESSED_BYTES:,}-byte test limit) -- '
                f'refusing to test, possible decompression bomb')
        bad = zf.testzip()
    if bad is not None:
        return ArchiveTestResult(False, f'corrupt member: {bad}')
    return ArchiveTestResult(True, 'clean')


def _test_tar(path):
    """Check declared sizes as TAR headers arrive, before reading member data."""
    with tarfile.open(path, 'r|*') as tf:
        for member in _bounded_tar_members(tf):
            if not member.isfile():
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            try:
                while fh.read(65536):
                    pass
            except (tarfile.TarError, OSError) as exc:
                return ArchiveTestResult(False, f'corrupt member {member.name}: {exc}')
    return ArchiveTestResult(True, 'clean (best-effort read-through, tar has no CRC test)')


def _bounded_tar_members(tf):
    total = 0
    for count, member in enumerate(tf, 1):
        total += max(0, member.size)
        if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise _DecoderLimit(
                f'archive declares over {MAX_ARCHIVE_UNCOMPRESSED_BYTES:,} '
                'bytes uncompressed -- refusing to test, possible decompression bomb')
        if count > _MAX_TAR_MEMBERS:
            raise _DecoderLimit('Archive contains too many entries to inspect.')
        yield member


# ---------------------------------------------------------------------------
# Format-specific extractors
# ---------------------------------------------------------------------------

def _extract_from_zip(path):
    with zipfile.ZipFile(path, 'r') as zf:
        names = zf.namelist()
        match = _find_match(names)
        if not match:
            return ''
        with zf.open(match) as fh:
            data = fh.read(MAX_DESCRIPTION_BYTES + 1)
    return _decode(data, match)


def _extract_from_tar(path):
    best = None
    data = b''
    with tarfile.open(path, 'r|*') as tf:
        for member in _bounded_tar_members(tf):
            if not member.isfile():
                continue
            candidates = [member.name] if best is None else [best, member.name]
            if _find_match(candidates) != member.name:
                continue
            fh = tf.extractfile(member)
            if fh is not None:
                with fh:
                    data = fh.read(MAX_DESCRIPTION_BYTES + 1)
                best = member.name
    return _decode(data, best) if best else ''


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_match(names):
    """Find the highest-priority candidate file among *names*.

    *names* is the list of filenames inside the archive (may include
    directory paths). We match the basename, case-insensitive, and prefer
    files at the archive root over deeply nested ones.
    """
    by_priority = {n.lower(): i for i, n in enumerate(DESCRIPTION_CANDIDATES)}

    best = None
    best_pri = len(DESCRIPTION_CANDIDATES) + 1
    best_depth = 999

    for n in names:
        base = os.path.basename(n).lower()
        if base not in by_priority:
            continue
        pri = by_priority[base]
        depth = n.count('/') + n.count('\\')
        # Prefer lower priority number first, then shallower depth
        if (pri < best_pri) or (pri == best_pri and depth < best_depth):
            best = n
            best_pri = pri
            best_depth = depth
    return best


def _decode(data, source_name):
    """Decode archive contents (CP437 by default — BBS files predate UTF-8;
    fall back to UTF-8/latin-1 if it's clearly not CP437). Trim and cap."""
    if not data:
        return ''
    # Newer files (README.md from a github archive) are usually utf-8
    if source_name.lower().endswith('.md'):
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('cp437', errors='replace')
    else:
        try:
            text = data.decode('cp437', errors='replace')
        except Exception:
            text = data.decode('latin-1', errors='replace')

    # Strip trailing nulls / whitespace
    text = text.rstrip('\x00 \r\n\t')
    if len(text) > MAX_DESCRIPTION_BYTES:
        text = text[:MAX_DESCRIPTION_BYTES].rstrip()
    return text
