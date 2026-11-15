"""Stage uploads privately on the destination filesystem and publish atomically."""

import errno
import logging
import os
import shutil
import tempfile
from contextlib import contextmanager


STAGING_DIR = '.anetbbs-upload'
logger = logging.getLogger(__name__)


class UploadRejected(ValueError):
    pass


def is_staging_path(path):
    return STAGING_DIR in path.replace('\\', '/').split('/')


def file_identity(path):
    entry = os.lstat(path)
    return f'{entry.st_dev}:{entry.st_ino}:{entry.st_ctime_ns}'


def open_staged_upload(dest):
    directory = os.path.join(os.path.dirname(dest), STAGING_DIR)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.islink(directory):
        raise OSError('Upload staging directory must not be a symlink.')
    # Some archive detectors use the filename extension.
    return tempfile.NamedTemporaryFile(
        mode='wb', dir=directory, suffix=os.path.splitext(dest)[1], delete=False)


def check_staged_upload(path):
    from .archive_meta import test_archive_integrity
    from .virus_scan import scan_path

    virus = scan_path(path)
    if virus.infected:
        raise UploadRejected(f'Virus detected ({virus.signature}).')
    archive = test_archive_integrity(path)
    if not archive.ok:
        raise UploadRejected(f'Corrupt archive ({archive.message}).')


@contextmanager
def stage_upload(dest):
    staged = open_staged_upload(dest)
    try:
        yield staged
    finally:
        staged.close()
        try:
            os.unlink(staged.name)
        except FileNotFoundError:
            pass
        except OSError:
            logger.exception('Could not remove staged upload')


def save_new_upload(upload, dest):
    with stage_upload(dest) as staged:
        with staged:
            upload.save(staged)
        check_staged_upload(staged.name)
        # Unlike rename/replace, this fails atomically if the name exists.
        os.link(staged.name, dest)


def publish_received_upload(path, dest):
    """Publish a completed receive without replacing an existing name."""
    try:
        os.link(path, dest)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    with stage_upload(dest) as staged:
        with staged, open(path, 'rb') as source:
            shutil.copyfileobj(source, staged)
        os.link(staged.name, dest)


def approve_queued_upload(path, folder, filename, entry_id):
    """Recheck the quarantined bytes and publish without replacing an existing file."""
    name = os.path.basename(filename)
    if not name or name.startswith('.'):
        raise UploadRejected('Invalid filename.')
    dest = os.path.join(folder, name)
    with stage_upload(dest) as staged:
        with staged, open(path, 'rb') as source:
            shutil.copyfileobj(source, staged)
        check_staged_upload(staged.name)
        try:
            os.link(staged.name, dest)
        except FileExistsError:
            base, ext = os.path.splitext(name)
            dest = os.path.join(folder, f'{base}-{entry_id}{ext}')
            os.link(staged.name, dest)
    return dest
