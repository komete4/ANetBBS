"""Regression tests for a real bug found in a follow-up security/
performance audit: door_dos and door_dosemu games fail with a silent
or cryptic error when their own install directory isn't writable --
the exact same EROFS failure class root-caused live for a door_native
game's storage (ANetSlots, 2026-11-01), now confirmed to also affect
these two emulator-backed game types, which both write into their own
game_dir (a drop-file copy, and often the door's own save/score
state) with no way to redirect that via an env var the way a
door_native game can with BBS_DOOR_DATA_DIR.

Two fixes covered here:

1. anetbbs/games/door_runner.py's _build_dosemu_command() used to
   write its own generated _ANET.BAT launcher script directly into
   game_dir (the door's install directory) -- even though that file
   is ANetBBS's own generated content, not game data, with no reason
   to live anywhere but the per-node scratch dir, which is always
   writable. Fixed: it's now written into the per-node scratch dir
   (dosemu2's `I:`) instead, with `-E` updated to match.

2. Both _build_dos_command() and _build_dosemu_command() now probe-
   write into game_dir up front and raise a clear PermissionError
   (naming the actual fix: move the game under data/, or widen
   ReadWritePaths) instead of letting DOSBox/dosemu2 fail silently or
   cryptically deep inside a generated autoexec/batch script.
"""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_IS_ROOT = os.geteuid() == 0


def _make_game(exe_path, game_type='door_dos', slug='testdoor'):
    return SimpleNamespace(
        game_type=game_type,
        slug=slug,
        executable_path=exe_path,
        working_directory='',
        command_line_args='',
        needs_fossil_driver=False,
    )


class DosemuBatLocationTests(unittest.TestCase):
    def test_bat_written_to_scratch_dir_not_game_dir(self):
        from anetbbs.games.door_runner import _build_dosemu_command
        from anetbbs.games.node_paths import node_dir

        with tempfile.TemporaryDirectory() as game_dir:
            exe_path = os.path.join(game_dir, 'GAME.EXE')
            with open(exe_path, 'w') as f:
                f.write('fake')
            os.chmod(exe_path, 0o755)

            game = _make_game(exe_path, game_type='door_dosemu')
            cmd, returned_game_dir = _build_dosemu_command(
                game, node_number=1, dosemu_path='/usr/bin/dosemu')

            self.assertEqual(returned_game_dir, game_dir)
            bat_in_game_dir = os.path.join(game_dir, '_ANET.BAT')
            self.assertFalse(
                os.path.exists(bat_in_game_dir),
                '_ANET.BAT must not be written into the (possibly '
                'read-only) game directory')

            scratch_dir = node_dir(1).rstrip(os.sep)
            bat_in_scratch = os.path.join(scratch_dir, '_ANET.BAT')
            self.assertTrue(
                os.path.isfile(bat_in_scratch),
                f'_ANET.BAT should be written to the per-node scratch '
                f'dir ({scratch_dir}), which is always writable')
            os.remove(bat_in_scratch)

            self.assertIn('-E', cmd)
            e_idx = cmd.index('-E')
            self.assertEqual(cmd[e_idx + 1], 'I:\\_ANET.BAT')

    def test_explicit_drive_order_with_game_directory_with_spaces(self):
        from anetbbs.games.door_runner import _build_dosemu_command

        with tempfile.TemporaryDirectory() as root:
            game_dir = Path(root) / 'DOS game'
            game_dir.mkdir()
            executable = game_dir / 'GAME.EXE'
            executable.touch()
            scratch = Path(root) / 'session'
            scratch.mkdir()
            game = _make_game(str(executable), game_type='door_dosemu')

            cmd, cwd = _build_dosemu_command(game, 1, '/usr/bin/dosemu',
                                             scratch=str(scratch))
            config = Path(cmd[cmd.index('-f') + 1]).read_text()
            hdimage = next(line for line in config.splitlines()
                           if line.startswith('$_hdimage'))
            paths = hdimage.split('"')[1].split()
            self.assertEqual(paths[:2], ['+0', '-3'])
            self.assertEqual(Path(paths[3]).resolve(), game_dir.resolve())
            self.assertEqual(Path(paths[4]), scratch)
            self.assertEqual(paths[5:], ['+1'])
            self.assertNotIn('-d', cmd)
            self.assertEqual(Path(cwd), game_dir)
            self.assertTrue((scratch / '_ANET.BAT').is_file())
            self.assertFalse((game_dir / '_ANET.BAT').exists())


@unittest.skipIf(_IS_ROOT, 'permission bits do not block root; cannot test EROFS-shaped failure')
class GameDirWritableCheckTests(unittest.TestCase):
    def test_dos_command_raises_clear_error_when_game_dir_not_writable(self):
        from anetbbs.games.door_runner import _build_dos_command

        with tempfile.TemporaryDirectory() as game_dir:
            exe_path = os.path.join(game_dir, 'GAME.EXE')
            with open(exe_path, 'w') as f:
                f.write('fake')
            os.chmod(exe_path, 0o755)
            os.chmod(game_dir, stat.S_IRUSR | stat.S_IXUSR)  # r-x, no write
            try:
                game = _make_game(exe_path, game_type='door_dos', slug='ro-dos-door')
                with self.assertRaises(PermissionError) as ctx:
                    _build_dos_command(game, node_number=1, cwd=game_dir)
                msg = str(ctx.exception)
                self.assertIn('ro-dos-door', msg)
                self.assertIn('not writable', msg)
                self.assertIn('ReadWritePaths', msg)
            finally:
                os.chmod(game_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def test_dosemu_command_raises_clear_error_when_game_dir_not_writable(self):
        from anetbbs.games.door_runner import _build_dosemu_command

        with tempfile.TemporaryDirectory() as game_dir:
            exe_path = os.path.join(game_dir, 'GAME.EXE')
            with open(exe_path, 'w') as f:
                f.write('fake')
            os.chmod(exe_path, 0o755)
            os.chmod(game_dir, stat.S_IRUSR | stat.S_IXUSR)  # r-x, no write
            try:
                game = _make_game(exe_path, game_type='door_dosemu', slug='ro-dosemu-door')
                with self.assertRaises(PermissionError) as ctx:
                    _build_dosemu_command(game, node_number=1, dosemu_path='/usr/bin/dosemu')
                msg = str(ctx.exception)
                self.assertIn('ro-dosemu-door', msg)
                self.assertIn('not writable', msg)
            finally:
                os.chmod(game_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def test_dos_command_succeeds_when_game_dir_writable(self):
        """Sanity check: the new probe-write doesn't break the normal
        (writable) case -- it creates and removes its own marker file
        and otherwise doesn't interfere with command building."""
        from anetbbs.games.door_runner import _build_dos_command

        with tempfile.TemporaryDirectory() as game_dir:
            exe_path = os.path.join(game_dir, 'GAME.EXE')
            with open(exe_path, 'w') as f:
                f.write('fake')
            os.chmod(exe_path, 0o755)

            game = _make_game(exe_path, game_type='door_dos', slug='rw-dos-door')
            cmd, returned_game_dir = _build_dos_command(game, node_number=1, cwd=game_dir)
            self.assertEqual(returned_game_dir, game_dir)
            self.assertEqual(os.listdir(game_dir), ['GAME.EXE'])


if __name__ == '__main__':
    unittest.main()
