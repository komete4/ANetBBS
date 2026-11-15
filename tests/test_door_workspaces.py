"""The compatibility copy uses the real game directory as its lock domain."""

import pytest


def test_game_directory_stays_exclusive_while_another_game_can_launch(tmp_path):
    from anetbbs.games.door_runner import DoorWorkspaceBusy, _DoorWorkspace

    game = tmp_path / 'game'
    other_game = tmp_path / 'other'
    first = _DoorWorkspace(tmp_path / 'session-one')
    second = _DoorWorkspace(tmp_path / 'session-two')
    independent = _DoorWorkspace(tmp_path / 'session-three')
    try:
        first.lock([game])
        with pytest.raises(DoorWorkspaceBusy):
            second.lock([game])
        independent.lock([other_game])
    finally:
        first.close()
        second.close()
        independent.close()
    second.lock([game])
    second.close()


def test_cleanup_removes_session_drop_without_touching_game_state(tmp_path):
    from anetbbs.games.door_runner import _DoorWorkspace

    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    source = scratch / 'DOOR.SYS'
    source.write_text('session metadata')
    game = tmp_path / 'game'
    workspace = _DoorWorkspace(scratch)
    workspace.lock([game])
    state = game / 'GAME.DAT'
    state.write_text('persistent game data')
    drop = game / 'DOOR.SYS'
    try:
        workspace.publish_drop_file(source, drop)
        assert drop.read_text() == 'session metadata'
    finally:
        workspace.close()
    assert state.read_text() == 'persistent game data'
    assert not drop.exists()
    assert not scratch.exists()
