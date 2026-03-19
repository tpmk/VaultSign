# tests/test_state.py
import pytest

from vaultsign.state import SignerState, SignerStateMachine
from vaultsign.errors import SignerLockedError, SignerStateError


def test_initial_state():
    sm = SignerStateMachine()
    assert sm.state == SignerState.INIT


def test_init_to_locked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    assert sm.state == SignerState.LOCKED


def test_locked_to_unlocked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    assert sm.state == SignerState.UNLOCKED


def test_unlocked_to_locked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    sm.transition_to(SignerState.LOCKED)
    assert sm.state == SignerState.LOCKED


def test_unlocked_to_stopped():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    sm.transition_to(SignerState.STOPPED)
    assert sm.state == SignerState.STOPPED


def test_invalid_transition_raises():
    sm = SignerStateMachine()
    with pytest.raises(SignerStateError):
        sm.transition_to(SignerState.UNLOCKED)  # can't go INIT -> UNLOCKED


def test_error_to_locked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.ERROR)
    sm.transition_to(SignerState.LOCKED)
    assert sm.state == SignerState.LOCKED


def test_any_to_error():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    sm.transition_to(SignerState.ERROR)
    assert sm.state == SignerState.ERROR


def test_require_unlocked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    with pytest.raises(SignerLockedError):
        sm.require_unlocked()
    sm.transition_to(SignerState.UNLOCKED)
    sm.require_unlocked()  # should not raise
