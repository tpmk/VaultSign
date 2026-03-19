# src/vaultsign/state.py
"""Signer state machine.

States: INIT -> LOCKED -> UNLOCKED -> STOPPED
                 ^           |
                 |   lock/TTL|
                 +-----------+
        Any -> ERROR -> LOCKED | STOPPED
"""

from enum import Enum

from .errors import SignerLockedError, SignerStateError


class SignerState(Enum):
    INIT = "init"
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    ERROR = "error"
    STOPPED = "stopped"


# Valid transitions: {from_state: {allowed_to_states}}
_TRANSITIONS: dict[SignerState, set[SignerState]] = {
    SignerState.INIT: {SignerState.LOCKED, SignerState.ERROR, SignerState.STOPPED},
    SignerState.LOCKED: {SignerState.UNLOCKED, SignerState.ERROR, SignerState.STOPPED},
    SignerState.UNLOCKED: {SignerState.LOCKED, SignerState.ERROR, SignerState.STOPPED},
    SignerState.ERROR: {SignerState.LOCKED, SignerState.STOPPED},
    SignerState.STOPPED: set(),  # terminal
}


class SignerStateMachine:
    def __init__(self):
        self._state = SignerState.INIT

    @property
    def state(self) -> SignerState:
        return self._state

    def transition_to(self, new_state: SignerState) -> None:
        allowed = _TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            raise SignerStateError(
                f"Invalid transition: {self._state.value} -> {new_state.value}"
            )
        self._state = new_state

    def require_unlocked(self) -> None:
        if self._state != SignerState.UNLOCKED:
            raise SignerLockedError("Signer is locked")
