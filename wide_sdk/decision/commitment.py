import math
from typing import List

class CommitmentGate:
    def __init__(self, states_count: int, min_dwell_time: float, default_cooldown: float = 0.0) -> None:
        if states_count < 1:
            raise ValueError("states_count must be at least 1")
        if min_dwell_time < 0.0:
            raise ValueError("min_dwell_time cannot be negative")

        self.states_count = states_count
        self.min_dwell_time = min_dwell_time
        self.cooldowns: List[float] = [default_cooldown] * states_count
        self.last_entries: List[float] = [-math.inf] * states_count
        self.exemptions: List[bool] = [False] * states_count
        self.current_state = 0
        self.entered_at_time = 0.0
        self.accepted_transitions = 0
        self.rejected_transitions = 0

    @property
    def state(self) -> int:
        return self.current_state

    @property
    def min_dwell(self) -> float:
        return self.min_dwell_time

    @property
    def accepted(self) -> int:
        return self.accepted_transitions

    @property
    def rejected(self) -> int:
        return self.rejected_transitions

    def set_cooldown(self, state: int, seconds: float) -> None:
        if 0 <= state < self.states_count:
            self.cooldowns[state] = seconds

    def set_exempt(self, state: int, exempt: bool) -> None:
        if 0 <= state < self.states_count:
            self.exemptions[state] = exempt

    def allowed(self, next_state: int, now: float) -> bool:
        if not (0 <= next_state < self.states_count):
            return False
        if next_state == self.current_state:
            return False
        if self.exemptions[next_state]:
            return True
        if self.cooldowns[next_state] > 0.0 and (now - self.last_entries[next_state]) < self.cooldowns[next_state]:
            return False
        return (now - self.entered_at_time) >= self.min_dwell_time

    def try_transition(self, next_state: int, now: float) -> bool:
        if not self.allowed(next_state, now):
            self.rejected_transitions += 1
            return False
        self.current_state = next_state
        self.entered_at_time = now
        self.last_entries[next_state] = now
        self.accepted_transitions += 1
        return True


class Commitment:
    def __init__(self, lifetime: float, lock_window: float) -> None:
        if lifetime <= 0.0:
            raise ValueError("lifetime must be positive")
        if lock_window < 0.0:
            raise ValueError("lock_window cannot be negative")

        self.lifetime = lifetime
        self.lock_window = lock_window
        self.adopted_at = -math.inf
        self.current_score = 0.0
        self.has_commitment = False

    @property
    def score(self) -> float:
        return self.current_score

    @property
    def committed(self) -> bool:
        return self.has_commitment

    def is_expired(self, now: float) -> bool:
        return not self.has_commitment or (now - self.adopted_at) >= self.lifetime

    def is_locked(self, now: float) -> bool:
        return self.has_commitment and (now - self.adopted_at) < self.lock_window

    def should_replace(self, challenger_score: float, margin: float, now: float) -> bool:
        if self.is_expired(now):
            return True
        if self.is_locked(now):
            return False
        return challenger_score >= (self.current_score + margin)

    def adopt(self, score: float, now: float) -> None:
        self.current_score = score
        self.adopted_at = now
        self.has_commitment = True

    def clear(self) -> None:
        self.has_commitment = False
        self.current_score = 0.0
        self.adopted_at = -math.inf
