import math
from enum import Enum
from typing import List

class BarrierBudget(Enum):
    Patient = 0
    Measured = 1
    Hasty = 2
    Immediate = 3

class SynchronizationBarrier:
    def __init__(self, capacity: int = 16) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.capacity = capacity
        self.agent_ids: List[int] = [0] * capacity
        self.ready_states: List[bool] = [False] * capacity
        self.report_times: List[float] = [0.0] * capacity
        self.quorum_reached = False
        self.stage_start_time = 0.0

    @property
    def reached_quorum(self) -> bool:
        return self.quorum_reached

    def report_ready(self, agent_id: int, now: float) -> None:
        if agent_id == 0:
            return
        for i in range(self.capacity):
            if self.agent_ids[i] == agent_id or self.agent_ids[i] == 0:
                self.agent_ids[i] = agent_id
                self.ready_states[i] = True
                self.report_times[i] = now
                return

    def tick(self, population: int, quorum_threshold: float = 0.6, timeout_seconds: float = 10.0, now: float = 0.0) -> bool:
        if population < 1:
            return False
        required = math.ceil(population * quorum_threshold)

        ready_count = sum(1 for i in range(self.capacity) if self.agent_ids[i] != 0 and self.ready_states[i])

        if self.stage_start_time == 0.0:
            self.stage_start_time = now

        if ready_count >= required:
            self.quorum_reached = True
            return True

        if (now - self.stage_start_time) >= timeout_seconds:
            self.quorum_reached = False
            return True

        return False

    def reset(self) -> None:
        self.agent_ids = [0] * self.capacity
        self.ready_states = [False] * self.capacity
        self.report_times = [0.0] * self.capacity
        self.quorum_reached = False
        self.stage_start_time = 0.0
