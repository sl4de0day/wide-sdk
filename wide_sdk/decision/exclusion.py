import math
from typing import List, Tuple

class ClaimTable:
    def __init__(self, slots_count: int) -> None:
        if slots_count < 1:
            raise ValueError("slots_count must be at least 1")
        self.slots_count = slots_count
        self.holders: List[int] = [0] * slots_count
        self.expiration_times: List[float] = [0.0] * slots_count
        self.bids: List[float] = [0.0] * slots_count

    @property
    def slots(self) -> int:
        return self.slots_count

    def occupancy(self, now: float) -> int:
        return sum(1 for i in range(self.slots_count) if self.holders[i] != 0 and now < self.expiration_times[i])

    def try_claim(self, holder_id: int, bid: float, lifetime: float, now: float, capacity: int) -> bool:
        if holder_id == 0 or capacity < 1 or lifetime <= 0.0:
            return False

        for i in range(self.slots_count):
            if self.holders[i] == holder_id:
                self.expiration_times[i] = now + lifetime
                self.bids[i] = bid
                return True

        used = 0
        free_index = -1
        weakest_index = -1
        weakest_bid = math.inf

        for i in range(self.slots_count):
            live = self.holders[i] != 0 and now < self.expiration_times[i]
            if not live:
                if free_index < 0:
                    free_index = i
                continue
            used += 1
            if self.bids[i] < weakest_bid:
                weakest_bid = self.bids[i]
                weakest_index = i

        if used < capacity and free_index >= 0:
            self.holders[free_index] = holder_id
            self.expiration_times[free_index] = now + lifetime
            self.bids[free_index] = bid
            return True

        if weakest_index >= 0 and bid > weakest_bid:
            self.holders[weakest_index] = holder_id
            self.expiration_times[weakest_index] = now + lifetime
            self.bids[weakest_index] = bid
            return True

        return False

    def release(self, holder_id: int) -> None:
        for i in range(self.slots_count):
            if self.holders[i] == holder_id:
                self.holders[i] = 0
                self.expiration_times[i] = 0.0
                self.bids[i] = 0.0


class PartitionAssignment:
    def __init__(self, partitions_count: int) -> None:
        if partitions_count < 1:
            raise ValueError("partitions_count must be at least 1")
        self.partitions_count = partitions_count
        self.assignments: List[int] = [0] * partitions_count
        self.expiration_times: List[float] = [0.0] * partitions_count

    def try_assign(self, agent_id: int, preferred: int, lifetime: float, now: float) -> Tuple[bool, int]:
        if agent_id == 0 or lifetime <= 0.0:
            return False, -1

        for i in range(self.partitions_count):
            if self.assignments[i] == agent_id and now < self.expiration_times[i]:
                self.expiration_times[i] = now + lifetime
                return True, i

        norm_pref = ((preferred % self.partitions_count) + self.partitions_count) % self.partitions_count

        for step in range(self.partitions_count // 2 + 1):
            candidates = [norm_pref] if step == 0 else [
                (norm_pref + step) % self.partitions_count,
                ((norm_pref - step) % self.partitions_count + self.partitions_count) % self.partitions_count
            ]
            for c in candidates:
                live = self.assignments[c] != 0 and now < self.expiration_times[c]
                if not live:
                    self.assignments[c] = agent_id
                    self.expiration_times[c] = now + lifetime
                    return True, c

        return False, -1

    def release(self, agent_id: int) -> None:
        for i in range(self.partitions_count):
            if self.assignments[i] == agent_id:
                self.assignments[i] = 0
                self.expiration_times[i] = 0.0
