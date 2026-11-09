from typing import List

class PluralityConsensus:
    def __init__(self, classes_count: int, capacity: int = 16, freshness_window: float = 6.0, min_votes_count: int = 1) -> None:
        if classes_count < 1:
            raise ValueError("classes_count must be at least 1")
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        if freshness_window <= 0.0:
            raise ValueError("freshness_window must be positive")
        if min_votes_count < 1:
            raise ValueError("min_votes_count must be at least 1")

        self.classes_count = classes_count
        self.capacity = capacity
        self.freshness_window = freshness_window
        self.min_votes_count = min_votes_count
        self.voter_ids: List[int] = [0] * capacity
        self.voter_classes: List[int] = [0] * capacity
        self.voter_times: List[float] = [0.0] * capacity
        self.tallies: List[int] = [0] * classes_count
        self.agreed_value = 0
        self.is_settled = False

    @property
    def value(self) -> int:
        return self.agreed_value

    @property
    def settled(self) -> bool:
        return self.is_settled

    def vote(self, voter_id: int, class_index: int, now: float) -> bool:
        if voter_id == 0 or not (0 <= class_index < self.classes_count):
            return False

        for i in range(self.capacity):
            if self.voter_ids[i] == voter_id:
                self.voter_classes[i] = class_index
                self.voter_times[i] = now
                return True

        for i in range(self.capacity):
            live = self.voter_ids[i] != 0 and (now - self.voter_times[i]) < self.freshness_window
            if not live:
                self.voter_ids[i] = voter_id
                self.voter_classes[i] = class_index
                self.voter_times[i] = now
                return True

        return False

    def resolve(self, now: float) -> bool:
        self.tallies = [0] * self.classes_count
        total_live = 0

        for i in range(self.capacity):
            if self.voter_ids[i] != 0 and (now - self.voter_times[i]) < self.freshness_window:
                c = self.voter_classes[i]
                if 0 <= c < self.classes_count:
                    self.tallies[c] += 1
                    total_live += 1

        if total_live < self.min_votes_count:
            self.is_settled = False
            return False

        top_votes = 0
        top_class = 0
        tie = False

        for c in range(self.classes_count):
            v = self.tallies[c]
            if v > top_votes:
                top_votes = v
                top_class = c
                tie = False
            elif v == top_votes and top_votes > 0:
                tie = True

        if top_votes >= self.min_votes_count and not tie:
            self.agreed_value = top_class
            self.is_settled = True
            return True

        self.is_settled = False
        return False
