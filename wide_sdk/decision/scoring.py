import math
from typing import Callable, List, Tuple

class Criterion:
    def __init__(self, weight: float, term: Callable[[int], float]) -> None:
        if not math.isfinite(weight) or weight < 0.0:
            raise ValueError("weight must be finite and non-negative")
        if not term:
            raise ValueError("term cannot be null")
        self.weight = weight
        self.term = term

class WeightedScorer:
    def __init__(self, *criteria: Criterion) -> None:
        if not criteria:
            raise ValueError("criteria cannot be empty")
        self.criteria: List[Criterion] = list(criteria)
        self.total_weight = sum(c.weight for c in self.criteria)
        if not math.isfinite(self.total_weight) or self.total_weight <= 0.0:
            raise ValueError("total_weight must be positive")

    def score(self, candidate: int) -> float:
        s = 0.0
        for c in self.criteria:
            val = c.term(candidate)
            clamped = 0.0 if not math.isfinite(val) else max(0.0, min(1.0, val))
            s += c.weight * clamped
        return s / self.total_weight

    def try_select(self, candidate_count: int, threshold: float = 0.5, bias: float = 1.0) -> Tuple[bool, int, float]:
        if candidate_count < 1 or bias <= 0.0:
            return False, -1, 0.0

        effective_threshold = threshold / bias
        best_index = -1
        best_score = -1.0

        for i in range(candidate_count):
            s = self.score(i)
            if s > best_score:
                best_score = s
                best_index = i

        if best_score >= effective_threshold and best_index >= 0:
            return True, best_index, best_score

        return False, best_index, best_score
