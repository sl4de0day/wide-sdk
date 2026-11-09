import unittest
from wide_sdk.decision import (
    CommitmentGate,
    Commitment,
    PluralityConsensus,
    ClaimTable,
    PartitionAssignment,
    WeightedScorer,
    Criterion,
    SynchronizationBarrier,
)

class TestDecisionCore(unittest.TestCase):
    def test_commitment_gate(self) -> None:
        gate = CommitmentGate(4, 0.5)
        self.assertEqual(gate.state, 0)
        self.assertFalse(gate.try_transition(1, 0.1))
        self.assertTrue(gate.try_transition(1, 0.6))
        self.assertEqual(gate.state, 1)

    def test_commitment_lock_and_margin(self) -> None:
        plan = Commitment(5.0, 2.0)
        plan.adopt(0.8, 10.0)
        self.assertFalse(plan.should_replace(0.95, 0.1, 11.0))
        self.assertTrue(plan.should_replace(0.95, 0.1, 13.0))

    def test_consensus(self) -> None:
        consensus = PluralityConsensus(4, 8, 5.0, 2)
        consensus.vote(101, 2, 1.0)
        consensus.vote(102, 2, 1.2)
        consensus.vote(103, 1, 1.5)
        self.assertTrue(consensus.resolve(2.0))
        self.assertEqual(consensus.value, 2)

    def test_claim_table(self) -> None:
        claims = ClaimTable(4)
        self.assertTrue(claims.try_claim(1, 0.5, 3.0, 0.0, 2))
        self.assertTrue(claims.try_claim(2, 0.8, 3.0, 0.5, 2))
        self.assertFalse(claims.try_claim(3, 0.3, 3.0, 1.0, 2))
        self.assertTrue(claims.try_claim(3, 0.9, 3.0, 1.0, 2))

    def test_partition_assignment(self) -> None:
        partitions = PartitionAssignment(4)
        ok1, p1 = partitions.try_assign(10, 0, 5.0, 1.0)
        self.assertTrue(ok1)
        self.assertEqual(p1, 0)
        ok2, p2 = partitions.try_assign(20, 0, 5.0, 1.0)
        self.assertTrue(ok2)
        self.assertNotEqual(p2, 0)

    def test_weighted_scorer(self) -> None:
        scorer = WeightedScorer(
            Criterion(0.6, lambda c: 0.9 if c == 0 else 0.3),
            Criterion(0.4, lambda c: 0.8 if c == 0 else 0.9),
        )
        ok, best, score = scorer.try_select(2, 0.5)
        self.assertTrue(ok)
        self.assertEqual(best, 0)

    def test_barrier(self) -> None:
        barrier = SynchronizationBarrier(4)
        barrier.report_ready(1, 10.0)
        barrier.report_ready(2, 10.5)
        self.assertTrue(barrier.tick(3, 0.6, 5.0, 11.0))
        self.assertTrue(barrier.reached_quorum)

if __name__ == "__main__":
    unittest.main()
