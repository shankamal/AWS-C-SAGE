from types import SimpleNamespace
from unittest import TestCase

from .findings_views import _compliance_posture
from .models import Finding


class ComplianceScoreTests(TestCase):
    def _finding(self, status):
        return SimpleNamespace(status=status)

    def test_compliance_posture_counts_and_percentages(self):
        rows = [
            self._finding(Finding.Status.COMPLIANT),
            self._finding(Finding.Status.COMPLIANT),
            self._finding(Finding.Status.NON_COMPLIANT),
            self._finding(Finding.Status.SUPPRESSED),
        ]
        posture = _compliance_posture(rows)
        self.assertEqual(posture["total"], 4)
        self.assertEqual(posture["compliant"], 2)
        self.assertEqual(posture["non_compliant"], 1)
        self.assertEqual(posture["suppressed"], 1)
        self.assertEqual(posture["score"], 50.0)
        self.assertEqual(posture["non_compliant_end"], 75.0)

    def test_empty_compliance_posture(self):
        posture = _compliance_posture([])
        self.assertEqual(posture["total"], 0)
        self.assertEqual(posture["score"], 0)
