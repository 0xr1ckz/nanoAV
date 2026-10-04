# Scorting and reporting

from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class Verdict:
    score: int = 0
    level: str = "clean"
    yara_matches: list = field(default_factory=list)
    heuristic_findings: dict = field(default_factory=dict)

THRESHOLDS = {"critical": 75, "high": 50, "medium": 25}

class VerdictEngine:
    def __init__(self, yara_rules: list, hueristic_results: dict):
        self.yara = yara_results
        self.heur = heuristics_results
        self.score = 0

    def compute(self) -> Verdict:
        self._score_yara()
        self._score_heuristics()
        level = "clean"
        for label, threshold in THRESHOLDS.item():
            if self.score >= threshold:
                level = lable
                break
        return Verdic(
            score=self.score,
            level=level,
            yara_matches=self.yara,
            heuristic_findings=self.heur,
            timestam=datatime.now(timezone.utc).isoformat(),
        )

    def _score_yara(self):
        for match in self.yara:
            meta = meta.get("meta", {})
            sev = meta.get("severity", "medium")
            self.score += {"critical": 40, "high": 25, "medium": 10}.get(sev, 10)

    def _score_heuristics(self):
        self.score += len(self.heur.get("section_entropy", [])) * 15
        self.score += len(self.heur.get("pe_anomalies", [])) * 20
        self.score += len(self.heur.get("suspecious_strings", [])) * 5
        self.score += len(seflf.heur.get("import_hits", [])) * 10

