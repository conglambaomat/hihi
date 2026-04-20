"""Lightweight follow-up chat intent classification."""

from __future__ import annotations

import unicodedata
from typing import Any, Dict


class ChatIntentRouter:
    """Classify follow-up analyst chat so routes and loops can seed the right memory."""

    def classify(self, message: str) -> Dict[str, Any]:
        text = self._normalize_text(message)
        intent = "new_pivot"
        requires_fresh_evidence = True

        if any(token in text for token in ("summary", "summarize", "recap", "tom tat")):
            intent = "recap"
            requires_fresh_evidence = False
        elif any(token in text for token in ("why", "because", "explain", "what evidence", "vi sao", "tai sao", "giai thich", "bang chung")):
            intent = "explain"
            requires_fresh_evidence = False
        elif any(token in text for token in ("challenge", "are you sure", "contradiction", "mau thuan")):
            intent = "challenge_evidence"
            requires_fresh_evidence = False
        elif any(token in text for token in ("upload", "artifact", "sample", "attachment", "paste", "submit")):
            intent = "new_artifact"
            requires_fresh_evidence = True
        elif any(token in text for token in ("scope", "instead", "focus on", "change to")):
            intent = "scope_change"
            requires_fresh_evidence = True
        elif any(token in text for token in ("approve", "reject", "review")):
            intent = "review_approval"
            requires_fresh_evidence = False

        return {
            "intent": intent,
            "requires_fresh_evidence": requires_fresh_evidence,
            "analyst_message": message,
        }

    def _normalize_text(self, message: str) -> str:
        raw = str(message or "").strip().lower()
        variants = [raw]
        repaired = self._repair_mojibake(raw)
        if repaired and repaired != raw:
            variants.append(repaired)
        normalized: list[str] = []
        for item in variants:
            folded = unicodedata.normalize("NFKD", item)
            simplified = "".join(ch for ch in folded if not unicodedata.combining(ch))
            normalized.append(simplified.lower())
        return " ".join(dict.fromkeys(part for part in normalized if part))

    @staticmethod
    def _repair_mojibake(text: str) -> str:
        try:
            repaired = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return text
        return repaired.strip().lower() or text
