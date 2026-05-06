"""Authoritative chat routing classification for AISA conversational turns."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict


class ChatIntentRouter:
    """Classify chat turns into direct vs investigation execution modes."""

    DIRECT_RESPONSE_MODE = "direct_response"
    INVESTIGATION_MODE = "investigation"

    def classify(self, message: str) -> Dict[str, Any]:
        text = self._normalize_text(message)
        has_observable = self._has_observable(text)
        looks_like_artifact = self._looks_like_artifact_submission(text)
        intent = "new_pivot"
        requires_fresh_evidence = bool(has_observable or looks_like_artifact)
        execution_mode = self.INVESTIGATION_MODE if requires_fresh_evidence else self.DIRECT_RESPONSE_MODE

        if any(token in text for token in ("summary", "summarize", "recap", "tom tat")):
            intent = "recap"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE
        elif any(token in text for token in ("why", "because", "explain", "what evidence", "vi sao", "tai sao", "giai thich", "bang chung")):
            intent = "explain"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE
        elif any(token in text for token in ("challenge", "are you sure", "contradiction", "mau thuan")):
            intent = "challenge_evidence"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE
        elif any(token in text for token in ("hello", "xin chao", "good morning", "good afternoon")) or text in {"hi", "hey", "chao"}:
            intent = "greeting"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE
        elif any(token in text for token in (
            "who are you",
            "ban la ai",
            "are you really",
            "thuc su",
            "that su",
            "identity",
            "capability",
            "what can you do",
            "ban co the lam gi",
            "help me",
            "giup toi",
            "ban co phai",
            "bạn có phải",
        )):
            intent = "capability_question"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE
        elif any(token in text for token in ("upload", "artifact", "sample", "attachment", "paste", "submit")):
            intent = "new_artifact"
            requires_fresh_evidence = True
            execution_mode = self.INVESTIGATION_MODE
        elif any(token in text for token in ("scope", "instead", "focus on", "change to")):
            intent = "scope_change"
            requires_fresh_evidence = bool(has_observable or looks_like_artifact)
            execution_mode = self.INVESTIGATION_MODE if requires_fresh_evidence else self.DIRECT_RESPONSE_MODE
        elif any(token in text for token in ("approve", "reject", "review")):
            intent = "review_approval"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE
        elif has_observable or looks_like_artifact or self._message_requests_fresh_evidence(text):
            intent = "new_pivot" if has_observable or looks_like_artifact else "investigation_request"
            requires_fresh_evidence = True
            execution_mode = self.INVESTIGATION_MODE
        else:
            intent = "clarification"
            requires_fresh_evidence = False
            execution_mode = self.DIRECT_RESPONSE_MODE

        return {
            "intent": intent,
            "requires_fresh_evidence": requires_fresh_evidence,
            "execution_mode": execution_mode,
            "has_observable": has_observable,
            "looks_like_artifact": looks_like_artifact,
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

    @staticmethod
    def _has_observable(message: str) -> bool:
        focused_message = str(message or "")
        patterns = (
            r'([A-Z]:[/\\][\w/\\.\- ]+|/[\w/.\- ]+)',
            r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
            r'https?://\S+',
            r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b',
            r'\b[a-fA-F0-9]{32,64}\b',
            r'\b[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,}\b',
            r'\bCVE-\d{4}-\d{4,}\b',
        )
        return any(re.search(pattern, focused_message) for pattern in patterns)

    @staticmethod
    def _looks_like_artifact_submission(message: str) -> bool:
        focused_message = str(message or "").strip()
        lower_message = focused_message.lower()
        if not focused_message:
            return False
        if len(focused_message) > 280 or focused_message.count("\n") >= 3:
            return True
        if ChatIntentRouter._looks_inline_log_artifact(lower_message):
            return True
        artifact_markers = (
            "subject:",
            "from:",
            "to:",
            "received:",
            "return-path:",
            "message-id:",
            "alert:",
            "event id",
            "siem",
            "powershell",
            "cmd.exe",
            "user-agent:",
            "pcap",
            "mail header",
            "email header",
            "log snippet",
            "ioc list",
        )
        return any(marker in lower_message for marker in artifact_markers)

    @staticmethod
    def _looks_inline_log_artifact(message: str) -> bool:
        lowered = str(message or "").lower()
        kv_markers = ("sourcetype=", "source=", "src_ip=", "dest_ip=", "dest_port=", "eventcode=", "host=")
        splunk_markers = ("stream:tcp", "stream:udp", "splunk", "index=", "_time=")
        has_log_kv = sum(1 for marker in kv_markers if marker in lowered) >= 2
        has_network_tuple = ("src_ip=" in lowered or "srcip=" in lowered) and ("dest_ip=" in lowered or "dstip=" in lowered or "dest_port=" in lowered)
        return bool((has_log_kv and any(marker in lowered for marker in splunk_markers)) or (has_network_tuple and ("source=" in lowered or "sourcetype=" in lowered)))

    @staticmethod
    def _message_requests_fresh_evidence(message: str) -> bool:
        text = str(message or "").strip().lower()
        if not text:
            return False
        investigation_patterns = (
            "investigate",
            "pivot",
            "check",
            "analyze",
            "lookup",
            "look up",
            "search",
            "hunt",
            "query",
            "scan",
            "enrich",
            "triage",
            "verify",
            "confirm",
            "correlate",
            "find related",
            "pull",
            "dieu tra",
            "kiem tra",
            "phan tich",
            "tra cuu",
            "xac minh",
            "tim them",
            "san",
            "quet",
        )
        return any(pattern in text for pattern in investigation_patterns)
