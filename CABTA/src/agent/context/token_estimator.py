"""Dependency-free token estimation helpers for AISA context orchestration."""

from __future__ import annotations

import json
import math
from typing import Any


def estimate_text_tokens(text: Any) -> int:
    """Estimate prompt tokens with a deterministic local heuristic.

    The heuristic intentionally avoids external tokenizer dependencies. It uses
    roughly four characters per token with small structural overhead so budget
    decisions remain stable across offline/local-first deployments.
    """
    value = "" if text is None else str(text)
    if not value:
        return 0
    # Add a bounded newline/punctuation overhead so structured prompts do not
    # look artificially cheap compared with compact prose.
    structural = value.count("\n") + value.count(":") // 2 + value.count(",") // 3
    return max(1, int(math.ceil(len(value) / 4.0)) + structural)


def estimate_json_tokens(payload: Any) -> int:
    """Estimate tokens for a JSON-serializable payload."""
    try:
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        text = str(payload)
    # JSON carries quoting/bracket overhead beyond raw text.
    return estimate_text_tokens(text) + max(1, int(math.ceil(len(text) / 80.0))) if text else 0
