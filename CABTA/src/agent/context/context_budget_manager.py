"""Context budgeting for AISA model-call orchestration."""

from __future__ import annotations

from typing import Any, Dict

from .token_estimator import estimate_json_tokens, estimate_text_tokens

DEFAULT_SECTION_RATIOS: Dict[str, float] = {
    "system_rules": 0.10,
    "goal": 0.06,
    "reasoning": 0.20,
    "evidence": 0.24,
    "entities": 0.10,
    "hypotheses": 0.12,
    "coverage": 0.08,
    "tools": 0.06,
    "workflow": 0.04,
}


class ContextBudgetManager:
    """Resolve model-aware budgets and token diagnostics."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.context_config = self._resolve_context_config(self.config)

    @staticmethod
    def _resolve_context_config(config: Dict[str, Any]) -> Dict[str, Any]:
        agent_cfg = config.get("agent", {}) if isinstance(config, dict) else {}
        nested = agent_cfg.get("context", {}) if isinstance(agent_cfg, dict) else {}
        top_level = config.get("context_management", {}) if isinstance(config, dict) else {}
        merged = {**(top_level if isinstance(top_level, dict) else {}), **(nested if isinstance(nested, dict) else {})}
        return merged

    def enabled(self) -> bool:
        return bool(self.context_config.get("enabled", True))

    def window_tokens(self, model: str = "") -> int:
        model_windows = self.context_config.get("model_windows", {})
        if isinstance(model_windows, dict) and model and model_windows.get(model):
            return int(model_windows[model])
        return int(
            self.context_config.get("context_window_tokens")
            or self.context_config.get("default_model_window_tokens")
            or 32000
        )

    def reserved_output_tokens(self) -> int:
        return int(
            self.context_config.get("reserved_output_tokens")
            or self.context_config.get("response_reserve_tokens")
            or 4096
        )

    def safety_margin_tokens(self) -> int:
        return int(self.context_config.get("safety_margin_tokens") or 1024)

    def hard_prompt_budget_tokens(self, model: str = "") -> int:
        explicit = self.context_config.get("hard_prompt_budget_tokens")
        if explicit:
            return int(explicit)
        ratio = float(self.context_config.get("hard_prompt_budget_ratio") or 0.92)
        usable = self.usable_tokens(model)
        return max(1, int(usable * max(0.1, min(1.0, ratio))))

    def usable_tokens(self, model: str = "") -> int:
        return max(1, self.window_tokens(model) - self.reserved_output_tokens() - self.safety_margin_tokens())

    def section_ratios(self, objective: str = "decide_next_tool") -> Dict[str, float]:
        configured = self.context_config.get("section_budgets") or self.context_config.get("budgets") or {}
        if isinstance(configured, dict):
            objective_cfg = configured.get(objective) if isinstance(configured.get(objective), dict) else configured
            if isinstance(objective_cfg, dict) and objective_cfg:
                ratios = {str(k): float(v) for k, v in objective_cfg.items() if isinstance(v, (int, float))}
                total = sum(v for v in ratios.values() if v > 0)
                if total > 0:
                    return {k: max(0.0, v) / total for k, v in ratios.items()}
        return dict(DEFAULT_SECTION_RATIOS)

    def section_budgets(self, *, objective: str = "decide_next_tool", model: str = "") -> Dict[str, int]:
        hard_budget = self.hard_prompt_budget_tokens(model)
        ratios = self.section_ratios(objective)
        return {section: int(hard_budget * ratio) for section, ratio in ratios.items()}

    def estimate_sections(self, sections: Dict[str, Any]) -> Dict[str, int]:
        estimates: Dict[str, int] = {}
        for section, value in (sections or {}).items():
            if isinstance(value, str):
                estimates[section] = estimate_text_tokens(value)
            else:
                estimates[section] = estimate_json_tokens(value)
        return estimates

    def budget_report(self, *, sections: Dict[str, Any], objective: str, model: str) -> Dict[str, Any]:
        by_section = self.estimate_sections(sections)
        estimated_total = sum(by_section.values())
        hard_budget = self.hard_prompt_budget_tokens(model)
        usable = self.usable_tokens(model)
        threshold = float(self.context_config.get("compaction_threshold_ratio") or 0.85)
        over_budget = estimated_total > hard_budget or estimated_total > int(usable * threshold)
        target = int(hard_budget * max(0.1, min(1.0, threshold)))
        return {
            "schema_version": "context-budget/v1",
            "model": model,
            "window_tokens": self.window_tokens(model),
            "usable_tokens": usable,
            "reserved_output_tokens": self.reserved_output_tokens(),
            "safety_margin_tokens": self.safety_margin_tokens(),
            "hard_prompt_budget_tokens": hard_budget,
            "compaction_threshold_ratio": threshold,
            "compression_target_tokens": target,
            "objective": objective,
            "section_budgets": self.section_budgets(objective=objective, model=model),
            "estimated_total": estimated_total,
            "by_section": by_section,
            "over_budget": bool(over_budget),
            "authority_policy": "budgeting_may_compress_prompt_context_but_does_not_delete_or_override_evidence",
        }

    def max_ledger_items(self) -> int:
        return int(self.context_config.get("max_ledger_items") or 120)

    def max_context_pack_bytes(self) -> int:
        return int(self.context_config.get("max_context_pack_bytes") or 200000)
