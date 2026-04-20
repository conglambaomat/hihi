"""
Playbook Engine - Execute predefined investigation workflows.

Supports:
  - Sequential and conditional step execution
  - ``for_each`` iteration over dynamic result sets
  - Human-in-the-loop approval checkpoints
  - YAML-based playbook definitions (loaded from ``data/playbooks/``)
  - Runtime variable interpolation in tool parameters

A playbook is a list of steps.  Each step invokes a tool and can branch
based on the outcome (``on_success`` / ``on_failure`` / ``condition``).
"""

import asyncio
import json
import logging
import operator
import re
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import yaml; fall back gracefully if not installed
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PlaybookStep:
    """One step in a playbook."""
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # e.g. "verdict == 'MALICIOUS'"
    on_success: Optional[str] = None  # Name of the next step on success
    on_failure: Optional[str] = None  # Name of the next step on failure
    requires_approval: bool = False  # Pause for human approval
    for_each: Optional[str] = None  # Iterate over a context variable
    timeout: int = 120  # Per-step timeout in seconds
    description: str = ""
    action: Optional[str] = None  # e.g. "final_answer", "trigger_playbook", "input"

    def to_dict(self) -> Dict:
        d = {
            "name": self.name,
            "tool": self.tool,
            "params": self.params,
            "condition": self.condition,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "requires_approval": self.requires_approval,
            "for_each": self.for_each,
            "timeout": self.timeout,
            "description": self.description,
        }
        if self.action:
            d["action"] = self.action
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "PlaybookStep":
        # Handle condition: can be a string or a dict with if/then/else
        raw_cond = d.get("condition")
        condition_str = None
        on_success = d.get("on_success")
        on_failure = d.get("on_failure")

        if isinstance(raw_cond, dict):
            # Playbook YAML format: condition: {if: "...", then: "step", else: "step"}
            condition_str = raw_cond.get("if")
            if isinstance(condition_str, str):
                condition_str = condition_str.strip()
            cond_then = raw_cond.get("then")
            cond_else = raw_cond.get("else")
            if cond_then == d.get("name"):
                cond_then = None
            if cond_else == d.get("name"):
                cond_else = None
            if cond_then and not on_success:
                on_success = cond_then
            if cond_else and not on_failure:
                on_failure = cond_else
        elif isinstance(raw_cond, str):
            condition_str = raw_cond

        return cls(
            name=d["name"],
            tool=d.get("tool", ""),
            params=d.get("params") or {},
            condition=condition_str,
            on_success=on_success,
            on_failure=on_failure,
            requires_approval=d.get("requires_approval", False),
            for_each=d.get("for_each"),
            timeout=d.get("timeout", 120),
            description=d.get("description", ""),
            action=d.get("action"),
        )


# ---------------------------------------------------------------------------
# Safe condition evaluator (no eval)
# ---------------------------------------------------------------------------

# Supported operators for condition parsing
_OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}

# Regex to parse simple conditions like: variable op value
_SIMPLE_COND = re.compile(
    r"^\s*(\w[\w.]*)\s*(==|!=|>=?|<=?)\s*(.+?)\s*$"
)
# Regex to parse 'value in variable' conditions
_IN_COND = re.compile(
    r"""^\s*['"](.+?)['"]\s+in\s+(\w[\w.]*)\s*$"""
)
# Regex to parse 'variable in (val1, val2)' conditions
_VAR_IN_TUPLE = re.compile(
    r"""^\s*(\w[\w.]*)\s+in\s+\((.+?)\)\s*$"""
)
_TEMPLATE_VAR = re.compile(r"\{\{\s*(.+?)\s*\}\}")
_TRUTHY_VAR = re.compile(r"^\s*(\w[\w.]*)\s*$")


def _parse_literal(text: str) -> Any:
    """Parse a string literal into a Python value."""
    text = text.strip()
    if (text.startswith("'") and text.endswith("'")) or \
       (text.startswith('"') and text.endswith('"')):
        return text[1:-1]
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if text.lower() == "none":
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _normalize_comparable(value: Any) -> Any:
    """Normalize ratio-like strings such as ``2/3`` for numeric comparisons."""
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"\d+\s*/\s*\d+", text):
            numerator, denominator = [int(part.strip()) for part in text.split("/", 1)]
            if denominator:
                return numerator / denominator
    return value


def _resolve_var(var_path: str, context: Dict) -> Any:
    """Resolve a dotted variable path in the context dict."""
    parts = var_path.split(".")
    obj = context
    for part in parts:
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def safe_evaluate_condition(condition: str, context: Dict) -> bool:
    """
    Evaluate a step condition safely WITHOUT using eval().

    Supported syntax:
    - ``verdict == 'MALICIOUS'``
    - ``score > 70``
    - ``score >= 50``
    - ``'ransomware' in tags``
    - ``file_type in ('PE', 'ELF')``
    - ``cond1 and cond2``   (split on ' and ')
    - ``cond1 or cond2``    (split on ' or ')

    Returns False on any parse error (safe default).
    """
    if not condition or not condition.strip():
        return True

    condition = condition.strip()

    try:
        condition = _TEMPLATE_VAR.sub(lambda m: m.group(1).strip(), condition)

        # Handle 'and' by splitting
        if " and " in condition:
            parts = condition.split(" and ")
            return all(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Handle 'or' by splitting
        if " or " in condition:
            parts = condition.split(" or ")
            return any(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Flatten context: include last_result fields at top level
        flat_ctx = dict(context)
        lr = context.get("last_result", {})
        if isinstance(lr, dict):
            for k, v in lr.items():
                if k not in flat_ctx:
                    flat_ctx[k] = v
        # Also flatten one level of nested dicts
        for key, val in list(context.items()):
            if isinstance(val, dict):
                for k2, v2 in val.items():
                    fk = f"{key}_{k2}"
                    if fk not in flat_ctx:
                        flat_ctx[fk] = v2

        m = _TRUTHY_VAR.match(condition)
        if m:
            return bool(_resolve_var(m.group(1), flat_ctx))

        # Pattern: 'value' in variable
        m = _IN_COND.match(condition)
        if m:
            needle = m.group(1)
            haystack = _resolve_var(m.group(2), flat_ctx)
            if isinstance(haystack, (list, tuple, set)):
                return needle in haystack
            if isinstance(haystack, str):
                return needle in haystack
            return False

        # Pattern: variable in (val1, val2, ...)
        m = _VAR_IN_TUPLE.match(condition)
        if m:
            var_val = _resolve_var(m.group(1), flat_ctx)
            tuple_items = [_parse_literal(v.strip()) for v in m.group(2).split(",")]
            return var_val in tuple_items

        # Pattern: variable op value
        m = _SIMPLE_COND.match(condition)
        if m:
            left_val = _normalize_comparable(_resolve_var(m.group(1), flat_ctx))
            op_str = m.group(2)
            right_val = _normalize_comparable(_parse_literal(m.group(3)))

            op_func = _OPERATORS.get(op_str)
            if op_func is None:
                return False

            # Type coercion for numeric comparisons
            if isinstance(right_val, (int, float)) and left_val is not None:
                try:
                    left_val = type(right_val)(left_val)
                except (ValueError, TypeError):
                    pass

            try:
                return op_func(left_val, right_val)
            except TypeError:
                return False

        # Unrecognised pattern
        logger.debug("[PLAYBOOK] Could not parse condition: %s", condition)
        return False

    except Exception as exc:
        logger.debug("[PLAYBOOK] Condition '%s' failed: %s", condition, exc)
        return False


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """
    Loads and executes investigation playbooks.

    A playbook is identified by its ``playbook_id`` (which is either its
    file-stem for built-in YAML playbooks or the DB ``id`` for user-created
    ones).

    The engine delegates actual tool calls to the ``agent_loop``, which
    handles MCP tool routing, local tools, and result recording.
    """

    def __init__(self, agent_loop, agent_store, governance_store=None):
        """
        Parameters
        ----------
        agent_loop
            An object with an async ``run_tool(tool_name, params) -> dict``
            method.
        agent_store
            An ``AgentStore`` instance for persistence.
        """
        self.agent_loop = agent_loop
        self.store = agent_store
        self.governance_store = governance_store

        # Built-in playbooks directory
        self._playbooks_dir = Path(__file__).parent.parent.parent / "data" / "playbooks"

        # In-memory cache: playbook_id -> definition dict
        self._cache: Dict[str, Dict] = {}

        # Load built-in playbooks at start
        self.load_builtin_playbooks()

    # ------------------------------------------------------------------ #
    #  Loading
    # ------------------------------------------------------------------ #

    def load_builtin_playbooks(self) -> int:
        """
        Load YAML playbook definitions from ``data/playbooks/``.

        Returns the number of playbooks loaded.
        """
        if not self._playbooks_dir.is_dir():
            logger.debug("[PLAYBOOK] No playbooks directory at %s", self._playbooks_dir)
            return 0

        if not _HAS_YAML:
            logger.warning(
                "[PLAYBOOK] PyYAML is not installed -- cannot load YAML playbooks. "
                "Install with: pip install pyyaml"
            )
            return 0

        count = 0
        for path in sorted(self._playbooks_dir.glob("*.yaml")) + sorted(self._playbooks_dir.glob("*.yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    definition = yaml.safe_load(f)

                if not isinstance(definition, dict):
                    logger.warning("[PLAYBOOK] Skipping %s (not a dict)", path.name)
                    continue

                pid = definition.get("id", path.stem)
                definition["id"] = pid
                definition["source"] = "builtin"
                definition["file"] = str(path)

                # Validate steps
                steps = definition.get("steps", [])
                if not steps:
                    logger.warning("[PLAYBOOK] Skipping %s (no steps)", path.name)
                    continue

                # Parse steps into PlaybookStep objects (validation)
                parsed = [PlaybookStep.from_dict(s) for s in steps]
                definition["_parsed_steps"] = parsed

                self._cache[pid] = definition
                count += 1
                logger.debug("[PLAYBOOK] Loaded: %s (%d steps)", pid, len(parsed))

            except Exception as exc:
                logger.warning("[PLAYBOOK] Failed to load %s: %s", path.name, exc)

        # Also load from DB
        try:
            for pb in self.store.list_playbooks():
                pid = pb.get("id", pb.get("name", ""))
                if pid and pid not in self._cache:
                    steps_data = pb.get("steps_json", [])
                    if isinstance(steps_data, str):
                        steps_data = json.loads(steps_data)
                    self._cache[pid] = {
                        "id": pid,
                        "name": pb.get("name", pid),
                        "description": pb.get("description", ""),
                        "steps": steps_data,
                        "_parsed_steps": [PlaybookStep.from_dict(s) for s in steps_data],
                        "source": "database",
                    }
                    count += 1
        except Exception as exc:
            logger.debug("[PLAYBOOK] DB load error: %s", exc)

        logger.info("[PLAYBOOK] %d playbooks available", len(self._cache))
        return count

    # ------------------------------------------------------------------ #
    #  Accessors
    # ------------------------------------------------------------------ #

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Get a playbook definition by ID."""
        pb = self._cache.get(playbook_id)
        if pb:
            raw_inputs = deepcopy(pb.get("input_params", pb.get("input", [])))
            normalized_parameters: Dict[str, Dict[str, Any]] = {}
            if isinstance(raw_inputs, list):
                for item in raw_inputs:
                    if isinstance(item, dict) and item.get("name"):
                        normalized_parameters[str(item["name"])] = {
                            k: deepcopy(v) for k, v in item.items() if k != "name"
                        }
            elif isinstance(raw_inputs, dict):
                normalized_parameters = deepcopy(raw_inputs)

            return {
                "id": pb.get("id", playbook_id),
                "name": pb.get("name", playbook_id),
                "description": pb.get("description", ""),
                "steps": [
                    s.to_dict() if hasattr(s, "to_dict") else s
                    for s in pb.get("_parsed_steps", pb.get("steps", []))
                ],
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
                "input": raw_inputs,
                "input_params": raw_inputs,
                "inputs": raw_inputs,
                "parameters": normalized_parameters,
            }
        return None

    def list_playbooks(self) -> List[Dict]:
        """List all available playbooks (built-in + database)."""
        results = []
        for pid, pb in self._cache.items():
            steps = pb.get("_parsed_steps", pb.get("steps", []))
            tools: List[str] = []
            for step in steps:
                tool_name = None
                if hasattr(step, "tool"):
                    tool_name = step.tool
                elif isinstance(step, dict):
                    tool_name = step.get("tool") or step.get("type")
                if tool_name and tool_name not in tools:
                    tools.append(tool_name)
            results.append({
                "id": pid,
                "name": pb.get("name", pid),
                "description": pb.get("description", ""),
                "step_count": len(steps),
                "tool_count": len(tools),
                "tools": tools,
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
            })
        return results

    def list_available(self) -> List[Dict]:
        """Alias for ``list_playbooks`` -- lists all available playbooks."""
        return self.list_playbooks()

    def validate_playbook_definition(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a human-readable playbook definition without executing it."""
        issues: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        if not isinstance(definition, dict):
            return {
                "valid": False,
                "issues": [{"level": "error", "message": "Playbook definition must be a mapping/dict"}],
                "warnings": [],
                "step_count": 0,
                "tool_count": 0,
            }

        steps = definition.get("steps", [])
        if not isinstance(steps, list) or not steps:
            return {
                "valid": False,
                "issues": [{"level": "error", "message": "Playbook must declare a non-empty steps list"}],
                "warnings": [],
                "step_count": 0,
                "tool_count": 0,
            }

        parsed_steps: List[PlaybookStep] = []
        step_names: List[str] = []
        for index, raw_step in enumerate(steps, start=1):
            if not isinstance(raw_step, dict):
                issues.append(
                    {"level": "error", "step": index, "message": f"Step #{index} must be a mapping/dict"}
                )
                continue
            try:
                parsed = PlaybookStep.from_dict(raw_step)
                parsed_steps.append(parsed)
                step_names.append(parsed.name)
            except Exception as exc:
                issues.append(
                    {"level": "error", "step": index, "message": f"Step #{index} is invalid: {exc}"}
                )

        duplicates = sorted({name for name in step_names if step_names.count(name) > 1})
        for name in duplicates:
            issues.append({"level": "error", "step_name": name, "message": f"Duplicate step name: {name}"})

        declared_tools: List[str] = []
        terminal_actions: List[str] = []
        approval_steps: List[str] = []
        conditional_steps: List[str] = []
        loop_steps: List[str] = []
        timeout_steps: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        known_steps = set(step_names)

        for parsed in parsed_steps:
            if parsed.tool:
                if parsed.tool not in declared_tools:
                    declared_tools.append(parsed.tool)
            if parsed.action == "final_answer":
                terminal_actions.append(parsed.name)
            if parsed.requires_approval:
                approval_steps.append(parsed.name)
            if parsed.condition:
                conditional_steps.append(parsed.name)
            if parsed.for_each:
                loop_steps.append(parsed.name)

            timeout_steps.append(
                {
                    "name": parsed.name,
                    "timeout": int(parsed.timeout or 0),
                }
            )

            if not parsed.tool and not parsed.action and not parsed.requires_approval and not parsed.condition and not parsed.for_each:
                warnings.append(
                    {
                        "level": "warning",
                        "step_name": parsed.name,
                        "message": "Step has no tool, action, condition, approval, or iteration semantics",
                    }
                )

            if parsed.requires_approval and not parsed.tool:
                warnings.append(
                    {
                        "level": "warning",
                        "step_name": parsed.name,
                        "message": "Approval step has no tool; approval will pause without executing a tool call",
                    }
                )

            if parsed.for_each and not parsed.tool:
                warnings.append(
                    {
                        "level": "warning",
                        "step_name": parsed.name,
                        "message": "for_each is declared without a tool; iteration may not do useful work",
                    }
                )

            if int(parsed.timeout or 0) <= 0:
                issues.append(
                    {
                        "level": "error",
                        "step_name": parsed.name,
                        "message": "timeout must be greater than 0 seconds",
                    }
                )

            for edge_type, target in (("on_success", parsed.on_success), ("on_failure", parsed.on_failure)):
                if not target:
                    continue
                edges.append({"from": parsed.name, "to": target, "type": edge_type})
                if target != "end" and target not in known_steps:
                    issues.append(
                        {
                            "level": "error",
                            "step_name": parsed.name,
                            "message": f"{edge_type} references unknown step '{target}'",
                        }
                    )

        return {
            "valid": not any(item.get("level") == "error" for item in issues),
            "issues": issues,
            "warnings": warnings,
            "step_count": len(parsed_steps),
            "tool_count": len(declared_tools),
            "declared_tools": declared_tools,
            "terminal_actions": terminal_actions,
            "approval_steps": approval_steps,
            "conditional_steps": conditional_steps,
            "loop_steps": loop_steps,
            "timeout_steps": timeout_steps,
            "max_timeout_seconds": max((item["timeout"] for item in timeout_steps), default=0),
            "edges": edges,
        }

    def describe_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Return an inspectable contract for a playbook before execution."""
        pb = self._cache.get(playbook_id)
        if not pb:
            return None

        public_playbook = self.get_playbook(playbook_id)
        if public_playbook is None:
            return None

        validation = self.validate_playbook_definition(
            {
                "id": public_playbook.get("id"),
                "name": public_playbook.get("name"),
                "description": public_playbook.get("description"),
                "steps": public_playbook.get("steps", []),
            }
        )

        parsed_steps = pb.get("_parsed_steps", [])
        approval_steps = [step.name for step in parsed_steps if getattr(step, "requires_approval", False)]
        conditional_steps = [step.name for step in parsed_steps if getattr(step, "condition", None)]
        loop_steps = [step.name for step in parsed_steps if getattr(step, "for_each", None)]

        return {
            **public_playbook,
            "validation": validation,
            "execution_contract": {
                "approval_steps": approval_steps,
                "conditional_steps": conditional_steps,
                "loop_steps": loop_steps,
                "timeout_steps": validation.get("timeout_steps", []),
                "max_timeout_seconds": validation.get("max_timeout_seconds", 0),
                "branch_edges": validation.get("edges", []),
                "terminal_actions": validation.get("terminal_actions", []),
                "supports_resume_approval": bool(approval_steps),
                "supports_iteration": bool(loop_steps),
                "human_readable_source": pb.get("source", "unknown") in {"builtin", "file", "database"},
            },
        }

    def load_playbook(self, yaml_path: str) -> Dict:
        """Load a single YAML playbook from a file path and register it.

        Args:
            yaml_path: Absolute or relative path to the YAML playbook file.

        Returns:
            Dict with playbook metadata (id, name, step_count) on success,
            or a dict with an ``error`` key on failure.
        """
        if not _HAS_YAML:
            return {"error": "PyYAML is not installed. Install with: pip install pyyaml"}

        path = Path(yaml_path)
        if not path.is_file():
            return {"error": f"Playbook file not found: {yaml_path}"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                definition = yaml.safe_load(f)

            if not isinstance(definition, dict):
                return {"error": f"Invalid playbook format in {path.name} (expected a dict)"}

            pid = definition.get("id", path.stem)
            definition["id"] = pid
            definition["source"] = "file"
            definition["file"] = str(path.resolve())

            validation = self.validate_playbook_definition(definition)
            if not validation.get("valid"):
                first_error = next(
                    (item.get("message") for item in validation.get("issues", []) if item.get("level") == "error"),
                    "Playbook validation failed",
                )
                return {"error": first_error, "validation": validation}

            steps = definition.get("steps", [])
            parsed = [PlaybookStep.from_dict(s) for s in steps]
            definition["_parsed_steps"] = parsed

            self._cache[pid] = definition

            logger.info("[PLAYBOOK] Loaded from file: %s (%d steps)", pid, len(parsed))

            return {
                "id": pid,
                "name": definition.get("name", pid),
                "description": definition.get("description", ""),
                "step_count": len(parsed),
                "source": "file",
                "file": str(path.resolve()),
                "validation": validation,
            }

        except Exception as exc:
            logger.error("[PLAYBOOK] Failed to load %s: %s", yaml_path, exc)
            return {"error": f"Failed to load playbook: {exc}"}

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    def _capture_notify_loop(self) -> None:
        """Capture the main event loop so websocket pub/sub stays thread-safe."""
        if not hasattr(self.agent_loop, "_main_loop"):
            return
        existing_loop = getattr(self.agent_loop, "_main_loop", None)
        if existing_loop is not None:
            try:
                if existing_loop.is_running():
                    return
            except Exception:
                pass
        try:
            self.agent_loop._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            return

    def _notify(self, session_id: str, message: Dict[str, Any]) -> None:
        """Emit progress events via the shared agent pub/sub channel when available."""
        notify = getattr(self.agent_loop, "_notify", None)
        if callable(notify):
            try:
                notify(session_id, message)
            except Exception as exc:
                logger.debug("[PLAYBOOK] notify failed for %s: %s", session_id, exc)

    @staticmethod
    def _preview_result(result: Any, limit: int = 1200) -> str:
        """Return a compact preview string for UI updates."""
        if isinstance(result, str):
            return result[:limit]
        try:
            return json.dumps(result, default=str)[:limit]
        except Exception:
            return str(result)[:limit]

    def _build_session_metadata(
        self,
        playbook_id: str,
        pb: Dict[str, Any],
        input_data: Dict[str, Any],
        max_steps: int,
    ) -> Dict[str, Any]:
        return {
            "execution_mode": "playbook",
            "playbook_id": playbook_id,
            "playbook_name": pb.get("name", playbook_id),
            "input_data": input_data,
            "max_steps": max_steps,
            "current_step": 0,
            "current_step_name": "",
            "pending_approval": None,
            "playbook_resume_state": None,
        }

    def _schedule_execution(
        self,
        session_id: str,
        playbook_id: str,
        pb: Dict[str, Any],
        steps: List["PlaybookStep"],
        context: Dict[str, Any],
        case_id: Optional[str] = None,
        start_step_name: Optional[str] = None,
        step_number: int = 0,
        skip_approval_step: Optional[str] = None,
    ) -> None:
        """Run playbook work in the background so HTTP can return immediately."""

        def _run() -> None:
            asyncio.run(
                self._execute_session(
                    session_id=session_id,
                    playbook_id=playbook_id,
                    pb=pb,
                    steps=steps,
                    context=deepcopy(context),
                    case_id=case_id,
                    start_step_name=start_step_name,
                    step_number=step_number,
                    skip_approval_step=skip_approval_step,
                )
            )

        threading.Thread(
            target=_run,
            daemon=True,
            name=f"playbook-{session_id}",
        ).start()

    async def _execute_session(
        self,
        session_id: str,
        playbook_id: str,
        pb: Dict[str, Any],
        steps: List["PlaybookStep"],
        context: Dict[str, Any],
        case_id: Optional[str] = None,
        start_step_name: Optional[str] = None,
        step_number: int = 0,
        skip_approval_step: Optional[str] = None,
    ) -> None:
        """Internal worker that executes or resumes a playbook session."""
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}
        max_steps = max(len(steps), 1)
        current_step: Optional[PlaybookStep] = (
            step_map.get(start_step_name) if start_step_name else steps[0]
        )

        self.store.update_session_status(session_id, "active")
        self.store.update_session_metadata(
            session_id,
            {
                "execution_mode": "playbook",
                "playbook_id": playbook_id,
                "playbook_name": pb.get("name", playbook_id),
                "max_steps": max_steps,
                "current_step": step_number,
                "current_step_name": current_step.name if current_step else "",
                "pending_approval": None,
                "playbook_resume_state": None,
            },
        )
        self._notify(
            session_id,
            {
                "type": "phase",
                "phase": "thinking",
                "step": step_number,
                "max_steps": max_steps,
                "playbook_id": playbook_id,
            },
        )

        logger.info(
            "[PLAYBOOK] Starting %s (session %s, %d steps)",
            playbook_id, session_id, len(steps),
        )

        try:
            while current_step is not None:
                step_number += 1

                if step_number > 200:
                    summary = "Aborted: exceeded maximum step count (200)"
                    logger.error("[PLAYBOOK] Step limit (200) reached -- aborting")
                    self.store.update_session_status(session_id, "failed", summary=summary)
                    self._notify(
                        session_id,
                        {"type": "failed", "error": summary, "step": step_number - 1, "max_steps": max_steps},
                    )
                    return

                self.store.update_session_metadata(
                    session_id,
                    {"current_step": step_number - 1, "current_step_name": current_step.name},
                )

                if current_step.condition:
                    condition_passed = self.evaluate_condition(current_step.condition, context)

                    if (
                        not current_step.tool
                        and not current_step.action
                        and not current_step.for_each
                        and not current_step.requires_approval
                    ):
                        current_step = self._resolve_next(
                            current_step.on_success if condition_passed else current_step.on_failure,
                            step_map,
                            steps,
                            step_number,
                        )
                        continue

                    if not condition_passed:
                        logger.debug(
                            "[PLAYBOOK] Skipping step '%s' (condition false)",
                            current_step.name,
                        )
                        self._notify(
                            session_id,
                            {
                                "type": "step",
                                "step": step_number - 1,
                                "max_steps": max_steps,
                                "skipped": current_step.name,
                            },
                        )
                        current_step = self._resolve_next(
                            current_step.on_failure, step_map, steps, step_number,
                        )
                        continue

                if current_step.requires_approval and current_step.name != skip_approval_step:
                    params = self._interpolate_params(current_step.params, context)
                    reason = current_step.description or current_step.name
                    approval_id = None
                    if self.governance_store is not None:
                        approval_id = self.governance_store.create_approval(
                            session_id=session_id,
                            case_id=case_id,
                            workflow_id=self._session_workflow_id(session_id),
                            action_type="playbook_step",
                            tool_name=current_step.tool,
                            target=params,
                            rationale=reason,
                            confidence=0.75,
                            metadata={"step_name": current_step.name, "playbook_id": playbook_id},
                        )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="approval_required",
                        content=f"Waiting for approval: {reason}",
                        tool_name=current_step.tool,
                        tool_params=json.dumps(params, default=str),
                    )
                    self.store.update_session_metadata(
                        session_id,
                        {
                            "current_step": step_number,
                            "current_step_name": current_step.name,
                            "pending_approval": {
                                "tool": current_step.tool,
                                "params": params,
                                "reason": reason,
                                "approval_id": approval_id,
                            },
                            "playbook_resume_state": {
                                "playbook_id": playbook_id,
                                "context": deepcopy(context),
                                "step_name": current_step.name,
                                "step_number": step_number,
                                "case_id": case_id,
                            },
                        },
                    )
                    self.store.update_session_status(session_id, "waiting_approval")
                    self._notify(
                        session_id,
                        {
                            "type": "approval_required",
                            "tool": current_step.tool,
                            "params": params,
                            "reason": reason,
                            "step": step_number,
                            "max_steps": max_steps,
                        },
                    )
                    return

                if current_step.action and not current_step.tool:
                    action = current_step.action
                    params = self._interpolate_params(current_step.params, context)
                    self._notify(
                        session_id,
                        {
                            "type": "phase",
                            "phase": "acting",
                            "step": step_number,
                            "max_steps": max_steps,
                            "tool": action,
                            "playbook_id": playbook_id,
                        },
                    )

                    if action == "final_answer":
                        report_text = self._interpolate_string(
                            current_step.description or current_step.name,
                            context,
                        )
                        self._log_decision(
                            session_id,
                            decision_type="playbook_final_answer",
                            summary=report_text,
                            rationale=f"Playbook terminal action for {playbook_id}",
                        )
                        result = {
                            "action": "final_answer",
                            "report": report_text,
                        }
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="final_answer",
                            content=report_text,
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(result, default=str),
                            duration_ms=0,
                        )
                        context[current_step.name] = result
                        context["last_result"] = result
                        self.store.update_session_metadata(
                            session_id,
                            {"current_step": step_number, "current_step_name": current_step.name},
                        )
                        self._notify(
                            session_id,
                            {"type": "step", "step": step_number, "max_steps": max_steps},
                        )
                        self._notify(
                            session_id,
                            {"type": "message", "content": report_text},
                        )
                        current_step = self._resolve_next(
                            current_step.on_success or "end",
                            step_map,
                            steps,
                            step_number,
                        )
                        skip_approval_step = None
                        continue

                    if action == "trigger_playbook":
                        target_pb = params.get("playbook", "")
                        trigger_input = {k: v for k, v in params.items() if k != "playbook"}
                        trigger_input.update(
                            {k: v for k, v in context.items() if k not in ("session_id", "playbook_id", "input")}
                        )

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="trigger_playbook",
                            content=f"Triggering playbook: {target_pb}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )

                        try:
                            sub_session = await self.execute(
                                target_pb,
                                trigger_input,
                                case_id=case_id,
                                wait_for_completion=True,
                            )
                            result = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "sub_session_id": sub_session,
                            }
                        except Exception as exc:
                            logger.warning(
                                "[PLAYBOOK] trigger_playbook '%s' failed: %s",
                                target_pb, exc,
                            )
                            result = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "error": str(exc),
                            }
                        context[current_step.name] = result
                        context["last_result"] = result
                        self.store.update_session_metadata(
                            session_id,
                            {"current_step": step_number, "current_step_name": current_step.name},
                        )
                        self._notify(
                            session_id,
                            {"type": "step", "step": step_number, "max_steps": max_steps},
                        )
                        current_step = self._resolve_next(
                            current_step.on_success or "end",
                            step_map,
                            steps,
                            step_number,
                        )
                        skip_approval_step = None
                        continue

                    if action == "input":
                        prompt = params.get("prompt", current_step.description)
                        result = {"action": "input", "prompt": prompt, "value": prompt}
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="input",
                            content=f"Input: {prompt}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(result, default=str),
                            duration_ms=0,
                        )
                        context[current_step.name] = result
                        context["last_result"] = result
                        self.store.update_session_metadata(
                            session_id,
                            {"current_step": step_number, "current_step_name": current_step.name},
                        )
                        self._notify(
                            session_id,
                            {"type": "step", "step": step_number, "max_steps": max_steps},
                        )
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        skip_approval_step = None
                        continue

                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="action",
                        content=f"Action: {action} - {current_step.description}",
                        tool_name="",
                        tool_params=json.dumps(params, default=str),
                        tool_result="",
                        duration_ms=0,
                    )
                    context[current_step.name] = {"action": action}
                    context["last_result"] = context[current_step.name]
                    self.store.update_session_metadata(
                        session_id,
                        {"current_step": step_number, "current_step_name": current_step.name},
                    )
                    self._notify(
                        session_id,
                        {"type": "step", "step": step_number, "max_steps": max_steps},
                    )
                    current_step = self._resolve_next(
                        current_step.on_success, step_map, steps, step_number,
                    )
                    skip_approval_step = None
                    continue

                self._notify(
                    session_id,
                    {
                        "type": "phase",
                        "phase": "acting",
                        "step": step_number,
                        "max_steps": max_steps,
                        "tool": current_step.tool or current_step.name,
                        "playbook_id": playbook_id,
                    },
                )

                if current_step.for_each:
                    items = _resolve_var(current_step.for_each, context)
                    if not isinstance(items, list):
                        items = [items] if items else []

                    self._notify(
                        session_id,
                        {
                            "type": "tool_call",
                            "tool": current_step.tool,
                            "args": self._interpolate_params(current_step.params, context),
                        },
                    )

                    iteration_results = []
                    for i, item in enumerate(items[:50]):
                        iter_context = {**context, "item": item, "item_index": i}
                        params = self._interpolate_params(current_step.params, iter_context)
                        start = time.time()
                        result = await self._run_tool(
                            current_step.tool,
                            params,
                            current_step.timeout,
                            session_id=session_id,
                            case_id=case_id,
                            workflow_id=self._session_workflow_id(session_id),
                            playbook_id=playbook_id,
                        )
                        duration_ms = int((time.time() - start) * 1000)
                        iteration_results.append(result)

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="for_each_iteration",
                            content=f"{current_step.name} (item {i})",
                            tool_name=current_step.tool,
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(result, default=str)[:10000],
                            duration_ms=duration_ms,
                        )

                    summary_result = self._aggregate_iteration_results(
                        current_step.name,
                        items,
                        iteration_results,
                    )
                    context[current_step.name] = summary_result
                    context[f"{current_step.name}_results"] = iteration_results
                    context["last_result"] = summary_result
                    for key, val in summary_result.items():
                        context[f"{current_step.name}_{key}"] = val
                    has_error = summary_result["has_error"]
                    next_step_name = current_step.on_failure if has_error else current_step.on_success
                    self._notify(
                        session_id,
                        {
                            "type": "tool_result",
                            "tool": current_step.tool,
                            "result_preview": self._preview_result(summary_result),
                        },
                    )

                else:
                    params = self._interpolate_params(current_step.params, context)
                    self._notify(
                        session_id,
                        {"type": "tool_call", "tool": current_step.tool, "args": params},
                    )

                    start = time.time()
                    result = await self._run_tool(
                        current_step.tool,
                        params,
                        current_step.timeout,
                        session_id=session_id,
                        case_id=case_id,
                        workflow_id=self._session_workflow_id(session_id),
                        playbook_id=playbook_id,
                    )
                    duration_ms = int((time.time() - start) * 1000)

                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="tool_call",
                        content=current_step.description or current_step.name,
                        tool_name=current_step.tool,
                        tool_params=json.dumps(params, default=str),
                        tool_result=json.dumps(result, default=str)[:10000],
                        duration_ms=duration_ms,
                    )

                    context[current_step.name] = result
                    context["last_result"] = result
                    if isinstance(result, dict):
                        for key, val in result.items():
                            context[f"{current_step.name}_{key}"] = val

                    success = not (isinstance(result, dict) and "error" in result)
                    next_step_name = (
                        current_step.on_success if success else current_step.on_failure
                    )
                    self._notify(
                        session_id,
                        {
                            "type": "tool_result",
                            "tool": current_step.tool,
                            "result_preview": self._preview_result(result),
                            "duration": duration_ms,
                        },
                    )

                self.store.update_session_metadata(
                    session_id,
                    {"current_step": step_number, "current_step_name": current_step.name},
                )
                self._notify(
                    session_id,
                    {"type": "step", "step": step_number, "max_steps": max_steps},
                )

                if next_step_name == current_step.name:
                    next_step_name = None

                current_step = self._resolve_next(
                    next_step_name, step_map, steps, step_number,
                )
                skip_approval_step = None

            summary = (
                f"Playbook '{pb.get('name', playbook_id)}' completed "
                f"({step_number} steps executed)"
            )
            self.store.update_session_status(session_id, "completed", summary=summary)
            self.store.update_session_metadata(
                session_id,
                {
                    "current_step": step_number,
                    "current_step_name": "",
                    "pending_approval": None,
                    "playbook_resume_state": None,
                },
            )
            logger.info(
                "[PLAYBOOK] Completed %s (session %s, %d steps)",
                playbook_id, session_id, step_number,
            )
            self._notify(
                session_id,
                {"type": "completed", "summary": summary, "step": step_number, "max_steps": max_steps},
            )

        except Exception as exc:
            logger.error(
                "[PLAYBOOK] Execution error in %s step %d: %s",
                playbook_id, step_number, exc,
            )
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="error",
                content=f"Playbook error: {exc}",
            )
            self.store.update_session_status(
                session_id, "failed", summary=f"Error: {str(exc)[:200]}",
            )
            self.store.update_session_metadata(
                session_id,
                {
                    "current_step": max(step_number, 0),
                    "current_step_name": current_step.name if current_step else "",
                    "pending_approval": None,
                },
            )
            self._notify(
                session_id,
                {"type": "failed", "error": str(exc), "step": max(step_number, 0), "max_steps": max_steps},
            )

    async def execute(
        self,
        playbook_id: str,
        input_data: Dict,
        case_id: Optional[str] = None,
        wait_for_completion: bool = False,
    ) -> str:
        """
        Execute a playbook.

        Parameters
        ----------
        playbook_id : str
            ID of the playbook to run.
        input_data : dict
            Initial context variables (e.g. ``{"file_path": "/tmp/mal.exe"}``).
        case_id : str, optional
            Associated case ID for tracking.

        Returns
        -------
        str
            Session ID of the execution.
        """
        pb = self._cache.get(playbook_id)
        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        if not steps:
            raise ValueError(f"Playbook '{playbook_id}' has no steps")

        goal = f"Playbook: {pb.get('name', playbook_id)}"
        session_id = self.store.create_session(
            goal=goal, case_id=case_id, playbook_id=playbook_id,
            metadata=self._build_session_metadata(
                playbook_id=playbook_id,
                pb=pb,
                input_data=input_data,
                max_steps=len(steps),
            ),
        )

        context: Dict[str, Any] = {
            "session_id": session_id,
            "playbook_id": playbook_id,
            "input": input_data,
            **input_data,
        }

        self._capture_notify_loop()

        if wait_for_completion:
            await self._execute_session(
                session_id=session_id,
                playbook_id=playbook_id,
                pb=pb,
                steps=steps,
                context=context,
                case_id=case_id,
            )
            return session_id

        self._schedule_execution(
            session_id=session_id,
            playbook_id=playbook_id,
            pb=pb,
            steps=steps,
            context=context,
            case_id=case_id,
        )
        return session_id

    def _session_workflow_id(self, session_id: str) -> Optional[str]:
        session = self.store.get_session(session_id)
        if not session:
            return None
        metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
        return metadata.get("workflow_id")

    def _log_decision(
        self,
        session_id: str,
        *,
        decision_type: str,
        summary: str,
        rationale: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self.governance_store is None or not summary:
            return
        session = self.store.get_session(session_id)
        if not session:
            return
        session_metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
        try:
            self.governance_store.log_ai_decision(
                session_id=session_id,
                case_id=session.get("case_id"),
                workflow_id=session_metadata.get("workflow_id"),
                profile_id=session_metadata.get("agent_profile_id"),
                decision_type=decision_type,
                summary=summary,
                rationale=rationale,
                metadata=metadata or {},
            )
        except Exception:
            logger.debug("[PLAYBOOK] Failed to log AI decision", exc_info=True)

        '''
        # Build step lookup by name
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}

        logger.info(
            "[PLAYBOOK] Starting %s (session %s, %d steps)",
            playbook_id, session_id, len(steps),
        )

        current_step: Optional[PlaybookStep] = steps[0]
        step_number = 0

        try:
            while current_step is not None:
                step_number += 1

                # Safety: prevent infinite loops
                if step_number > 200:
                    logger.error("[PLAYBOOK] Step limit (200) reached -- aborting")
                    self.store.update_session_status(
                        session_id, "failed",
                        summary="Aborted: exceeded maximum step count (200)",
                    )
                    return session_id

                # Evaluate condition
                if current_step.condition:
                    condition_passed = self.evaluate_condition(current_step.condition, context)

                    if (
                        not current_step.tool
                        and not current_step.action
                        and not current_step.for_each
                        and not current_step.requires_approval
                    ):
                        current_step = self._resolve_next(
                            current_step.on_success if condition_passed else current_step.on_failure,
                            step_map,
                            steps,
                            step_number,
                        )
                        continue

                    if not condition_passed:
                        logger.debug(
                            "[PLAYBOOK] Skipping step '%s' (condition false)",
                            current_step.name,
                        )
                        current_step = self._resolve_next(
                            current_step.on_failure, step_map, steps, step_number,
                        )
                        continue

                # Human approval checkpoint
                if current_step.requires_approval:
                    logger.info(
                        "[PLAYBOOK] Step '%s' requires human approval -- pausing",
                        current_step.name,
                    )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="approval_required",
                        content=f"Waiting for approval: {current_step.description or current_step.name}",
                        tool_name=current_step.tool,
                        tool_params=json.dumps(
                            self._interpolate_params(current_step.params, context),
                            default=str,
                        ),
                    )
                    self.store.update_session_status(session_id, "waiting_approval")

                    # In a real system this would block until approval arrives.
                    # For now we log and return -- the UI / API layer handles
                    # the approval flow and re-calls execute_from_step.
                    return session_id

                # Handle action-only steps (no tool call needed)
                if current_step.action and not current_step.tool:
                    action = current_step.action
                    params = self._interpolate_params(current_step.params, context)

                    if action == "final_answer":
                        report_text = self._interpolate_string(
                            current_step.description or current_step.name,
                            context,
                        )
                        # Terminal step: record description as final report
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="final_answer",
                            content=report_text,
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "final_answer", "report": report_text},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "final_answer",
                            "report": report_text,
                        }
                        context["last_result"] = context[current_step.name]
                        # final_answer is terminal — go to next sequential or end
                        current_step = self._resolve_next(
                            current_step.on_success or "end",
                            step_map,
                            steps,
                            step_number,
                        )
                        continue

                    elif action == "trigger_playbook":
                        # Trigger another playbook
                        target_pb = params.get("playbook", "")
                        trigger_input = {k: v for k, v in params.items() if k != "playbook"}
                        trigger_input.update({k: v for k, v in context.items()
                                              if k not in ("session_id", "playbook_id", "input")})

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="trigger_playbook",
                            content=f"Triggering playbook: {target_pb}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )

                        try:
                            sub_session = await self.execute(
                                target_pb, trigger_input, case_id=case_id,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "sub_session_id": sub_session,
                            }
                        except Exception as exc:
                            logger.warning(
                                "[PLAYBOOK] trigger_playbook '%s' failed: %s",
                                target_pb, exc,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "error": str(exc),
                            }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success or "end",
                            step_map,
                            steps,
                            step_number,
                        )
                        continue

                    elif action == "input":
                        # Input step: use existing context data or record prompt
                        prompt = params.get("prompt", current_step.description)
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="input",
                            content=f"Input: {prompt}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "input", "prompt": prompt, "value": prompt},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "input",
                            "value": prompt,
                        }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    else:
                        # Unknown action — log and skip
                        logger.warning(
                            "[PLAYBOOK] Unknown action '%s' in step '%s'",
                            action, current_step.name,
                        )
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="action",
                            content=f"Action: {action} - {current_step.description}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )
                        context[current_step.name] = {"action": action}
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                # Handle for_each iteration
                if current_step.for_each:
                    items = _resolve_var(current_step.for_each, context)
                    if not isinstance(items, list):
                        items = [items] if items else []

                    logger.debug(
                        "[PLAYBOOK] for_each '%s': %d items",
                        current_step.for_each, len(items),
                    )

                    iteration_results = []
                    for i, item in enumerate(items[:50]):  # Cap iterations
                        iter_context = {**context, "item": item, "item_index": i}
                        params = self._interpolate_params(current_step.params, iter_context)

                        start = time.time()
                        result = await self._run_tool(
                            current_step.tool, params, current_step.timeout,
                        )
                        duration_ms = int((time.time() - start) * 1000)

                        iteration_results.append(result)

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="for_each_iteration",
                            content=f"{current_step.name} (item {i})",
                            tool_name=current_step.tool,
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(result, default=str)[:10000],
                            duration_ms=duration_ms,
                        )

                    context[f"{current_step.name}_results"] = iteration_results
                    context["last_result"] = iteration_results

                    # Determine success
                    has_error = any("error" in r for r in iteration_results if isinstance(r, dict))
                    next_step_name = current_step.on_failure if has_error else current_step.on_success

                else:
                    # Single execution
                    params = self._interpolate_params(current_step.params, context)

                    start = time.time()
                    result = await self._run_tool(
                        current_step.tool, params, current_step.timeout,
                    )
                    duration_ms = int((time.time() - start) * 1000)

                    # Record step
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="tool_call",
                        content=current_step.description or current_step.name,
                        tool_name=current_step.tool,
                        tool_params=json.dumps(params, default=str),
                        tool_result=json.dumps(result, default=str)[:10000],
                        duration_ms=duration_ms,
                    )

                    # Store result in context
                    context[current_step.name] = result
                    context["last_result"] = result

                    # Also expose nested result fields
                    if isinstance(result, dict):
                        for key, val in result.items():
                            context[f"{current_step.name}_{key}"] = val

                    # Determine next step
                    success = not (isinstance(result, dict) and "error" in result)
                    next_step_name = (
                        current_step.on_success if success else current_step.on_failure
                    )

                if next_step_name == current_step.name:
                    next_step_name = None

                # Resolve the next step
                current_step = self._resolve_next(
                    next_step_name, step_map, steps, step_number,
                )

            # All steps completed
            self.store.update_session_status(
                session_id, "completed",
                summary=f"Playbook '{pb.get('name', playbook_id)}' completed "
                        f"({step_number} steps executed)",
            )
            logger.info(
                "[PLAYBOOK] Completed %s (session %s, %d steps)",
                playbook_id, session_id, step_number,
            )

        except Exception as exc:
            logger.error(
                "[PLAYBOOK] Execution error in %s step %d: %s",
                playbook_id, step_number, exc,
            )
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="error",
                content=f"Playbook error: {exc}",
            )
            self.store.update_session_status(
                session_id, "failed", summary=f"Error: {str(exc)[:200]}",
            )

        return session_id
        '''

    async def resume_approval(self, session_id: str, approved: bool) -> bool:
        """Resume a paused playbook session after analyst approval or rejection."""
        session = self.store.get_session(session_id)
        if not session or session.get("status") != "waiting_approval":
            return False

        metadata = session.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        resume_state = metadata.get("playbook_resume_state") or {}
        if not isinstance(resume_state, dict):
            return False

        playbook_id = resume_state.get("playbook_id") or session.get("playbook_id")
        pb = self._cache.get(playbook_id)
        if pb is None:
            return False

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        if not steps:
            return False

        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}
        step_name = resume_state.get("step_name")
        current_step = step_map.get(step_name)
        if current_step is None:
            return False

        context = resume_state.get("context") or {}
        if not isinstance(context, dict):
            context = {}
        step_number = int(resume_state.get("step_number") or 0)
        case_id = resume_state.get("case_id") or session.get("case_id")
        max_steps = max(len(steps), 1)

        self._capture_notify_loop()
        self.store.update_session_metadata(
            session_id,
            {
                "pending_approval": None,
                "playbook_resume_state": None,
                "current_step": max(step_number - 1, 0),
                "current_step_name": step_name,
            },
        )

        if approved:
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="approval_granted",
                content=f"Approval granted for: {current_step.description or current_step.name}",
                tool_name=current_step.tool,
                tool_params=json.dumps(
                    self._interpolate_params(current_step.params, context),
                    default=str,
                ),
            )
            self.store.update_session_status(session_id, "active")
            self._notify(
                session_id,
                {"type": "message", "content": f"Approval granted. Resuming playbook '{pb.get('name', playbook_id)}'."},
            )
            self._schedule_execution(
                session_id=session_id,
                playbook_id=playbook_id,
                pb=pb,
                steps=steps,
                context=context,
                case_id=case_id,
                start_step_name=step_name,
                step_number=max(step_number - 1, 0),
                skip_approval_step=step_name,
            )
            return True

        self.store.add_step(
            session_id=session_id,
            step_number=step_number,
            step_type="approval_rejected",
            content=f"Approval rejected for: {current_step.description or current_step.name}",
            tool_name=current_step.tool,
            tool_params=json.dumps(
                self._interpolate_params(current_step.params, context),
                default=str,
            ),
        )
        self._notify(
            session_id,
            {"type": "message", "content": f"Approval rejected for step '{current_step.name}'."},
        )

        next_step = self._resolve_next(current_step.on_failure, step_map, steps, step_number)
        if next_step is None:
            summary = f"Playbook '{pb.get('name', playbook_id)}' stopped after approval was rejected"
            self.store.update_session_status(session_id, "cancelled", summary=summary)
            self.store.update_session_metadata(
                session_id,
                {"current_step": step_number, "current_step_name": ""},
            )
            self._notify(
                session_id,
                {"type": "cancelled", "summary": summary, "step": step_number, "max_steps": max_steps},
            )
            return True

        context["last_result"] = {
            "approval": "rejected",
            "step_name": step_name,
            "tool": current_step.tool,
        }
        self.store.update_session_status(session_id, "active")
        self._schedule_execution(
            session_id=session_id,
            playbook_id=playbook_id,
            pb=pb,
            steps=steps,
            context=context,
            case_id=case_id,
            start_step_name=next_step.name,
            step_number=step_number,
        )
        return True

    # ------------------------------------------------------------------ #
    #  Condition evaluation
    # ------------------------------------------------------------------ #

    def evaluate_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate a step condition against the current context.

        Delegates to ``safe_evaluate_condition`` which uses pattern matching
        instead of eval() for safety.

        Supported syntax:
        - ``verdict == 'MALICIOUS'``
        - ``score > 70``
        - ``score >= 50 and verdict != 'CLEAN'``
        - ``'ransomware' in tags``
        - ``file_type in ('PE', 'ELF')``
        """
        return safe_evaluate_condition(condition, context)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    async def _run_tool(
        self,
        tool_name: str,
        params: Dict,
        timeout: int,
        *,
        session_id: Optional[str] = None,
        case_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
    ) -> Dict:
        """
        Run a tool via the agent loop with a timeout.

        Returns the tool result dict, or an ``error`` dict on failure/timeout.
        """
        try:
            if hasattr(self.agent_loop, "run_tool"):
                import asyncio
                result = await asyncio.wait_for(
                    self.agent_loop.run_tool(
                        tool_name,
                        params,
                        execution_context={
                            "session_id": session_id,
                            "case_id": case_id,
                            "workflow_id": workflow_id,
                            "playbook_id": playbook_id,
                        },
                    ),
                    timeout=timeout,
                )
                return result if isinstance(result, dict) else {"result": result}
            else:
                return {"error": "agent_loop has no run_tool method"}
        except TimeoutError:
            return {"error": f"Tool '{tool_name}' timed out after {timeout}s"}
        except Exception as exc:
            return {"error": f"Tool '{tool_name}' failed: {exc}"}

    @staticmethod
    def _result_is_threat(result: Dict[str, Any]) -> bool:
        """Heuristic summary used for iterative enrichment steps."""
        if not isinstance(result, dict):
            return False

        verdict = str(result.get("verdict", "")).upper()
        if verdict in {"MALICIOUS", "SUSPICIOUS", "PHISHING", "SPAM", "KNOWN MALWARE"}:
            return True

        for key in ("malicious", "blocklisted", "found", "confirmed", "is_tor_exit_node"):
            if result.get(key) is True:
                return True

        try:
            if float(result.get("threat_score", 0)) >= 60:
                return True
        except Exception:
            pass

        return False

    def _aggregate_iteration_results(
        self,
        step_name: str,
        items: List[Any],
        iteration_results: List[Any],
    ) -> Dict[str, Any]:
        """Create a playbook-friendly aggregate object for ``for_each`` steps."""
        summary: Dict[str, Any] = {
            "results": iteration_results,
            "items": items,
            "results_count": len(iteration_results),
            "items_processed": len(items),
            "success_count": 0,
            "error_count": 0,
            "malicious": False,
            "suspicious": False,
            "blocklisted": False,
            "found": False,
            "confirmed_threats": 0,
            "matched_iocs": [],
            "malicious_iocs": [],
            "suspicious_indicators": [],
            "suspicious_files": [],
            "suspicious_executables": [],
            "malicious_artifacts": [],
            "file_paths": [],
            "executables": [],
        }

        seen_values = {
            "matched_iocs": set(),
            "malicious_iocs": set(),
            "suspicious_indicators": set(),
            "suspicious_files": set(),
            "suspicious_executables": set(),
            "malicious_artifacts": set(),
            "file_paths": set(),
            "executables": set(),
        }

        def _append_unique(bucket: str, value: Any) -> None:
            if value in (None, "", [], {}):
                return
            if isinstance(value, (list, tuple, set)):
                for nested in value:
                    _append_unique(bucket, nested)
                return
            if isinstance(value, dict):
                for nested_key in ("ioc", "indicator", "ip", "domain", "url", "file_path", "path", "filename", "sha256"):
                    if nested_key in value:
                        _append_unique(bucket, value.get(nested_key))
                return

            text = str(value).strip()
            if not text or text in seen_values[bucket]:
                return
            seen_values[bucket].add(text)
            summary[bucket].append(text)

        for index, raw_result in enumerate(iteration_results):
            result = raw_result if isinstance(raw_result, dict) else {"result": raw_result}
            item = items[index] if index < len(items) else None
            verdict = str(result.get("verdict", "")).upper()
            threaty = self._result_is_threat(result)

            if "error" in result:
                summary["error_count"] += 1
            else:
                summary["success_count"] += 1

            summary["malicious"] = summary["malicious"] or bool(result.get("malicious")) or threaty
            summary["suspicious"] = summary["suspicious"] or verdict in {"SUSPICIOUS", "PHISHING", "SPAM"}
            summary["blocklisted"] = summary["blocklisted"] or bool(result.get("blocklisted"))
            summary["found"] = summary["found"] or bool(result.get("found")) or threaty

            if threaty:
                summary["confirmed_threats"] += 1

            for candidate in (
                result.get("ioc"),
                result.get("indicator"),
                result.get("ip"),
                result.get("domain"),
                result.get("url"),
                result.get("hash_value"),
                result.get("sha256"),
                item,
            ):
                _append_unique("matched_iocs", candidate)
                if threaty:
                    _append_unique("malicious_iocs", candidate)
                    _append_unique("suspicious_indicators", candidate)

            _append_unique("suspicious_indicators", result.get("suspicious_indicators"))
            _append_unique("malicious_iocs", result.get("malicious_iocs"))

            for file_key in ("file_path", "path", "filename", "suspicious_files", "malicious_artifacts"):
                _append_unique("suspicious_files", result.get(file_key))
                _append_unique("file_paths", result.get(file_key))
                if threaty:
                    _append_unique("malicious_artifacts", result.get(file_key))

            for exec_key in ("executables", "suspicious_executables", "executable", "process_path"):
                _append_unique("suspicious_executables", result.get(exec_key))
                _append_unique("executables", result.get(exec_key))

            if isinstance(item, dict):
                for item_key in ("path", "file_path", "filename"):
                    _append_unique("file_paths", item.get(item_key))
                    _append_unique("suspicious_files", item.get(item_key))
                    if threaty:
                        _append_unique("malicious_artifacts", item.get(item_key))
            else:
                _append_unique("matched_iocs", item)
                if threaty:
                    _append_unique("malicious_iocs", item)

        summary["has_error"] = summary["error_count"] > 0
        summary["step_name"] = step_name
        return summary

    def _interpolate_params(self, params: Dict, context: Dict) -> Dict:
        """
        Replace ``{{variable}}`` placeholders in parameter values with
        values from the context.

        Supports:
        - ``{{file_path}}`` -- simple variable
        - ``{{step_name.field}}`` -- nested access
        - ``{{item}}`` -- current for_each item
        """
        result = {}
        for key, value in params.items():
            result[key] = self._interpolate_value(value, context)
        return result

    @classmethod
    def _interpolate_value(cls, value: Any, context: Dict) -> Any:
        """Preserve raw dict/list values when a template is the full value."""
        if isinstance(value, str):
            match = re.fullmatch(r"\s*\{\{(.+?)\}\}\s*", value)
            if match:
                resolved = _resolve_var(match.group(1).strip(), context)
                if resolved is not None:
                    return deepcopy(resolved)
            return cls._interpolate_string(value, context)
        if isinstance(value, dict):
            return {k: cls._interpolate_value(v, context) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._interpolate_value(item, context) for item in value]
        return value

    @staticmethod
    def _interpolate_string(template: str, context: Dict) -> str:
        """Replace ``{{var}}`` tokens in a string."""

        def _replacer(match):
            var_path = match.group(1).strip()
            resolved = _resolve_var(var_path, context)
            if resolved is not None:
                return str(resolved)
            return match.group(0)  # Leave placeholder as-is

        return re.sub(r"\{\{(.+?)\}\}", _replacer, template)

    @staticmethod
    def _resolve_next(
        next_name: Optional[str],
        step_map: Dict[str, PlaybookStep],
        steps: List[PlaybookStep],
        current_index: int,
    ) -> Optional[PlaybookStep]:
        """
        Resolve the next step to execute.

        If ``next_name`` is given, look it up in ``step_map``.
        Otherwise fall through to the next sequential step.
        ``None`` means the playbook is done.
        """
        if next_name == "__end__" or next_name == "end":
            return None

        if next_name:
            return step_map.get(next_name)

        # Default: next sequential step
        if current_index < len(steps):
            return steps[current_index]

        return None

    # ------------------------------------------------------------------ #
    #  Playbook creation
    # ------------------------------------------------------------------ #

    def register_playbook(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        trigger_type: str = "manual",
    ) -> str:
        """
        Register a new playbook (saved to DB and cache).

        Returns the playbook ID.
        """
        # Validate steps
        parsed = [PlaybookStep.from_dict(s) for s in steps]

        pid = self.store.save_playbook(
            name=name,
            description=description,
            steps=steps,
            trigger_type=trigger_type,
        )

        self._cache[pid] = {
            "id": pid,
            "name": name,
            "description": description,
            "steps": steps,
            "_parsed_steps": parsed,
            "source": "database",
            "trigger_type": trigger_type,
        }

        logger.info("[PLAYBOOK] Registered: %s (%d steps)", name, len(parsed))
        return pid
