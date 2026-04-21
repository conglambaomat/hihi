"""Investigation planning helpers for agentic CABTA sessions."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class InvestigationPlan:
    goal: str
    lane: str
    workflow_id: Optional[str]
    lead_profile: str
    primary_entities: List[str]
    observable_summary: List[str]
    incident_type: str
    evidence_gaps: List[str]
    initial_hypotheses: List[str]
    first_pivots: List[str]
    next_action_signals: List[Dict[str, Any]]
    stopping_conditions: List[str]
    escalation_conditions: List[str]
    triage_contracts: List[Dict[str, Any]]
    deterministic_verdict_owner: str = "CABTA deterministic core"
    generated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InvestigationPlanner:
    """Build a lightweight, JSON-friendly plan for each investigation session."""

    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    _HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    _CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    def build_plan(
        self,
        goal: str,
        *,
        metadata: Optional[Dict[str, Any]] = None,
        workflow_registry: Any = None,
        existing: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(existing, dict) and existing.get("lane") and existing.get("goal"):
            return self._normalize_existing(existing, goal=goal)

        meta = dict(metadata or {})
        lane = self._classify_lane(goal, meta)
        primary_entities = self._primary_entities(goal, lane)
        observable_summary = self._observable_summary(goal, primary_entities, metadata=meta)
        workflow_id = self._select_workflow_id(
            lane,
            workflow_registry,
            meta,
            goal=goal,
            primary_entities=primary_entities,
            observable_summary=observable_summary,
        )
        lead_profile = self._select_lead_profile(
            lane,
            workflow_registry,
            meta,
            workflow_id=workflow_id,
            goal=goal,
            primary_entities=primary_entities,
            observable_summary=observable_summary,
        )
        incident_type = self._incident_type(goal, lane, observable_summary, metadata=meta)
        evidence_gaps = self._evidence_gaps(lane, observable_summary, metadata=meta)
        initial_hypotheses = self._initial_hypotheses(
            goal,
            lane,
            primary_entities,
            observable_summary=observable_summary,
            metadata=meta,
        )
        first_pivots = self._first_pivots(lane, primary_entities, observable_summary, evidence_gaps)
        next_action_signals = self._next_action_signals(
            lane,
            observable_summary,
            evidence_gaps,
            initial_hypotheses,
            metadata=meta,
        )
        stopping_conditions = self._stopping_conditions(
            lane,
            evidence_gaps,
            observable_summary=observable_summary,
            metadata=meta,
        )
        escalation_conditions = self._escalation_conditions(
            lane,
            evidence_gaps,
            observable_summary=observable_summary,
            metadata=meta,
        )
        triage_contracts = self._triage_contracts(
            lane,
            observable_summary,
            evidence_gaps,
            first_pivots,
            stopping_conditions,
            escalation_conditions,
            metadata=meta,
        )
        plan = InvestigationPlan(
            goal=str(goal or "").strip(),
            lane=lane,
            workflow_id=workflow_id,
            lead_profile=lead_profile,
            primary_entities=primary_entities,
            observable_summary=observable_summary,
            incident_type=incident_type,
            evidence_gaps=evidence_gaps,
            initial_hypotheses=initial_hypotheses,
            first_pivots=first_pivots,
            next_action_signals=next_action_signals,
            stopping_conditions=stopping_conditions,
            escalation_conditions=escalation_conditions,
            triage_contracts=triage_contracts,
        )
        return plan.to_dict()

    def _normalize_existing(self, existing: Dict[str, Any], *, goal: str) -> Dict[str, Any]:
        payload = dict(existing)
        payload["goal"] = str(goal or payload.get("goal") or "").strip()
        payload.setdefault("workflow_id", None)
        payload.setdefault("lead_profile", "investigator")
        payload["primary_entities"] = [str(item) for item in payload.get("primary_entities", []) if str(item).strip()]
        payload["observable_summary"] = [str(item) for item in payload.get("observable_summary", []) if str(item).strip()]
        payload["incident_type"] = str(
            payload.get("incident_type")
            or self._incident_type(
                payload["goal"],
                payload.get("lane", "generic"),
                payload["observable_summary"],
                metadata=payload,
            )
        ).strip()
        payload["evidence_gaps"] = [str(item) for item in payload.get("evidence_gaps", []) if str(item).strip()]
        payload["initial_hypotheses"] = [str(item) for item in payload.get("initial_hypotheses", []) if str(item).strip()]
        payload["first_pivots"] = [str(item) for item in payload.get("first_pivots", []) if str(item).strip()]
        payload["next_action_signals"] = self._normalize_next_action_signals(payload.get("next_action_signals"))
        payload["stopping_conditions"] = [str(item) for item in payload.get("stopping_conditions", []) if str(item).strip()]
        payload["escalation_conditions"] = [str(item) for item in payload.get("escalation_conditions", []) if str(item).strip()]
        payload["triage_contracts"] = self._normalize_triage_contracts(payload.get("triage_contracts"))
        payload["deterministic_verdict_owner"] = str(
            payload.get("deterministic_verdict_owner") or "CABTA deterministic core"
        ).strip() or "CABTA deterministic core"
        payload.setdefault("generated_at", _now_iso())
        normalized_payload = {
            "goal": payload["goal"],
            "lane": str(payload.get("lane") or "generic").strip() or "generic",
            "workflow_id": payload.get("workflow_id"),
            "lead_profile": payload["lead_profile"],
            "primary_entities": payload["primary_entities"],
            "observable_summary": payload["observable_summary"],
            "incident_type": payload["incident_type"],
            "evidence_gaps": payload["evidence_gaps"],
            "initial_hypotheses": payload["initial_hypotheses"],
            "first_pivots": payload["first_pivots"],
            "next_action_signals": payload["next_action_signals"],
            "stopping_conditions": payload["stopping_conditions"],
            "escalation_conditions": payload["escalation_conditions"],
            "triage_contracts": payload["triage_contracts"],
            "deterministic_verdict_owner": payload["deterministic_verdict_owner"],
            "generated_at": payload["generated_at"],
        }
        return InvestigationPlan(**normalized_payload).to_dict()

    def _classify_lane(self, goal: str, metadata: Dict[str, Any]) -> str:
        lowered = str(goal or "").lower()
        capability_text = " ".join(
            str(item).lower()
            for item in (
                metadata.get("workflow_id"),
                metadata.get("agent_profile_id"),
                metadata.get("capability"),
                metadata.get("capability_id"),
                metadata.get("capability_family"),
            )
            if str(item or "").strip()
        )
        observable_hint_text = " ".join(
            str(item).lower()
            for item in (
                metadata.get("observable_summary"),
                metadata.get("observables"),
                metadata.get("observable_set"),
                metadata.get("accepted_facts"),
                metadata.get("entity_hints"),
                metadata.get("typed_fact_hints"),
            )
            if str(item or "").strip()
        )
        combined_text = f"{lowered} {capability_text} {observable_hint_text}".strip()
        if metadata.get("chat_parent_session_id"):
            if any(token in lowered for token in ("pivot", "related", "follow-up", "recap", "explain", "challenge")):
                return "case_follow_up"
        if any(token in combined_text for token in ("email", "phish", "sender", "dmarc", "dkim", "spf", "mail")):
            return "email"
        if any(token in combined_text for token in ("malware", "sample", "exe", "dll", "payload", "sandbox", "file", "process")):
            return "file"
        if any(
            token in combined_text
            for token in (
                "splunk",
                "log",
                "timeline",
                "session",
                "signin",
                "login",
                "identity",
                "telemetry",
                "hunt",
                "fortigate",
                "fortigate traffic",
                "outbound",
                "egress",
                "firewall",
                "winlogon",
                "4624",
                "4625",
            )
        ):
            return "log_identity"
        if any(token in combined_text for token in ("cve", "vulnerability", "exploit", "patch")):
            return "vulnerability"
        if any(token in combined_text for token in ("ioc", "domain", "ip", "hash", "url", "indicator")):
            return "ioc"
        if self._IP_RE.search(combined_text) or self._DOMAIN_RE.search(combined_text) or self._HASH_RE.search(combined_text):
            return "ioc"
        return "generic"

    def _metadata_capability_text(self, metadata: Dict[str, Any]) -> str:
        return " ".join(
            str(item).lower()
            for item in (
                metadata.get("workflow_id"),
                metadata.get("agent_profile_id"),
                metadata.get("capability"),
                metadata.get("capability_id"),
                metadata.get("capability_family"),
                metadata.get("workflow_hint"),
            )
            if str(item or "").strip()
        )

    def _workflow_truth_candidates(self, workflow_registry: Any) -> List[Dict[str, Any]]:
        if workflow_registry is None:
            return []
        try:
            items = workflow_registry.list_workflows()
        except Exception:
            return []
        return [dict(item) for item in items if isinstance(item, dict) and str(item.get("id") or "").strip()]

    def _score_workflow_candidate(
        self,
        workflow: Dict[str, Any],
        *,
        lane: str,
        metadata: Dict[str, Any],
        goal: str,
        primary_entities: List[str],
        observable_summary: List[str],
    ) -> int:
        workflow_id = str(workflow.get("id") or "").strip().lower()
        workflow_name = str(workflow.get("name") or "").strip().lower()
        default_profile = str(workflow.get("default_agent_profile") or "").strip().lower()
        capabilities = [str(item).strip().lower() for item in workflow.get("capabilities", []) if str(item).strip()]
        trigger_examples = [
            str(item).strip().lower() for item in workflow.get("trigger_examples", []) if str(item).strip()
        ]

        goal_text = str(goal or "").lower()
        capability_text = self._metadata_capability_text(metadata)
        observable_text = " ".join(str(item).lower() for item in observable_summary)
        entity_text = " ".join(str(item).lower() for item in primary_entities)
        combined_text = " ".join(
            part for part in (goal_text, capability_text, observable_text, entity_text) if part.strip()
        )

        score = 0
        explicit_workflow_id = str(metadata.get("workflow_id") or "").strip().lower()
        explicit_profile = str(metadata.get("agent_profile_id") or "").strip().lower()

        if explicit_workflow_id and explicit_workflow_id == workflow_id:
            score += 100
        if explicit_profile and explicit_profile == default_profile:
            score += 25

        lane_keyword_map = {
            "ioc": ("ioc", "indicator", "ip", "domain", "url", "hash", "threat_intel"),
            "email": ("email", "phish", "bec", "sender", "attachment", "mail"),
            "file": ("forensic", "artifact", "timeline", "malware", "host", "evidence"),
            "log_identity": ("investigation", "timeline", "session", "identity", "hunt", "log"),
            "vulnerability": ("investigation", "exposure", "vulnerability", "exploit"),
            "case_follow_up": ("investigation", "case", "follow-up", "recap"),
        }
        for token in lane_keyword_map.get(lane, ()):
            if token in workflow_id or token in workflow_name or any(token in item for item in capabilities):
                score += 6

        for capability in capabilities:
            if capability and capability in combined_text:
                score += 10
            elif capability.replace("-", " ") in combined_text:
                score += 8

        if "ioc-triage" == workflow_id:
            if lane == "ioc":
                score += 20
            if any(entity in {"ip", "domain", "hash", "cve", "ioc"} for entity in primary_entities):
                score += 10
        if "phishing-investigation" == workflow_id:
            if lane == "email":
                score += 20
            if any(token in combined_text for token in ("phish", "bec", "email", "mail", "sender", "attachment")):
                score += 12
        if "forensic-analysis" == workflow_id:
            if lane in {"file", "log_identity"}:
                score += 18
            if any(token in combined_text for token in ("forensic", "timeline", "artifact", "host", "malware", "sandbox")):
                score += 12
        if "full-investigation" == workflow_id:
            if lane in {"log_identity", "vulnerability", "case_follow_up"}:
                score += 16
        if "threat-hunt" == workflow_id:
            if any(token in combined_text for token in ("hunt", "telemetry", "search_logs", "splunk")):
                score += 12

        if default_profile and default_profile in combined_text:
            score += 10

        for example in trigger_examples[:3]:
            if example and any(token in combined_text for token in example.split()[:5]):
                score += 3

        return score

    def _select_workflow_id(
        self,
        lane: str,
        workflow_registry: Any,
        metadata: Dict[str, Any],
        *,
        goal: str,
        primary_entities: List[str],
        observable_summary: List[str],
    ) -> Optional[str]:
        explicit = str(metadata.get("workflow_id") or "").strip()
        if explicit:
            return explicit

        workflow_candidates = self._workflow_truth_candidates(workflow_registry)
        if workflow_candidates:
            scored: List[tuple[int, str]] = []
            for workflow in workflow_candidates:
                score = self._score_workflow_candidate(
                    workflow,
                    lane=lane,
                    metadata=metadata,
                    goal=goal,
                    primary_entities=primary_entities,
                    observable_summary=observable_summary,
                )
                if score > 0:
                    scored.append((score, str(workflow.get("id")).strip()))
            if scored:
                scored.sort(key=lambda item: (-item[0], item[1]))
                best_score, best_workflow_id = scored[0]
                if best_score >= 12:
                    return best_workflow_id

        candidate_by_lane = {
            "ioc": "ioc-triage",
            "email": "phishing-investigation",
            "file": "forensic-analysis",
            "log_identity": "full-investigation",
            "case_follow_up": "full-investigation",
            "vulnerability": "full-investigation",
        }.get(lane)
        if not candidate_by_lane or workflow_registry is None:
            return candidate_by_lane
        try:
            workflow = workflow_registry.get_workflow(candidate_by_lane)
            if workflow:
                return candidate_by_lane
        except Exception:
            return candidate_by_lane
        return None

    def _select_lead_profile(
        self,
        lane: str,
        workflow_registry: Any,
        metadata: Dict[str, Any],
        *,
        workflow_id: Optional[str],
        goal: str,
        primary_entities: List[str],
        observable_summary: List[str],
    ) -> str:
        explicit_profile = str(metadata.get("agent_profile_id") or "").strip()
        if explicit_profile:
            return explicit_profile
        if workflow_id and workflow_registry is not None:
            try:
                workflow = workflow_registry.get_workflow(workflow_id)
            except Exception:
                workflow = None
            if isinstance(workflow, dict):
                workflow_profile = str(workflow.get("default_agent_profile") or "").strip()
                if workflow_profile:
                    return workflow_profile
        workflow_candidates = self._workflow_truth_candidates(workflow_registry)
        if workflow_candidates:
            scored_profiles: List[tuple[int, str]] = []
            for workflow in workflow_candidates:
                profile = str(workflow.get("default_agent_profile") or "").strip()
                if not profile:
                    continue
                score = self._score_workflow_candidate(
                    workflow,
                    lane=lane,
                    metadata=metadata,
                    goal=goal,
                    primary_entities=primary_entities,
                    observable_summary=observable_summary,
                )
                if score > 0:
                    scored_profiles.append((score, profile))
            if scored_profiles:
                scored_profiles.sort(key=lambda item: (-item[0], item[1]))
                best_score, best_profile = scored_profiles[0]
                if best_score >= 12:
                    return best_profile
        return self._lead_profile_for_lane(lane)

    def _lead_profile_for_lane(self, lane: str) -> str:
        return {
            "email": "phishing_analyst",
            "file": "malware_analyst",
            "log_identity": "investigator",
            "vulnerability": "investigator",
            "case_follow_up": "investigator",
            "ioc": "investigator",
        }.get(lane, "investigator")

    def _primary_entities(self, goal: str, lane: str) -> List[str]:
        text = str(goal or "")
        entities: List[str] = []
        if self._IP_RE.search(text):
            entities.append("ip")
        if self._DOMAIN_RE.search(text):
            entities.append("domain")
        if self._EMAIL_RE.search(text):
            entities.extend(["email", "user"])
        if self._HASH_RE.search(text):
            entities.append("hash")
        if self._CVE_RE.search(text):
            entities.append("cve")
        if lane == "log_identity":
            entities.extend(["user", "host", "session", "process"])
        elif lane == "email":
            entities.extend(["sender", "recipient", "url", "attachment"])
        elif lane == "file":
            entities.extend(["file", "process", "host", "hash"])
        elif lane == "ioc":
            entities.extend(["ioc", "ip", "domain", "url", "hash"])
        return self._dedupe(entities)[:8]

    def _initial_hypotheses(
        self,
        goal: str,
        lane: str,
        primary_entities: List[str],
        *,
        observable_summary: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        focus = ", ".join(primary_entities[:4]) if primary_entities else "the submitted observable"
        observables = [str(item).strip() for item in (observable_summary or []) if str(item).strip()]
        meta = metadata or {}
        typed_fact_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("typed_fact_hints"),
                meta.get("entity_hints"),
                meta.get("accepted_facts"),
                meta.get("observable_summary"),
                meta.get("observables"),
            )
            if str(item or "").strip()
        )
        combined_text = f"{str(goal or '').lower()} {typed_fact_text}".strip()
        observable_focus = ", ".join(observables[:3]) if observables else focus

        hypotheses = [
            f"The activity around {observable_focus} reflects a real malicious security incident.",
            f"The available telemetry around {observable_focus} is benign, noisy, or still insufficient for a confident conclusion.",
        ]

        if lane == "email":
            hypotheses.append("Initial access likely occurred through phishing, malicious email content, or a delivered attachment or link.")
            if any(token in combined_text for token in ("bec", "business email compromise", "invoice", "spoof", "impersonat")):
                hypotheses.append("The email may represent impersonation, business email compromise, or sender trust abuse rather than generic spam.")
        elif lane == "file":
            hypotheses.append("The investigation likely centers on malware execution, staged payload behavior, or host-level process activity.")
            if any(token in combined_text for token in ("loader", "ransom", "payload", "sandbox", "yara", "execution")):
                hypotheses.append("The strongest file hypothesis is that a suspicious binary or staged payload executed and produced follow-on host activity.")
        elif lane == "log_identity":
            hypotheses.append("Credential misuse, session hijacking, or anomalous identity activity is the strongest specialized hypothesis.")
            if any(token in combined_text for token in ("mfa", "signin", "login", "session", "impossible travel", "credential")):
                hypotheses.append("The observed pattern may be driven by compromised credentials, session abuse, or identity control weakness.")
        elif lane == "vulnerability":
            hypotheses.append("The alert may be tied to exploitation of a known vulnerability or exposed service.")
            if any(token in combined_text for token in ("cve-", "exploit", "exposed", "patch", "vulnerability")):
                hypotheses.append("A known exposure may have enabled initial access, execution, or downstream attacker activity.")
        else:
            hypotheses.append(f"The strongest explanation should be tied back to a causal chain involving {focus}.")

        if any(token in combined_text for token in ("c2", "command and control", "beacon", "callback")):
            hypotheses.append("The observable set may be linked to command-and-control or recurring callback infrastructure.")
        if any(token in combined_text for token in ("delivery", "attachment", "sender", "recipient")) and lane != "email":
            hypotheses.append("A delivery-oriented initial access vector may connect the current evidence to earlier user-facing activity.")
        if any(token in combined_text for token in ("host:", "user:", "session:", "process:")):
            hypotheses.append("Entity linkage between the named host, user, session, or process will likely determine whether the case is causal or coincidental.")
        if "registrar" in str(goal or "").lower():
            hypotheses.append("Infrastructure ownership or registration details will help distinguish commodity abuse from targeted malicious staging.")
        return self._dedupe(hypotheses)[:6]

    def _observable_summary(self, goal: str, primary_entities: List[str], *, metadata: Optional[Dict[str, Any]] = None) -> List[str]:
        text = str(goal or "")
        summary: List[str] = []
        summary.extend(self._IP_RE.findall(text))
        summary.extend(item.lower() for item in self._DOMAIN_RE.findall(text))
        summary.extend(item.lower() for item in self._EMAIL_RE.findall(text))
        summary.extend(item.lower() for item in self._HASH_RE.findall(text))
        summary.extend(item.upper() for item in self._CVE_RE.findall(text))
        summary.extend(self._metadata_observable_summary(metadata or {}))
        if not summary and primary_entities:
            summary.extend(primary_entities[:3])
        return self._dedupe(summary)[:8]

    def _metadata_observable_summary(self, metadata: Dict[str, Any]) -> List[str]:
        summary: List[str] = []

        def _collect(value: Any) -> None:
            if isinstance(value, dict):
                for nested in value.values():
                    _collect(nested)
                return
            if isinstance(value, list):
                for nested in value:
                    _collect(nested)
                return
            text = str(value or "").strip()
            if not text:
                return
            summary.extend(self._IP_RE.findall(text))
            summary.extend(item.lower() for item in self._DOMAIN_RE.findall(text))
            summary.extend(item.lower() for item in self._EMAIL_RE.findall(text))
            summary.extend(item.lower() for item in self._HASH_RE.findall(text))
            summary.extend(item.upper() for item in self._CVE_RE.findall(text))

        for key in (
            "observable_summary",
            "observables",
            "observable_set",
            "accepted_facts",
            "entity_hints",
            "typed_fact_hints",
            "entity_state",
            "evidence_state",
        ):
            _collect(metadata.get(key))
        return self._dedupe(summary)[:8]

    def _incident_type(
        self,
        goal: str,
        lane: str,
        observable_summary: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        lowered = str(goal or "").lower()
        meta = metadata or {}
        capability_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("workflow_id"),
                meta.get("agent_profile_id"),
                meta.get("capability"),
                meta.get("capability_id"),
                meta.get("capability_family"),
            )
            if str(item or "").strip()
        )
        typed_fact_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("typed_fact_hints"),
                meta.get("entity_hints"),
                meta.get("observable_summary"),
                meta.get("observables"),
                meta.get("accepted_facts"),
            )
            if str(item or "").strip()
        )
        combined_text = f"{lowered} {capability_text} {typed_fact_text}".strip()
        observable_text = " ".join(str(item).lower() for item in observable_summary)

        if lane == "email":
            if any(token in combined_text for token in ("attachment", "invoice", "spoof", "dmarc", "dkim", "spf", "delivery")):
                return "phishing_or_malicious_email"
            return "email_or_identity_artifact"
        if lane == "file":
            if any(token in combined_text for token in ("ransom", "loader", "payload", "sandbox", "yara", "execution")):
                return "malware_or_file_execution"
            return "file_or_process_artifact"
        if lane == "log_identity":
            if any(
                token in combined_text
                for token in (
                    "fortigate",
                    "outbound",
                    "egress",
                    "firewall",
                    "beacon",
                    "callback",
                    "destination",
                    "dest_ip",
                )
            ):
                return "fortigate_outbound_monitoring"
            if any(
                token in combined_text
                for token in (
                    "4624",
                    "4625",
                    "winlogon",
                    "windows logon",
                    "login",
                    "signin",
                    "session",
                    "credential",
                    "identity",
                    "impossible travel",
                )
            ):
                return "windows_logon_monitoring"
            if any(token in combined_text for token in ("mfa", "signin", "login", "session", "credential", "identity", "impossible travel")):
                return "identity_or_session_activity"
            return "log_or_identity_activity"
        if lane == "vulnerability":
            return "vulnerability_exposure_or_exploitation"
        if any(item.startswith("cve-") for item in observable_summary):
            return "vulnerability_exposure_or_exploitation"
        if any("@" in item for item in observable_summary):
            return "email_or_identity_artifact"
        if any(self._HASH_RE.fullmatch(item) for item in observable_summary):
            return "file_or_malware_artifact"
        if any(self._IP_RE.fullmatch(item) for item in observable_summary) and any(
            token in combined_text or token in observable_text
            for token in ("c2", "command and control", "beacon", "tor", "egress", "callback")
        ):
            return "suspected_command_and_control"
        if any(self._DOMAIN_RE.fullmatch(item) for item in observable_summary) and any(
            token in combined_text or token in observable_text
            for token in ("phish", "spoof", "brand", "mail", "delivery")
        ):
            return "suspected_phishing_infrastructure"
        if any(token in combined_text for token in ("c2", "command and control", "beacon")):
            return "suspected_command_and_control"
        return "general_security_investigation"

    def _evidence_gaps(self, lane: str, observable_summary: List[str], *, metadata: Dict[str, Any]) -> List[str]:
        gaps: List[str] = []
        if lane == "log_identity":
            gaps.extend(
                [
                    "Need explicit user, host, session, and process linkage.",
                    "Need stronger attribution between auth evidence and downstream process or network activity.",
                ]
            )
            typed_fact_text = " ".join(
                str(item).lower()
                for item in (
                    metadata.get("typed_fact_hints"),
                    metadata.get("entity_hints"),
                    metadata.get("accepted_facts"),
                    metadata.get("observables"),
                    metadata.get("observable_summary"),
                )
                if str(item or "").strip()
            )
            if any(token in typed_fact_text for token in ("fortigate", "outbound", "egress", "firewall", "dest_ip", "destination", "beacon", "callback")):
                gaps.insert(0, "Need FortiGate egress attribution covering source host, destination, service, action, and policy context.")
                gaps.append("Need to confirm whether outbound traffic is allowed business activity, blocked noise, or suspicious beacon-like behavior.")
            if any(token in typed_fact_text for token in ("4624", "4625", "winlogon", "windows logon", "logon type", "credential", "signin")):
                gaps.insert(0, "Need Windows logon attribution covering account, host, source network, logon type, and success-versus-failure sequence.")
                gaps.append("Need to distinguish routine logon activity from brute force, password spray, or compromised-session behavior.")
        elif lane == "email":
            gaps.extend(
                [
                    "Need delivery evidence linking sender, recipient, and any attachment or URL.",
                    "Need downstream host or user execution evidence before concluding impact.",
                ]
            )
        elif lane == "file":
            gaps.extend(
                [
                    "Need stable file, process, and host linkage.",
                    "Need sandbox or behavioral evidence to separate inert files from active execution chains.",
                ]
            )
        elif lane == "vulnerability":
            gaps.extend(
                [
                    "Need proof that the vulnerable asset is exposed or actively exploited.",
                    "Need asset attribution and impact evidence before escalating root cause confidence.",
                ]
            )
        else:
            gaps.extend(
                [
                    "Need deterministic evidence tied to the submitted observable.",
                    "Need at least one corroborating pivot before finalizing the strongest explanation.",
                ]
            )

        if metadata.get("chat_parent_session_id"):
            gaps.insert(0, "Need to determine whether the follow-up can be answered from accepted context or requires fresh evidence.")
        if observable_summary:
            gaps.insert(0, f"Need to validate the primary observable set: {', '.join(observable_summary[:3])}.")
        return self._dedupe(gaps)[:6]

    def _first_pivots(self, lane: str, primary_entities: List[str], observable_summary: List[str], evidence_gaps: List[str]) -> List[str]:
        pivots = {
            "ioc": [
                "Run deterministic IOC enrichment first.",
                "Pivot to related infrastructure or reputation sources.",
                "Correlate results before answering.",
            ],
            "email": [
                "Analyze the submitted email or message artifacts first.",
                "Extract links, sender identity, and delivery evidence.",
                "Correlate delivery evidence with follow-on host or user activity.",
            ],
            "file": [
                "Analyze the submitted file or process artifact first.",
                "Pivot to sandbox, hash, or YARA evidence.",
                "Correlate file or process evidence with host/network observations.",
            ],
            "log_identity": [
                "Run a focused log hunt using the primary observable.",
                "Pivot across user, host, session, and process context.",
                "Correlate explicit auth, process, and network observations before concluding.",
            ],
            "case_follow_up": [
                "Load the last accepted thread snapshot.",
                "Answer from existing evidence unless the analyst explicitly asks for a fresh pivot.",
                "If new evidence is needed, start from pinned entities and unresolved questions.",
            ],
        }.get(
            lane,
            [
                "Start from the strongest submitted observable.",
                "Collect at least one deterministic tool result before escalating reasoning.",
            ],
        )
        observable_text = " ".join(observable_summary).lower()
        if any("@" in item for item in observable_summary):
            pivots.insert(0, "Validate sender/recipient identity and delivery artifacts before broader pivots.")
        if any(item.startswith("cve-") for item in observable_summary):
            pivots.insert(0, "Validate whether the referenced CVE maps to an exposed asset or active exploitation path.")
        if any(self._IP_RE.fullmatch(item) for item in observable_summary):
            pivots.insert(0, "Pivot from the IP observable into reputation, ownership, and correlated session/host evidence.")
        if any(self._DOMAIN_RE.fullmatch(item) for item in observable_summary):
            pivots.insert(0, "Pivot from the domain observable into infrastructure, delivery, and network evidence.")
        if any(self._HASH_RE.fullmatch(item) for item in observable_summary):
            pivots.insert(0, "Pivot from the hash observable into file, sandbox, and host execution evidence.")
        if observable_summary:
            pivots.insert(0, f"Validate the strongest observable first: {', '.join(observable_summary[:3])}.")
        elif primary_entities and lane == "generic":
            pivots.insert(0, f"Bootstrap the investigation around {', '.join(primary_entities[:3])}.")
        if any(token in observable_text for token in ("fortigate", "outbound", "egress", "beacon", "callback")):
            pivots.append("Prioritize pivots that verify source host, destination, service, action, and repeat cadence for outbound traffic.")
        if any(token in observable_text for token in ("4624", "4625", "winlogon", "logon", "signin", "login")):
            pivots.append("Prioritize pivots that verify account, host, source network, logon type, and success-failure sequence before expanding scope.")
        if "session" in observable_text or "signin" in observable_text or "login" in observable_text:
            pivots.append("Prioritize pivots that clarify user, session, and host linkage before expanding scope.")
        if evidence_gaps:
            pivots.append(f"Prioritize pivots that reduce this evidence gap: {evidence_gaps[0]}")
        return self._dedupe(pivots)[:6]

    def _next_action_signals(
        self,
        lane: str,
        observable_summary: List[str],
        evidence_gaps: List[str],
        initial_hypotheses: List[str],
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        meta = metadata or {}
        typed_fact_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("typed_fact_hints"),
                meta.get("entity_hints"),
                meta.get("accepted_facts"),
                meta.get("observables"),
                meta.get("observable_summary"),
            )
            if str(item or "").strip()
        )
        top_gap = str(evidence_gaps[0]).strip() if evidence_gaps else ""
        strongest_observable = ", ".join(observable_summary[:3])
        strongest_hypothesis = str(initial_hypotheses[0]).strip() if initial_hypotheses else ""
        signals: List[Dict[str, Any]] = []

        def _append(tool: str, priority: int, reason: str, signal_type: str) -> None:
            if not str(tool).strip() or not str(reason).strip():
                return
            signals.append(
                {
                    "tool": str(tool).strip(),
                    "priority": int(priority),
                    "reason": str(reason).strip(),
                    "signal_type": str(signal_type).strip(),
                }
            )

        if lane == "log_identity":
            _append(
                "search_logs",
                100,
                f"Reduce the highest-priority identity evidence gap first: {top_gap or 'Need explicit user, host, session, and process linkage.'}",
                "evidence_gap",
            )
        elif lane == "email":
            _append(
                "analyze_email",
                100,
                f"Validate the submitted email artifacts before broader pivots: {strongest_observable or 'submitted email evidence'}.",
                "plan_pivot",
            )
        elif lane == "file":
            _append(
                "analyze_malware",
                100,
                f"Validate the submitted file or execution artifact before enrichment: {strongest_observable or 'submitted file evidence'}.",
                "plan_pivot",
            )
        else:
            _append(
                "investigate_ioc",
                90,
                f"Anchor the investigation on the strongest observable first: {strongest_observable or 'submitted observable'}.",
                "plan_pivot",
            )

        if top_gap and any(token in top_gap.lower() for token in ("host", "user", "session", "process", "telemetry", "log")):
            _append("search_logs", 95, f"Close the top telemetry gap directly: {top_gap}", "evidence_gap")
        if top_gap and any(token in top_gap.lower() for token in ("delivery", "sender", "recipient", "attachment")):
            _append("analyze_email", 95, f"Close the top email-delivery gap directly: {top_gap}", "evidence_gap")
        if top_gap and any(token in top_gap.lower() for token in ("file", "hash", "sandbox", "behavior", "execution")):
            _append("analyze_malware", 95, f"Close the top file-behavior gap directly: {top_gap}", "evidence_gap")
        if top_gap and any(token in top_gap.lower() for token in ("ioc", "observable", "reputation", "ownership", "corroborating")):
            _append("investigate_ioc", 92, f"Close the top IOC evidence gap directly: {top_gap}", "evidence_gap")

        if strongest_hypothesis and any(token in strongest_hypothesis.lower() for token in ("command-and-control", "command and control", "callback", "beacon")):
            _append("investigate_ioc", 88, "Test the leading C2-style hypothesis with deterministic IOC enrichment before deeper interpretation.", "hypothesis")
        if strongest_hypothesis and any(token in strongest_hypothesis.lower() for token in ("phishing", "business email compromise", "email", "delivery")):
            _append("analyze_email", 88, "Test the leading phishing or delivery hypothesis against message artifacts before answering.", "hypothesis")
        if strongest_hypothesis and any(token in strongest_hypothesis.lower() for token in ("malware", "payload", "execution", "binary")):
            _append("analyze_malware", 88, "Test the leading malware-execution hypothesis against file behavior before answering.", "hypothesis")

        if any(token in typed_fact_text for token in ("fortigate", "outbound", "egress", "firewall", "dest_ip", "destination", "beacon", "callback")):
            _append("search_logs", 93, "FortiGate outbound triage should confirm source, destination, service, action, and recurrence before conclusion.", "fortigate_outbound")
        if any(token in typed_fact_text for token in ("4624", "4625", "winlogon", "windows logon", "logon type", "failed logon", "successful logon")):
            _append("search_logs", 93, "Windows logon triage should confirm account, host, source network, logon type, and success-failure sequence before conclusion.", "windows_logon")
        if any(token in typed_fact_text for token in ("host:", "user:", "session:", "process:")):
            _append("search_logs", 84, "Named entities are present; prefer pivots that prove explicit host, user, session, or process linkage.", "entity_linkage")
        return self._normalize_next_action_signals(signals)[:6]

    def _triage_contracts(
        self,
        lane: str,
        observable_summary: List[str],
        evidence_gaps: List[str],
        first_pivots: List[str],
        stopping_conditions: List[str],
        escalation_conditions: List[str],
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        meta = metadata or {}
        typed_fact_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("typed_fact_hints"),
                meta.get("entity_hints"),
                meta.get("accepted_facts"),
                meta.get("observables"),
                meta.get("observable_summary"),
            )
            if str(item or "").strip()
        )
        contracts: List[Dict[str, Any]] = []

        def _append(
            contract_id: str,
            title: str,
            trigger_tokens: tuple[str, ...],
            required_fields: List[str],
            analyst_questions: List[str],
            escalation_hooks: Optional[List[str]] = None,
        ) -> None:
            if trigger_tokens and not any(token in typed_fact_text for token in trigger_tokens):
                return
            contracts.append(
                {
                    "contract_id": contract_id,
                    "contract_version": "triage-contract/v1",
                    "lane": lane,
                    "title": title,
                    "deterministic_verdict_owner": "CABTA deterministic core",
                    "observable_scope": list(observable_summary[:3]),
                    "required_fields": required_fields,
                    "analyst_questions": analyst_questions,
                    "evidence_gaps": [
                        item for item in evidence_gaps if any(field.replace("_", " ") in item.lower() or field in item.lower() for field in required_fields)
                    ][:3] or list(evidence_gaps[:2]),
                    "pivot_priorities": list(first_pivots[:3]),
                    "stopping_conditions": list(stopping_conditions[:3]),
                    "escalation_conditions": list(escalation_conditions[:3]),
                    "escalation_hooks": [str(item).strip() for item in (escalation_hooks or []) if str(item).strip()][:3],
                    "verdict_policy": "Gather attribution and chronology; do not change verdict ownership or finalize severity in the contract.",
                }
            )

        if lane == "log_identity":
            _append(
                "fortigate_outbound_monitoring",
                "FortiGate outbound monitoring triage",
                ("fortigate", "outbound", "egress", "firewall", "dest_ip", "destination", "beacon", "callback"),
                ["source_host", "dest_ip", "service", "action", "policy_context", "repeat_cadence"],
                [
                    "Which source host initiated the outbound connection?",
                    "What destination, service, and action were recorded by FortiGate?",
                    "Does the egress pattern repeat like beaconing or align to expected business activity?",
                ],
                [
                    "Escalate when FortiGate evidence shows beacon-like recurrence without trusted business justification.",
                    "Escalate when the source host or policy context cannot be attributed after the planned pivots.",
                ],
            )
            _append(
                "windows_logon_monitoring",
                "Windows logon monitoring triage",
                ("4624", "4625", "winlogon", "windows logon", "logon type", "failed logon", "successful logon"),
                ["account", "host", "source_ip", "logon_type", "event_sequence", "session_id"],
                [
                    "Which account and host are tied to the logon events?",
                    "Did the same source address produce both 4625 and 4624 activity?",
                    "Does the logon type and sequence suggest normal access, spray, or compromise?",
                ],
                [
                    "Escalate when the event sequence suggests brute force, password spray, or compromised-session behavior.",
                    "Escalate when account, host, or source attribution remains incomplete after log pivots.",
                ],
            )
        elif lane == "email":
            _append(
                "phishing_email_triage",
                "Phishing email triage",
                ("email", "phish", "sender", "recipient", "attachment", "url", "dmarc", "dkim", "spf", "bec", "spoof"),
                ["sender", "recipient", "delivery_path", "auth_results", "message_artifact", "embedded_observables"],
                [
                    "Which sender and recipient are tied to the suspicious message?",
                    "Do SPF, DKIM, and DMARC results support or contradict the claimed sender identity?",
                    "Which attachment, URL, or message element requires the next deterministic pivot?",
                ],
                [
                    "Escalate when impersonation or BEC indicators target payments, trust, or executive workflows.",
                    "Escalate when delivery evidence exists but downstream user or host impact remains unresolved.",
                ],
            )
        elif lane == "ioc":
            _append(
                "ioc_triage",
                "IOC triage",
                ("ioc", "indicator", "ip", "domain", "url", "hash", "reputation", "ownership", "callback", "beacon"),
                ["observable", "observable_type", "reputation", "ownership", "sightings", "linked_context"],
                [
                    "What exact observable is under review and what type is it?",
                    "What deterministic reputation or ownership evidence supports this IOC assessment?",
                    "Which host, user, file, or delivery context links this IOC to the investigated case?",
                ],
                [
                    "Escalate when malicious reputation appears without enough case linkage to explain impact.",
                    "Escalate when infrastructure is suspicious but host, user, or delivery attribution remains unresolved.",
                ],
            )
        return self._normalize_triage_contracts(contracts)[:3]

    def _normalize_next_action_signals(self, signals: Any) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        seen = set()
        for item in signals or []:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool") or "").strip()
            reason = str(item.get("reason") or "").strip()
            if not tool or not reason:
                continue
            try:
                priority = int(item.get("priority", 0))
            except (TypeError, ValueError):
                priority = 0
            signal_type = str(item.get("signal_type") or "generic").strip() or "generic"
            key = (tool.lower(), reason.lower())
            if key in seen:
                continue
            seen.add(key)
            normalized.append(
                {
                    "tool": tool,
                    "priority": priority,
                    "reason": reason,
                    "signal_type": signal_type,
                }
            )
        normalized.sort(key=lambda item: (-int(item.get("priority", 0)), str(item.get("tool") or ""), str(item.get("reason") or "")))
        return normalized

    def _normalize_triage_contracts(self, contracts: Any) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        seen = set()
        for item in contracts or []:
            if not isinstance(item, dict):
                continue
            contract_id = str(item.get("contract_id") or "").strip()
            title = str(item.get("title") or "").strip()
            if not contract_id or not title:
                continue
            key = contract_id.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(
                {
                    "contract_id": contract_id,
                    "contract_version": str(item.get("contract_version") or "triage-contract/v1").strip() or "triage-contract/v1",
                    "lane": str(item.get("lane") or "generic").strip() or "generic",
                    "title": title,
                    "deterministic_verdict_owner": str(item.get("deterministic_verdict_owner") or "CABTA deterministic core").strip() or "CABTA deterministic core",
                    "observable_scope": [str(value).strip() for value in item.get("observable_scope", []) if str(value).strip()],
                    "required_fields": [str(value).strip() for value in item.get("required_fields", []) if str(value).strip()],
                    "analyst_questions": [str(value).strip() for value in item.get("analyst_questions", []) if str(value).strip()],
                    "evidence_gaps": [str(value).strip() for value in item.get("evidence_gaps", []) if str(value).strip()],
                    "pivot_priorities": [str(value).strip() for value in item.get("pivot_priorities", []) if str(value).strip()],
                    "stopping_conditions": [str(value).strip() for value in item.get("stopping_conditions", []) if str(value).strip()],
                    "escalation_conditions": [str(value).strip() for value in item.get("escalation_conditions", []) if str(value).strip()],
                    "escalation_hooks": [str(value).strip() for value in item.get("escalation_hooks", []) if str(value).strip()],
                    "verdict_policy": str(item.get("verdict_policy") or "").strip(),
                }
            )
        return normalized

    def _stopping_conditions(
        self,
        lane: str,
        evidence_gaps: List[str],
        *,
        observable_summary: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        observables = [str(item).strip() for item in (observable_summary or []) if str(item).strip()]
        meta = metadata or {}
        typed_fact_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("typed_fact_hints"),
                meta.get("entity_hints"),
                meta.get("accepted_facts"),
                meta.get("observables"),
                meta.get("observable_summary"),
            )
            if str(item or "").strip()
        )
        conditions = [
            "Stop when the strongest hypothesis has materially better support than alternatives.",
            "Stop when deterministic evidence and causal explanation are aligned enough for analyst review.",
            "Stop early if the remaining evidence gaps require analyst approval or external action.",
        ]
        if evidence_gaps:
            conditions.insert(
                1,
                f"Stop when the highest-priority evidence gap is reduced enough for an explainable conclusion: {evidence_gaps[0]}",
            )
        if observables:
            conditions.append(
                f"Stop when the primary observable set has been validated or explained well enough for analyst review: {', '.join(observables[:3])}."
            )
        if lane == "case_follow_up":
            conditions.insert(
                0,
                "Stop immediately if the analyst only asked for explanation or recap and the snapshot already answers it.",
            )
        if any(token in typed_fact_text for token in ("recap", "explain", "summary", "follow-up", "follow up")):
            conditions.insert(
                0,
                "Stop as soon as the requested explanation can be answered from accepted context without requiring a fresh pivot.",
            )
        if any(token in typed_fact_text for token in ("delivery", "attachment", "sender", "recipient")) and lane == "email":
            conditions.append("Stop when sender, recipient, and delivery evidence are linked clearly enough to explain the email path.")
        if any(token in typed_fact_text for token in ("session", "signin", "login", "credential", "mfa")) and lane == "log_identity":
            conditions.append("Stop when user, session, and host attribution are coherent enough to distinguish compromise from anomaly.")
        if any(token in typed_fact_text for token in ("sandbox", "execution", "payload", "loader")) and lane == "file":
            conditions.append("Stop when execution evidence is sufficient to separate inert artifacts from active malicious behavior.")
        if any(token in typed_fact_text for token in ("cve-", "exploit", "exposed", "patch")) and lane == "vulnerability":
            conditions.append("Stop when exposure and exploitability are clear enough to justify the severity and escalation posture.")
        return self._dedupe(conditions)[:6]

    def _escalation_conditions(
        self,
        lane: str,
        evidence_gaps: List[str],
        *,
        observable_summary: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        observables = [str(item).strip() for item in (observable_summary or []) if str(item).strip()]
        meta = metadata or {}
        typed_fact_text = " ".join(
            str(item).lower()
            for item in (
                meta.get("typed_fact_hints"),
                meta.get("entity_hints"),
                meta.get("accepted_facts"),
                meta.get("observables"),
                meta.get("observable_summary"),
            )
            if str(item or "").strip()
        )
        conditions = [
            "Escalate when high-risk evidence appears without enough contradictory coverage.",
            "Escalate when approval-gated actions or broad hunts are required.",
            "Escalate when identity attribution, host attribution, or root cause remains weak after two pivots.",
        ]
        if evidence_gaps:
            conditions.append(
                f"Escalate when the top evidence gap remains unresolved after the planned pivots: {evidence_gaps[0]}"
            )
        if lane == "email":
            conditions.append("Escalate when delivery evidence exists but downstream execution or user attribution is still missing.")
        if lane == "log_identity":
            conditions.append("Escalate when auth anomalies exist without enough session or host timeline evidence.")
        if any(token in typed_fact_text for token in ("host:", "user:", "session:", "process:")):
            conditions.insert(
                1,
                "Escalate when named entity linkage remains unresolved across host, user, session, or process evidence.",
            )
        if any(token in typed_fact_text for token in ("bec", "business email compromise", "spoof", "invoice", "impersonat")):
            conditions.insert(
                2,
                "Escalate when impersonation or BEC indicators suggest payment, trust, or executive-abuse risk.",
            )
        if any(token in typed_fact_text for token in ("c2", "command and control", "beacon", "callback")):
            conditions.insert(
                3,
                "Escalate when recurring callback or command-and-control evidence appears without strong host attribution.",
            )
        if any(token in typed_fact_text for token in ("cve-", "exploit", "exposed", "vulnerability")):
            conditions.append("Escalate when a known exposure may enable active exploitation or broader asset impact.")
        if any(item.startswith("CVE-") for item in observables):
            conditions.append("Escalate when the referenced CVE maps to exposed or business-critical assets.")
        return self._dedupe(conditions)[:7]

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            clean = str(value or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(clean)
        return ordered
