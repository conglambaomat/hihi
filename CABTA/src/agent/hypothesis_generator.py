"""Deterministic dynamic hypothesis generation for AISA investigations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HypothesisCandidate:
    """A non-authoritative candidate hypothesis generated from deterministic evidence."""

    candidate_id: str
    statement: str
    origin: str = "dynamic_evidence"
    hypothesis_type: str = "generic_incident"
    attack_path: List[str] = field(default_factory=list)
    topics: List[str] = field(default_factory=list)
    trigger_observation_ids: List[str] = field(default_factory=list)
    trigger_entity_ids: List[str] = field(default_factory=list)
    required_evidence: List[Dict[str, Any]] = field(default_factory=list)
    generation_reason: str = ""
    reason_codes: List[str] = field(default_factory=list)
    confidence_prior: float = 0.34
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    verification: Dict[str, Any] = field(default_factory=dict)
    dedupe_key: str = ""
    generator_version: str = "hypothesis-generator/p0-v1"
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = "hypothesis/v1"
        payload["hypothesis_id"] = payload.get("candidate_id")
        verification = payload.get("verification") or {}
        status = str(verification.get("status") or "candidate")
        payload["status"] = "plausible" if status in {"promotable", "staged"} else status
        payload["support_refs"] = list(payload.get("trigger_observation_ids") or [])
        payload["contradict_refs"] = list((verification.get("contradict_refs") if isinstance(verification, dict) else []) or [])
        payload["missing_refs"] = list((verification.get("missing_evidence") if isinstance(verification, dict) else []) or [])
        payload["attack_stage_chain"] = list(payload.get("attack_path") or [])
        payload["claim_limits"] = ["Hypothesis is not a final verdict.", "Do not claim compromise without deterministic supporting evidence."]
        payload["confidence_prior"] = round(float(payload.get("confidence_prior", 0.0)), 3)
        payload["score_breakdown"] = {
            str(key): round(float(value), 3)
            for key, value in (payload.get("score_breakdown") or {}).items()
            if isinstance(value, (int, float))
        }
        return payload


class HypothesisGenerator:
    """Generate dynamic hypotheses from typed observations without calling an LLM."""

    VERSION = "hypothesis-generator/p0-v1"
    MAX_OBSERVATIONS = 80
    MAX_CANDIDATES = 12

    def generate(
        self,
        *,
        goal: str,
        session_id: str,
        reasoning_state: Optional[Dict[str, Any]],
        investigation_plan: Optional[Dict[str, Any]],
        active_observations: Optional[List[Dict[str, Any]]],
        entity_state: Optional[Dict[str, Any]],
        evidence_state: Optional[Dict[str, Any]],
        deterministic_decision: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        observations = [item for item in (active_observations or [])[-self.MAX_OBSERVATIONS:] if isinstance(item, dict)]
        candidates: List[HypothesisCandidate] = []
        candidates.extend(self._network_c2_candidates(observations, entity_state, evidence_state))
        candidates.extend(self._identity_compromise_candidates(observations, entity_state, evidence_state))
        candidates.extend(self._mfa_fatigue_candidates(observations, entity_state, evidence_state))
        candidates.extend(self._oauth_consent_candidates(observations, entity_state, evidence_state))
        candidates.extend(self._phishing_session_candidates(observations, entity_state, evidence_state))
        candidates.extend(self._malware_callback_candidates(observations, entity_state, evidence_state))

        deduped = self.dedupe_candidates(candidates)
        for candidate in deduped:
            candidate.verification = self.verify_candidate(candidate, observations, entity_state, evidence_state)

        events = [self._event("candidate_generated", candidate) for candidate in deduped]
        return {
            "schema_version": "hypothesis-generation/v1",
            "generator_version": self.VERSION,
            "candidates": [candidate.to_dict() for candidate in deduped[: self.MAX_CANDIDATES]],
            "events": events[: self.MAX_CANDIDATES],
            "summary": {
                "candidate_count": len(deduped[: self.MAX_CANDIDATES]),
                "promotable_count": sum(1 for item in deduped[: self.MAX_CANDIDATES] if item.verification.get("status") == "promotable"),
                "deterministic_verdict_preserved": str((deterministic_decision or {}).get("verdict") or "UNKNOWN").upper(),
            },
        }

    def verify_candidate(
        self,
        candidate: HypothesisCandidate,
        observations: List[Dict[str, Any]],
        entity_state: Optional[Dict[str, Any]],
        evidence_state: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        observation_ids = {str(item.get("observation_id") or "").lower() for item in observations}
        trigger_ids = {str(item).lower() for item in candidate.trigger_observation_ids}
        passed: List[str] = []
        failed: List[str] = []
        missing: List[str] = []
        if trigger_ids.intersection(observation_ids):
            passed.append("trigger_observation")
        else:
            failed.append("trigger_observation")
            missing.append("A fresh deterministic trigger observation is required before promotion.")

        required_types = set()
        required_entities = set()
        for contract in candidate.required_evidence:
            required_types.update(str(item) for item in contract.get("required_observation_types", []) if str(item).strip())
            required_entities.update(str(item) for item in contract.get("required_entities", []) if str(item).strip())
        present_types = {self._obs_type(item) for item in observations if str(item.get("observation_id") or "").lower() in trigger_ids}
        missing_types = sorted(required_types - present_types)
        if not missing_types:
            passed.append("required_observation_types")
        else:
            failed.append("required_observation_types")
            missing.append("Need observation types: " + ", ".join(missing_types))

        present_entities = self._entity_types(observations, entity_state)
        missing_entities = sorted(required_entities - present_entities)
        if not missing_entities:
            passed.append("required_entities")
        else:
            failed.append("required_entities")
            missing.append("Need entity types: " + ", ".join(missing_entities))

        avg_quality = self._avg_quality([item for item in observations if str(item.get("observation_id") or "").lower() in trigger_ids])
        minimum_quality = min([float(contract.get("minimum_quality", 0.55) or 0.55) for contract in candidate.required_evidence] or [0.55])
        if avg_quality >= minimum_quality:
            passed.append("minimum_quality")
        else:
            failed.append("minimum_quality")
            missing.append(f"Need average trigger evidence quality >= {minimum_quality:.2f}.")

        if self._has_blocker(candidate, observations):
            failed.append("contradiction_blocker")
            missing.append("Resolve allowlist, VPN, approved app, simulation, clean verdict, or business-justification contradiction.")
        else:
            passed.append("contradiction_blocker")

        status = "promotable" if not failed else "staged"
        return {"status": status, "passed_checks": passed, "failed_checks": failed, "missing_evidence": missing}

    def dedupe_candidates(self, candidates: List[HypothesisCandidate]) -> List[HypothesisCandidate]:
        by_key: Dict[str, HypothesisCandidate] = {}
        for candidate in candidates:
            candidate.dedupe_key = candidate.dedupe_key or self.candidate_dedupe_key(candidate)
            existing = by_key.get(candidate.dedupe_key)
            if existing is None or candidate.confidence_prior > existing.confidence_prior:
                if existing is not None:
                    candidate.reason_codes = self._dedupe([*existing.reason_codes, *candidate.reason_codes])
                    candidate.trigger_observation_ids = self._dedupe([*existing.trigger_observation_ids, *candidate.trigger_observation_ids])
                    candidate.trigger_entity_ids = self._dedupe([*existing.trigger_entity_ids, *candidate.trigger_entity_ids])
                by_key[candidate.dedupe_key] = candidate
        return sorted(by_key.values(), key=lambda item: (item.confidence_prior, len(item.trigger_observation_ids)), reverse=True)

    def candidate_dedupe_key(self, candidate: HypothesisCandidate) -> str:
        basis = "|".join([
            candidate.hypothesis_type,
            ",".join(sorted(candidate.attack_path)),
            ",".join(sorted(candidate.trigger_entity_ids))[:180],
            ",".join(sorted(candidate.reason_codes)),
        ])
        return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _network_c2_candidates(self, observations: List[Dict[str, Any]], entity_state: Any, evidence_state: Any) -> List[HypothesisCandidate]:
        out: List[HypothesisCandidate] = []
        for obs in observations:
            if self._obs_type(obs) != "network_event":
                continue
            facts = self._facts(obs)
            text = self._text(obs)
            dest = facts.get("dest_ip") or facts.get("dst_ip") or facts.get("domain") or facts.get("dest")
            source = facts.get("host") or facts.get("src_ip") or facts.get("source_ip")
            fortigate = any(token in text for token in ("fortinet", "fortigate", "policyid", "policy_id"))
            suspicious = any(token in text for token in ("c2", "beacon", "callback", "malicious", "suspicious", "tor", "newly_registered"))
            if not (dest and source and (fortigate or suspicious)):
                continue
            out.append(self._candidate(
                "Potential C2 or FortiGate beaconing activity from {source} to {dest}.",
                "c2_beaconing",
                ["command_and_control"],
                ["network_event", "c2", "fortigate", "beacon"],
                obs,
                ["host", "ip"],
                "c2_fortigate_beaconing_p0",
                "FortiGate or suspicious network telemetry showed outbound callback/beacon indicators.",
                ["P0_C2_FORTIGATE_BEACON", "ENTITY_HOST_DESTINATION_LINK"],
                source=source,
                dest=dest,
            ))
        return out

    def _identity_compromise_candidates(self, observations: List[Dict[str, Any]], entity_state: Any, evidence_state: Any) -> List[HypothesisCandidate]:
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for obs in observations:
            if self._obs_type(obs) != "auth_event":
                continue
            user = str(self._facts(obs).get("user") or self._entity_value(obs, "user") or "").lower()
            if user:
                by_user.setdefault(user, []).append(obs)
        out: List[HypothesisCandidate] = []
        for user, items in by_user.items():
            sources = {str(self._facts(item).get("source_ip") or self._facts(item).get("src_ip") or "") for item in items}
            text = " ".join(self._text(item) for item in items)
            if len(items) >= 2 and (len([src for src in sources if src]) >= 2 or any(t in text for t in ("impossible travel", "token reuse", "session reuse", "suspicious session"))):
                out.append(self._candidate(
                    "Potential impossible travel, token reuse, or session compromise for user {source}.",
                    "identity_compromise",
                    ["initial_access", "credential_access"],
                    ["auth_event", "identity", "session", "credential"],
                    items[-1],
                    ["user", "ip"],
                    "identity_impossible_travel_token_reuse_p0",
                    "Authentication telemetry showed repeated or divergent source/session patterns for the same user.",
                    ["P0_IMPOSSIBLE_TRAVEL_TOKEN_REUSE"],
                    source=user,
                    extra_trigger_ids=[str(item.get("observation_id")) for item in items],
                ))
        return out

    def _mfa_fatigue_candidates(self, observations: List[Dict[str, Any]], entity_state: Any, evidence_state: Any) -> List[HypothesisCandidate]:
        out: List[HypothesisCandidate] = []
        for obs in observations:
            text = self._text(obs)
            facts = self._facts(obs)
            if self._obs_type(obs) == "auth_event" and any(token in text for token in ("mfa fatigue", "mfa push", "repeated mfa", "mfa_denied", "mfa denied", "push denied", "multiple prompts")):
                user = facts.get("user") or self._entity_value(obs, "user") or "the affected user"
                out.append(self._candidate(
                    "Potential MFA fatigue attack against {source}.",
                    "mfa_fatigue",
                    ["credential_access", "initial_access"],
                    ["auth_event", "mfa", "identity"],
                    obs,
                    ["user"],
                    "mfa_fatigue_p0",
                    "Authentication telemetry described repeated MFA prompts, failures, or push fatigue indicators.",
                    ["P0_MFA_FATIGUE"],
                    source=user,
                    minimum_quality=0.5,
                ))
        return out

    def _oauth_consent_candidates(self, observations: List[Dict[str, Any]], entity_state: Any, evidence_state: Any) -> List[HypothesisCandidate]:
        out: List[HypothesisCandidate] = []
        for obs in observations:
            text = self._text(obs)
            facts = self._facts(obs)
            obs_type = self._obs_type(obs)
            if obs_type in {"auth_event", "oauth_consent_event", "correlation_observation"} and any(token in text for token in ("oauth", "consent", "grant", "risky scope", "mail.read", "offline_access")):
                user = facts.get("user") or self._entity_value(obs, "user") or "user"
                app = facts.get("app") or facts.get("client_id") or self._entity_value(obs, "app") or "application"
                out.append(self._candidate(
                    "Potential OAuth consent abuse involving {source} and {dest}.",
                    "oauth_consent_abuse",
                    ["initial_access", "persistence", "collection"],
                    ["oauth", "consent", "identity", "mailbox"],
                    obs,
                    ["user", "app"],
                    "oauth_consent_abuse_p0",
                    "Consent or grant telemetry indicated risky OAuth scopes or mailbox/API access.",
                    ["P0_OAUTH_CONSENT_ABUSE"],
                    source=user,
                    dest=app,
                    required_types=[obs_type],
                    minimum_quality=0.5,
                ))
        return out

    def _phishing_session_candidates(self, observations: List[Dict[str, Any]], entity_state: Any, evidence_state: Any) -> List[HypothesisCandidate]:
        emails = [item for item in observations if self._obs_type(item) == "email_delivery" or "phish" in self._text(item)]
        auths = [item for item in observations if self._obs_type(item) == "auth_event"]
        if not emails or not auths:
            return []
        email = emails[-1]
        auth = auths[-1]
        recipient = self._facts(email).get("recipient") or self._entity_value(email, "recipient") or self._facts(auth).get("user") or "recipient"
        return [self._candidate(
            "Potential phishing-led credential or session compromise for {source}.",
            "phishing_compromise",
            ["initial_access", "credential_access"],
            ["phishing", "email_delivery", "auth_event", "session"],
            auth,
            ["sender", "recipient", "user"],
            "phishing_credential_session_compromise_p0",
            "Email delivery evidence was followed by authentication or session telemetry for the recipient/user.",
            ["P0_PHISHING_CREDENTIAL_SESSION_COMPROMISE", "P1_CHAIN_EMAIL_TO_AUTH"],
            source=recipient,
            required_types=["email_delivery", "auth_event"],
            extra_trigger_ids=[str(email.get("observation_id")), str(auth.get("observation_id"))],
        )]

    def _malware_callback_candidates(self, observations: List[Dict[str, Any]], entity_state: Any, evidence_state: Any) -> List[HypothesisCandidate]:
        execs = [item for item in observations if self._obs_type(item) in {"process_event", "file_execution", "sandbox_behavior"}]
        nets = [item for item in observations if self._obs_type(item) == "network_event"]
        if not execs:
            return []
        for item in execs:
            if self._facts(item).get("dest_ip") or self._facts(item).get("domain") or "callback" in self._text(item) or "c2" in self._text(item):
                nets.append(item)
        if not nets:
            return []
        proc = self._facts(execs[-1]).get("process_name") or self._facts(execs[-1]).get("file") or self._entity_value(execs[-1], "process") or "process"
        return [self._candidate(
            "Potential malware/process execution leading to network callback from {source}.",
            "malware_callback",
            ["execution", "command_and_control"],
            ["malware", "process_event", "file_execution", "network_event", "callback"],
            nets[-1],
            ["process", "host"],
            "malware_execution_network_callback_p0",
            "Process, file, or sandbox execution evidence was paired with suspicious network callback telemetry.",
            ["P0_MALWARE_EXECUTION_NETWORK_CALLBACK", "P1_CHAIN_PROCESS_TO_NETWORK"],
            source=proc,
            required_types=[self._obs_type(execs[-1]), self._obs_type(nets[-1])],
            extra_trigger_ids=[str(execs[-1].get("observation_id")), str(nets[-1].get("observation_id"))],
        )]

    def _candidate(self, template: str, hypothesis_type: str, attack_path: List[str], topics: List[str], observation: Dict[str, Any], required_entities: List[str], contract_id: str, reason: str, reason_codes: List[str], *, source: Any = "", dest: Any = "", required_types: Optional[List[str]] = None, minimum_quality: float = 0.55, extra_trigger_ids: Optional[List[str]] = None) -> HypothesisCandidate:
        obs_id = str(observation.get("observation_id") or "").strip()
        trigger_ids = self._dedupe([obs_id, *(extra_trigger_ids or [])])
        entities = self._entity_ids([observation])
        quality = float(observation.get("quality") or (observation.get("typed_fact") or {}).get("quality") or 0.0)
        statement = template.format(source=source or "the source entity", dest=dest or "the destination entity")
        candidate_id = "cand-" + hashlib.sha1((hypothesis_type + "|" + "|".join(trigger_ids) + statement).encode("utf-8", errors="ignore")).hexdigest()[:10]
        candidate = HypothesisCandidate(
            candidate_id=candidate_id,
            statement=statement,
            hypothesis_type=hypothesis_type,
            attack_path=attack_path,
            topics=self._dedupe(topics),
            trigger_observation_ids=trigger_ids,
            trigger_entity_ids=entities,
            required_evidence=[{
                "contract_id": contract_id,
                "required_observation_types": self._dedupe(required_types or [self._obs_type(observation)]),
                "required_entities": required_entities,
                "minimum_quality": minimum_quality,
                "contradiction_policy": "block_support_on_allowlist_business_justification_clean_or_approved_context",
            }],
            generation_reason=reason,
            reason_codes=self._dedupe(reason_codes),
            confidence_prior=max(0.24, min(0.48, 0.28 + quality * 0.2)),
            score_breakdown={"evidence_quality": quality, "llm_suggestion_weight": 0.0},
        )
        candidate.dedupe_key = self.candidate_dedupe_key(candidate)
        return candidate

    def _event(self, event_type: str, candidate: HypothesisCandidate) -> Dict[str, Any]:
        return {
            "event_id": "hyp-event-" + hashlib.sha1((event_type + candidate.candidate_id).encode()).hexdigest()[:10],
            "event_type": event_type,
            "candidate_id": candidate.candidate_id,
            "reason_codes": list(candidate.reason_codes),
            "trigger_observation_ids": list(candidate.trigger_observation_ids),
            "summary": candidate.generation_reason,
            "created_at": _now_iso(),
        }

    @staticmethod
    def _obs_type(obs: Dict[str, Any]) -> str:
        typed = obs.get("typed_fact") if isinstance(obs.get("typed_fact"), dict) else {}
        return str(typed.get("type") or obs.get("observation_type") or "correlation_observation").strip().lower()

    @staticmethod
    def _facts(obs: Dict[str, Any]) -> Dict[str, Any]:
        return obs.get("facts", {}) if isinstance(obs.get("facts"), dict) else {}

    @staticmethod
    def _text(value: Any) -> str:
        try:
            return json.dumps(value, default=str, sort_keys=True).lower()
        except Exception:
            return str(value).lower()

    def _entity_ids(self, observations: List[Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        for obs in observations:
            for entity in obs.get("entities", []) if isinstance(obs.get("entities"), list) else []:
                if isinstance(entity, dict) and entity.get("type") and entity.get("value"):
                    ids.append(f"{entity.get('type')}:{entity.get('value')}".lower())
        return self._dedupe(ids)

    def _entity_types(self, observations: List[Dict[str, Any]], entity_state: Optional[Dict[str, Any]]) -> set[str]:
        types = set()
        for obs in observations:
            for entity in obs.get("entities", []) if isinstance(obs.get("entities"), list) else []:
                if isinstance(entity, dict) and entity.get("type"):
                    types.add(str(entity.get("type")).lower())
        if isinstance(entity_state, dict) and isinstance(entity_state.get("entities"), dict):
            for entity in entity_state.get("entities", {}).values():
                if isinstance(entity, dict) and entity.get("type"):
                    types.add(str(entity.get("type")).lower())
        return types

    @staticmethod
    def _entity_value(obs: Dict[str, Any], entity_type: str) -> str:
        for entity in obs.get("entities", []) if isinstance(obs.get("entities"), list) else []:
            if isinstance(entity, dict) and str(entity.get("type") or "").lower() == entity_type:
                return str(entity.get("value") or "")
        return ""

    @staticmethod
    def _avg_quality(observations: List[Dict[str, Any]]) -> float:
        values = [float(item.get("quality") or (item.get("typed_fact") or {}).get("quality") or 0.0) for item in observations if isinstance(item, dict)]
        return sum(values) / len(values) if values else 0.0

    def _has_blocker(self, candidate: HypothesisCandidate, observations: List[Dict[str, Any]]) -> bool:
        trigger_ids = {str(item).lower() for item in candidate.trigger_observation_ids}
        text = " ".join(self._text(item) for item in observations if str(item.get("observation_id") or "").lower() in trigger_ids)
        return any(token in text for token in ("allowlist", "allowed list", "known good", "business justification", "approved app", "known vpn", "simulation", "clean", "benign"))

    @staticmethod
    def _dedupe(values: List[Any]) -> List[str]:
        seen = set()
        out: List[str] = []
        for value in values:
            clean = str(value or "").strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(clean)
        return out
