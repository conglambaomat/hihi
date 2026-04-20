"""Shared generic observation-type inference helpers."""

from __future__ import annotations

from typing import Any


def infer_generic_observation_type(payload: Any) -> str:
    """Infer the best typed observation kind from a generic payload.

    This keeps `correlation_observation` as a compatibility fallback only,
    while preferring stronger typed families whenever the payload exposes
    enough structured hints.
    """
    if not isinstance(payload, dict):
        return "correlation_observation"
    if payload.get("cve"):
        return "vulnerability_exposure"
    if payload.get("verdict") or payload.get("score") or payload.get("threat_score"):
        return "ioc_enrichment"
    if payload.get("sender") or payload.get("recipient") or payload.get("attachment"):
        return "email_delivery"
    if payload.get("suspicious_files") or payload.get("suspicious_executables"):
        return "file_execution"
    if payload.get("process_name") or payload.get("image") or payload.get("process"):
        return "process_event"
    if payload.get("url") or payload.get("domain") or payload.get("dest_ip") or payload.get("suspicious_indicators"):
        return "network_event"
    if payload.get("session_id") or payload.get("logon_id") or payload.get("source_ip"):
        return "auth_event"
    if payload.get("host") or payload.get("hostname") or payload.get("device"):
        return "host_timeline_event"
    if "results_count" in payload and int(payload.get("results_count") or 0) > 0:
        return "host_timeline_event"
    return "correlation_observation"