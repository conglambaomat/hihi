import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.agent.investigation_workdir import (
    CorruptWorkdirJsonError,
    InvestigationWorkdirService,
    UnsafeWorkdirPathError,
)


def test_create_or_get_creates_expected_layout_and_reuses_content(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)

    root = service.create_or_get("case-123", case_id="case-a", session_id="sess-a", thread_id="thread-a")
    service.write_text("case-123", "context.md", "analyst notes")
    root_again = service.create_or_get("case-123", case_id="case-a", session_id="sess-a", thread_id="thread-a")

    assert root_again == root
    assert (root / "manifest.json").exists()
    assert (root / "plan.md").exists()
    assert (root / "plan.json").exists()
    assert (root / "state.json").exists()
    assert (root / "context.md").read_text(encoding="utf-8") == "analyst notes"
    assert (root / "evidence" / "query_results").is_dir()
    assert (root / "evidence" / "enrichments").is_dir()
    assert (root / "evidence" / "observations").is_dir()
    assert (root / "log.jsonl").exists()

    manifest = service.read_json("case-123", "manifest.json")
    assert manifest["product"] == "AISA"
    assert manifest["runtime"]["verdict_authority"] == "deterministic_aisa_scoring"


def test_blocks_path_traversal_absolute_paths_and_symlink_escape(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    root = service.create_or_get("safe")

    with pytest.raises(UnsafeWorkdirPathError):
        service.write_text("safe", "../escape.txt", "bad")

    with pytest.raises(UnsafeWorkdirPathError):
        service.write_text("safe", str(tmp_path / "absolute.txt"), "bad")

    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this platform")

    with pytest.raises(UnsafeWorkdirPathError):
        service.write_text("safe", "link/escape.txt", "bad")


def test_json_read_write_and_corrupt_json_handling(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    service.create_or_get("json")

    service.write_json("json", "evidence/observations/result.json", {"verdict": "CLEAN"})
    assert service.read_json("json", "evidence/observations/result.json") == {"verdict": "CLEAN"}

    (service.get_path("json") / "bad.json").write_text("{not json", encoding="utf-8")
    assert service.read_json("json", "bad.json", default={"fallback": True}) == {"fallback": True}
    with pytest.raises(CorruptWorkdirJsonError):
        service.read_json("json", "bad.json")


def test_events_artifacts_summary_and_archive_stay_inside_workdir(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    root = service.create_or_get("audit", case_id="case-1")

    service.write_json("audit", "evidence/enrichments/enrichment.json", {"ok": True})
    artifact = service.register_artifact(
        "audit",
        relative_path="evidence/enrichments/enrichment.json",
        artifact_type="enrichment",
        source="unit-test",
        authoritative=True,
    )
    service.append_event("audit", "custom_event", {"api_key": "secret-value", "safe": "value"})

    assert artifact["authoritative"] is True
    assert artifact["verdict_boundary"] == "deterministic_decision_ref"

    events = [json.loads(line) for line in (root / "log.jsonl").read_text(encoding="utf-8").splitlines() if line]
    assert events[-1]["payload"]["api_key"] == "[REDACTED]"

    summary = service.summarize("audit")
    assert summary["artifact_count"] == 1
    assert summary["disk_usage_bytes"] > 0
    assert summary["last_event_type"] == "custom_event"
    assert summary["verdict_boundary"] == "deterministic_scoring_remains_authoritative"

    archive = service.archive("audit")
    assert archive is not None
    archive.relative_to(root)
    assert archive.suffix == ".zip"


def test_persist_observation_and_review_generation(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    root = service.create_or_get("obs")

    service.persist_observation(
        "obs",
        step_number=2,
        tool_name="investigate_ioc",
        params={"ioc": "8.8.8.8", "token": "secret"},
        result={"verdict": "CLEAN"},
    )
    service.generate_review("obs", summary="Investigation complete", status="completed")

    observation = service.read_json("obs", "evidence/observations/step-0002-investigate_ioc.json")
    assert observation["params"]["token"] == "[REDACTED]"
    assert observation["verdict_boundary"] == "deterministic_evidence_ref"
    assert "deterministic AISA scoring remains authoritative" in (root / "review.md").read_text(encoding="utf-8")


def test_resume_snapshot_and_session_payload_are_non_authoritative(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    service.create_or_get("resume", case_id="case-r", session_id="sess-r", thread_id="thread-r")
    service.sync_state("resume", phase="completed", last_step=3, state={"open_questions": ["q1"]})
    service.write_json("resume", "hypotheses.json", {"status": "supported"})

    snapshot = service.build_resume_snapshot("resume")
    payload = service.build_session_resume_payload("resume")

    assert snapshot["resume_authority"] == "workdir_mirror_non_authoritative"
    assert snapshot["verdict_boundary"] == "deterministic_scoring_remains_authoritative"
    assert snapshot["reasoning_state"] == {"status": "supported"}
    assert payload["session_id"] == "sess-r"
    assert payload["thread_id"] == "thread-r"
    assert payload["last_step"] == 3
    assert payload["snapshot"]["investigation_id"] == "resume"
    assert payload["metadata"]["source_workdir_investigation_id"] == "resume"
    assert payload["metadata"]["deterministic_verdict_boundary"] == "workdir_decision_is_historical_context_only_until_fresh_tool_validation"
    assert payload["state_payload"]["reasoning_state"] == {"status": "supported"}


def test_manifest_validation_hash_mismatch_and_review_state(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    root = service.create_or_get("integrity", case_id="case-i", session_id="sess-i")
    service.write_text("integrity", "artifacts/reports/report.md", "original", artifact_kind="report")

    valid = service.validate_manifest("integrity")
    assert valid["valid"] is True
    assert valid["status"] == "valid"
    assert valid["artifacts"][0]["sha256"]

    (root / "artifacts" / "reports" / "report.md").write_text("tampered", encoding="utf-8")
    invalid = service.validate_manifest("integrity")
    assert invalid["valid"] is False
    assert any(err["code"] == "artifact_hash_mismatch" for err in invalid["errors"])

    review = service.update_review_state(
        "integrity",
        decision="needs_rework",
        reviewer="analyst-1",
        notes="Re-run IOC enrichment before closure.",
    )
    assert review["decision"] == "needs_rework"
    assert review["reviewer"] == "analyst-1"
    assert review["verdict_boundary"] == "does_not_modify_canonical_evidence_or_deterministic_verdict"
    assert service.get_review_state("integrity")["history"][-1]["decision"] == "needs_rework"


def test_redacts_sensitive_strings_headers_and_urls(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    root = service.create_or_get("redact")
    service.append_event(
        "redact",
        "sensitive",
        {
            "safe": "keep evidence",
            "headers": "Authorization: Bearer abc123, X-Other: ok",
            "url": "https://example.test/path?api_key=secret-token&ioc=8.8.8.8",
            "note": "password=supersecret token: anothersecret",
        },
    )

    event = json.loads([line for line in (root / "log.jsonl").read_text(encoding="utf-8").splitlines() if line][-1])
    payload = event["payload"]
    assert payload["safe"] == "keep evidence"
    assert "abc123" not in payload["headers"]
    assert "api_key=[REDACTED]" in payload["url"]
    assert "secret-token" not in payload["url"]
    assert "supersecret" not in payload["note"]
    assert "anothersecret" not in payload["note"]


def test_archive_excludes_prior_archives_and_temp_files(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    root = service.create_or_get("archive-clean")
    service.write_text("archive-clean", "artifacts/reports/report.txt", "report")
    archive_dir = root / "_archive"
    archive_dir.mkdir(exist_ok=True)
    (archive_dir / "old.zip").write_text("nested", encoding="utf-8")
    (root / ".state.json.abc.tmp").write_text("tmp", encoding="utf-8")

    archive = service.archive("archive-clean")

    assert archive is not None
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
    assert "artifacts/reports/report.txt" in names
    assert "artifacts/reports/integrity-summary.json" in names
    assert not any(name.startswith("_archive/") for name in names)
    assert ".state.json.abc.tmp" not in names


def test_retention_lists_stale_and_dry_run_does_not_delete(tmp_path):
    service = InvestigationWorkdirService(base_dir=tmp_path)
    old_root = service.create_or_get("old")
    service.create_or_get("new")
    old_manifest = service.read_json("old", "manifest.json")
    old_manifest["updated_at"] = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    service.write_json("old", "manifest.json", old_manifest)

    stale = service.list_stale_workdirs(retention_days=30, keep_latest=10)
    result = service.apply_retention(retention_days=30, keep_latest=10, action="archive", dry_run=True)

    assert [item["investigation_id"] for item in stale] == ["old"]
    assert result["stale_count"] == 1
    assert old_root.exists()
