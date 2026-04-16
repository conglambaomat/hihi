from pathlib import Path

from src.utils.config_history import (
    history_repo_dir,
    list_history,
    restore_snapshot,
    snapshot_config,
)


def test_local_config_history_snapshots_and_restores(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("api_keys:\n  virustotal: first-key\n", encoding="utf-8")

    first = snapshot_config(config_file, reason="initial snapshot")
    assert first["status"] == "saved"
    repo_dir = history_repo_dir(config_file)
    assert (repo_dir / ".git").exists()

    config_file.write_text("api_keys:\n  virustotal: second-key\n", encoding="utf-8")
    second = snapshot_config(config_file, reason="second snapshot")
    assert second["status"] == "saved"
    assert second["revision"] != first["revision"]

    history = list_history(config_file, limit=10)
    assert len(history) >= 2
    assert history[0]["revision"] == second["revision"]

    restored = restore_snapshot(config_file, first["revision"], reason="rollback test")
    assert restored["status"] == "restored"
    assert "first-key" in config_file.read_text(encoding="utf-8")


def test_snapshot_config_is_noop_when_file_unchanged(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("api_keys:\n  virustotal: stable-key\n", encoding="utf-8")

    first = snapshot_config(config_file, reason="initial snapshot")
    second = snapshot_config(config_file, reason="no-op snapshot")

    assert first["status"] == "saved"
    assert second["status"] == "unchanged"
