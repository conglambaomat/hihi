from src.analyzers.text_analyzer import TextFileAnalyzer


def test_text_analyzer_truncates_large_files_for_interactive_scan(tmp_path):
    analyzer = TextFileAnalyzer({"analysis": {"text_max_scan_mb": 0.001}})

    sample = tmp_path / "large.log"
    line = (
        "callback=http://185.220.101.45:8443/beacon sleep=5000 "
        "password=secret123 secure-payroll-check.com CVE-2024-12345\n"
    )
    with open(sample, "w", encoding="utf-8") as handle:
        while handle.tell() < 400_000:
            handle.write(line)

    result = analyzer.analyze(str(sample))

    assert result["scan_scope"]["truncated"] is True
    assert result["scan_scope"]["strategy"] == "head_tail"
    assert result["scan_scope"]["total_bytes"] > result["scan_scope"]["scanned_bytes"]
    assert "Large text file scan truncated" in result["analysis_note"]


def test_text_analyzer_emits_substage_progress_messages(tmp_path):
    analyzer = TextFileAnalyzer({"analysis": {"text_max_scan_mb": 1}})
    progress = []
    analyzer.set_progress_callback(lambda percent, message: progress.append((percent, message)))

    sample = tmp_path / "sample.log"
    sample.write_text(
        "callback=http://185.220.101.45:8443/beacon sleep=5000 password=secret123\n",
        encoding="utf-8",
    )

    result = analyzer.analyze(str(sample))

    assert result["verdict"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}
    messages = [message for _, message in progress]
    assert any("Loading text content" in message for message in messages)
    assert any("Extracting IPs, URLs, domains, and hashes" in message for message in messages)
    assert any("Detecting C2 and malware patterns" in message for message in messages)
    assert any("Calculating threat score and summary" in message for message in messages)
