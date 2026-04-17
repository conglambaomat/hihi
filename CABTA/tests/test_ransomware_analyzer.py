import time

from src.analyzers.ransomware_analyzer import RansomwareAnalyzer


def test_ransomware_analyzer_handles_long_single_line_text_quickly(tmp_path):
    analyzer = RansomwareAnalyzer()

    sample = tmp_path / "mdm_like.jpg"
    long_line = (
        "A" * 150000
        + " HOW_TO_RECOVER_FILES.txt "
        + " callback=http://185.220.101.45:8443/beacon "
        + "B" * 150000
    )
    sample.write_text(long_line, encoding="utf-8")

    started = time.perf_counter()
    result = analyzer.analyze_file(str(sample))
    elapsed = time.perf_counter() - started

    assert elapsed < 2.0
    assert "indicator_count" in result
    assert result["verdict"] in {"RANSOMWARE", "SUSPECTED_RANSOMWARE", "NOT_RANSOMWARE"}

