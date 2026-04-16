import re

from src.detection.rule_generator import RuleGenerator


def _sample_file_data(**overrides):
    base = {
        "filename": "invoice_payload.exe",
        "file_type": "pe",
        "sha256": "a" * 64,
        "sha1": "b" * 40,
        "md5": "c" * 32,
        "verdict": "MALICIOUS",
        "malware_family": "DemoLoader",
        "interesting_strings": [
            "powershell -enc ZQB2AGkAbA==",
            "https://secure-payroll-check.com/login",
        ],
        "registry_keys": [r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"],
        "mutexes": ["Global\\DEMO_MUTEX"],
        "iocs": ["185.220.101.45", "secure-payroll-check.com"],
        "yara_tags": ["loader"],
        "yara_families": ["DemoLoader"],
    }
    base.update(overrides)
    return base


def test_generate_file_rules_yara_uses_real_literals_not_hash_strings():
    rules = RuleGenerator.generate_file_rules(_sample_file_data())
    yara_rule = rules["yara"]

    assert 'hash_sha256 = "' in yara_rule
    assert '$hash_sha256' not in yara_rule
    assert '$hash_md5' not in yara_rule
    assert 'rule DemoLoader' in yara_rule
    assert "uint16(0) == 0x5A4D" in yara_rule
    assert "secure-payroll-check.com" in yara_rule
    assert "Global\\\\DEMO_MUTEX" in yara_rule


def test_generate_file_rules_sigma_id_is_stable_and_uses_file_event():
    rules_one = RuleGenerator.generate_file_rules(_sample_file_data())
    rules_two = RuleGenerator.generate_file_rules(_sample_file_data())

    sigma_one = rules_one["sigma"]
    sigma_two = rules_two["sigma"]

    id_one = re.search(r"^id:\s+(.+)$", sigma_one, re.MULTILINE).group(1)
    id_two = re.search(r"^id:\s+(.+)$", sigma_two, re.MULTILINE).group(1)

    assert id_one == id_two
    assert "category: file_event" in sigma_one
    assert "Hashes|contains:" in sigma_one
    assert "TargetFilename|endswith" in sigma_one


def test_generate_file_rules_omit_empty_hash_clauses_and_keep_rule_valid():
    rules = RuleGenerator.generate_file_rules(
        _sample_file_data(sha256="", sha1="", md5="", interesting_strings=[], registry_keys=[], mutexes=[], iocs=[])
    )

    kql_rule = rules["kql"]
    spl_rule = rules["spl"]
    sigma_rule = rules["sigma"]
    yara_rule = rules["yara"]

    assert 'SHA256 == ""' not in kql_rule
    assert 'SHA1 == ""' not in kql_rule
    assert 'MD5 == ""' not in kql_rule
    assert 'sha256=""' not in spl_rule
    assert 'sha1=""' not in spl_rule
    assert 'md5=""' not in spl_rule
    assert "1 of selection_*" in sigma_rule
    assert "$str_0" in yara_rule
    assert "$ioc_" not in yara_rule
