import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import src.tools.ioc_investigator as ioc_module
import src.tools.malware_analyzer as malware_module
from src.web.routes import analysis as analysis_route
from src.analyzers.file_type_router import FileType
from src.tools.ioc_investigator import IOCInvestigator
from src.tools.malware_analyzer import MalwareAnalyzer


@pytest.mark.asyncio
async def test_ioc_investigator_supports_tool_only_mode(mock_config, monkeypatch):
    mock_config['analysis']['enable_llm'] = True
    investigator = IOCInvestigator(mock_config)

    investigator.threat_intel.investigate_ioc_comprehensive = AsyncMock(return_value={
        'sources': {'virustotal': {'found': False}},
        'sources_checked': 1,
        'sources_flagged': 0,
    })
    investigator.llm_analyzer.analyze_ioc_results = AsyncMock(return_value={'verdict': 'SUSPICIOUS'})

    monkeypatch.setattr(
        ioc_module.IntelligentScoring,
        'calculate_ioc_score',
        staticmethod(lambda _intel_results: 35),
    )

    result = await investigator.investigate('8.8.8.8', include_llm=False)

    investigator.llm_analyzer.analyze_ioc_results.assert_not_awaited()
    assert result['llm_analysis']['note'] == 'LLM skipped for tool-only IOC investigation'
    assert result['verdict'] == 'LOW_RISK'


def _stub_malware_pipeline(monkeypatch, analyzer: MalwareAnalyzer):
    monkeypatch.setattr(
        malware_module,
        'get_file_info',
        lambda _path: {'name': 'sample.ps1', 'size': 128, 'mime_type': 'text/plain'},
    )
    monkeypatch.setattr(
        malware_module,
        'calculate_file_hashes',
        lambda _path: {
            'sha256': 'a' * 64,
            'sha1': 'b' * 40,
            'md5': 'c' * 32,
        },
    )
    monkeypatch.setattr(
        malware_module.FileTypeRouter,
        'detect_file_type',
        staticmethod(lambda _path: (FileType.SCRIPT, {'detection_method': 'test'})),
    )
    monkeypatch.setattr(analyzer, '_get_analyzer', lambda _file_type: SimpleNamespace(analyze=lambda _path: {
        'analysis_tools': ['stub'],
        'capabilities': {},
        'strings': {},
        'packer_detection': {},
        'embedded_files': {},
        'pe_analysis': {},
        'signature': {},
        'anti_analysis': [],
        'threat_indicators': [],
        'suspicious_patterns': {},
        'iocs': {'ipv4': ['8.8.8.8'], 'urls': [], 'domains': []},
    }))
    monkeypatch.setattr(
        malware_module.EntropyAnalyzer,
        'analyze_file_entropy',
        staticmethod(lambda _path: {'overall_entropy': 3.5, 'interpretation': {'category': 'LOW'}}),
    )
    monkeypatch.setattr(analyzer.ransomware_analyzer, 'analyze_file', lambda _path: {'is_ransomware': False})
    monkeypatch.setattr(analyzer.string_extractor, 'extract_strings', lambda *_args, **_kwargs: {'ascii': [], 'unicode': []})
    monkeypatch.setattr(analyzer.string_extractor, 'categorize_suspicious_strings', lambda _strings: {})
    monkeypatch.setattr(analyzer.string_extractor, 'extract_iocs_from_strings', lambda _strings: {'urls': [], 'ipv4': [], 'domains': []})
    monkeypatch.setattr(analyzer.string_extractor, 'extract_registry_keys', lambda _strings: [])
    monkeypatch.setattr(analyzer.string_extractor, 'extract_mutexes', lambda _strings: [])
    monkeypatch.setattr(analyzer.string_extractor, 'extract_user_agents', lambda _strings: [])
    monkeypatch.setattr(analyzer.string_extractor, 'get_interesting_strings', lambda _strings, limit=50: [])
    monkeypatch.setattr(analyzer.yara_scanner, 'scan_file', lambda _path: [])
    monkeypatch.setattr(
        malware_module.YaraScanner,
        'interpret_matches',
        staticmethod(lambda _matches: {'malware_families': [], 'severity': 'NONE', 'tags': []}),
    )
    analyzer.threat_intel.investigate_ioc_comprehensive = AsyncMock(return_value={
        'sources': {},
        'sources_checked': 0,
        'sources_flagged': 0,
    })
    analyzer.sandbox.check_file_sandboxes = AsyncMock(return_value={})
    monkeypatch.setattr(
        malware_module.IntelligentScoring,
        'calculate_ioc_score',
        staticmethod(lambda _intel_results: 0),
    )
    monkeypatch.setattr(
        malware_module.ToolBasedScoring,
        'calculate_file_score',
        staticmethod(lambda _input: SimpleNamespace(
            combined_score=12,
            verdict='LOW_RISK',
            contributing_factors=['stub-score'],
            breakdown={'threat_intel': 12},
            confidence=0.82,
        )),
    )
    monkeypatch.setattr(
        malware_module.FalsePositiveFilter,
        'is_false_positive',
        staticmethod(lambda _file_data, _score: (False, '')),
    )
    monkeypatch.setattr(analyzer, '_generate_mitre_mapping', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        malware_module.RuleGenerator,
        'generate_file_rules',
        staticmethod(lambda _payload: {'sigma': 'title: test-rule'}),
    )


@pytest.mark.asyncio
async def test_file_analysis_uses_tool_only_ioc_investigation(mock_config, monkeypatch, tmp_path):
    mock_config['analysis']['enable_llm'] = True
    analyzer = MalwareAnalyzer(mock_config)
    _stub_malware_pipeline(monkeypatch, analyzer)

    analyzer.ioc_investigator = SimpleNamespace(
        investigate=AsyncMock(return_value={
            'ioc': '8.8.8.8',
            'ioc_type': 'ipv4',
            'verdict': 'SUSPICIOUS',
            'threat_score': 65,
        })
    )
    analyzer.llm_analyzer.analyze_file = AsyncMock(return_value={'verdict': 'LOW_RISK', 'analysis': 'stub'})

    sample = tmp_path / 'sample.ps1'
    sample.write_text('Write-Host test', encoding='utf-8')

    result = await analyzer.analyze(str(sample))

    analyzer.ioc_investigator.investigate.assert_awaited_once_with('8.8.8.8', include_llm=False)
    analyzer.llm_analyzer.analyze_file.assert_awaited_once()
    assert result['ioc_analysis']['investigated'] == 1
    assert result['llm_analysis']['verdict'] == 'LOW_RISK'


@pytest.mark.asyncio
async def test_file_analysis_respects_enable_llm_flag(mock_config, monkeypatch, tmp_path):
    mock_config['analysis']['enable_llm'] = False
    analyzer = MalwareAnalyzer(mock_config)
    _stub_malware_pipeline(monkeypatch, analyzer)

    analyzer.ioc_investigator = SimpleNamespace(
        investigate=AsyncMock(return_value={
            'ioc': '8.8.8.8',
            'ioc_type': 'ipv4',
            'verdict': 'SUSPICIOUS',
            'threat_score': 65,
        })
    )
    analyzer.llm_analyzer.analyze_file = AsyncMock(return_value={'verdict': 'LOW_RISK', 'analysis': 'should not run'})

    sample = tmp_path / 'sample.ps1'
    sample.write_text('Write-Host test', encoding='utf-8')

    result = await analyzer.analyze(str(sample))

    analyzer.ioc_investigator.investigate.assert_awaited_once_with('8.8.8.8', include_llm=False)
    analyzer.llm_analyzer.analyze_file.assert_not_awaited()
    assert result['llm_analysis']['note'] == 'LLM analysis disabled by configuration'


@pytest.mark.asyncio
async def test_file_analysis_llm_timeout_degrades_gracefully(mock_config, monkeypatch, tmp_path):
    mock_config['analysis']['enable_llm'] = True
    mock_config['analysis']['llm_timeout_seconds'] = 0.01
    analyzer = MalwareAnalyzer(mock_config)
    _stub_malware_pipeline(monkeypatch, analyzer)

    analyzer.ioc_investigator = SimpleNamespace(
        investigate=AsyncMock(return_value={
            'ioc': '8.8.8.8',
            'ioc_type': 'ipv4',
            'verdict': 'MALICIOUS',
            'threat_score': 95,
        })
    )

    async def _slow_llm(_payload):
        await asyncio.sleep(0.05)
        return {'verdict': 'MALICIOUS', 'analysis': 'late response'}

    analyzer.llm_analyzer.analyze_file = AsyncMock(side_effect=_slow_llm)

    sample = tmp_path / 'sample.ps1'
    sample.write_text('Write-Host test', encoding='utf-8')

    result = await analyzer.analyze(str(sample))

    analyzer.llm_analyzer.analyze_file.assert_awaited_once()
    assert result['verdict'] == 'LOW_RISK'
    assert result['llm_analysis']['fallback'] is True
    assert result['llm_analysis']['verdict'] == 'LOW_RISK'
    assert 'timed out' in result['llm_analysis']['note'].lower()
    assert result['llm_analysis']['error'] == 'timeout'

    llm_step = next(
        step for step in result['raw_output']['pipeline_steps']
        if step['step'] == 'llm_analysis'
    )
    assert llm_step['status'] == 'degraded'


@pytest.mark.asyncio
async def test_file_analysis_emits_stage_progress_and_pipeline_timings(mock_config, monkeypatch, tmp_path):
    mock_config['analysis']['enable_llm'] = False
    analyzer = MalwareAnalyzer(mock_config)
    _stub_malware_pipeline(monkeypatch, analyzer)

    progress_events = []
    analyzer.set_progress_callback(lambda percent, message: progress_events.append((percent, message)))
    analyzer.ioc_investigator = SimpleNamespace(
        investigate=AsyncMock(return_value={
            'ioc': '8.8.8.8',
            'ioc_type': 'ipv4',
            'verdict': 'SUSPICIOUS',
            'threat_score': 65,
        })
    )
    analyzer.llm_analyzer.analyze_file = AsyncMock(return_value={'verdict': 'LOW_RISK', 'analysis': 'should not run'})

    sample = tmp_path / 'sample.ps1'
    sample.write_text('Write-Host test', encoding='utf-8')

    result = await analyzer.analyze(str(sample))

    assert any('Querying threat intelligence' in message for _, message in progress_events)
    assert any('Checking existing sandbox reports' in message for _, message in progress_events)
    assert any('Generating detection rules' in message for _, message in progress_events)

    pipeline_steps = result['raw_output']['pipeline_steps']
    step_names = {step['step'] for step in pipeline_steps}
    assert 'hash_reputation' in step_names
    assert 'rule_generation' in step_names
    assert all(isinstance(step.get('duration_ms'), int) for step in pipeline_steps)


def test_run_file_analysis_bg_respects_timeout_and_reports_last_stage(monkeypatch):
    class DummyMgr:
        def __init__(self):
            self.updates = []
            self.failed = None
            self.completed = None

        def update_progress(self, job_id, progress, step):
            self.updates.append((job_id, progress, step))

        def fail_job(self, job_id, error):
            self.failed = (job_id, error)

        def complete_job(self, job_id, result, verdict=None, score=None):
            self.completed = (job_id, result, verdict, score)

    class SlowAnalyzer:
        def __init__(self, _config):
            self._progress_callback = None

        def set_progress_callback(self, callback):
            self._progress_callback = callback

        async def analyze(self, _file_path):
            if self._progress_callback:
                self._progress_callback(40, 'Running static analysis...')
            await asyncio.sleep(0.05)
            return {'verdict': 'CLEAN', 'composite_score': 0}

    monkeypatch.setattr(analysis_route, '_load_config', lambda: {'analysis': {'timeout_seconds': 0.01}})
    monkeypatch.setitem(sys.modules, 'src.tools.malware_analyzer', SimpleNamespace(MalwareAnalyzer=SlowAnalyzer))

    mgr = DummyMgr()
    analysis_route._run_file_analysis_bg(mgr, 'job123', '/tmp/demo.bin')

    assert mgr.completed is None
    assert mgr.failed is not None
    assert 'timed out while Running static analysis' in mgr.failed[1]
