from types import SimpleNamespace

from src.web.data_provider import WebDataProvider
from src.web.normalizer import normalize_job


def test_normalize_job_preserves_aliases_and_canonical_fields():
    job = {
        'id': 'job123',
        'analysis_type': 'ioc',
        'params': {'value': '8.8.8.8', 'mode': 'demo'},
        'status': 'completed',
        'progress': 100,
        'current_step': 'Done',
        'verdict': 'SUSPICIOUS',
        'score': 72,
        'created_at': '2026-03-30T09:00:00+00:00',
        'completed_at': '2026-03-30T09:00:05+00:00',
        'result': {'ioc': '8.8.8.8', 'threat_score': 72, 'confidence': 0.81},
    }

    normalized = normalize_job(job)

    assert normalized['job_id'] == 'job123'
    assert normalized['job_type'] == 'ioc'
    assert normalized['mode'] == 'demo'
    assert normalized['submitted_input']['value'] == '8.8.8.8'
    assert normalized['confidence'] == 0.81
    assert normalized['id'] == 'job123'
    assert normalized['analysis_type'] == 'ioc'
    assert normalized['params']['value'] == '8.8.8.8'


def test_provider_uses_demo_dataset_when_enabled(mock_config):
    mock_config['web'] = {'demo_mode': {'enabled': True, 'dataset': 'default'}}
    provider = WebDataProvider(mock_config)

    jobs = provider.demo_data()['jobs']
    sources = provider.demo_data()['sources']

    assert provider.is_demo_mode() is True
    assert provider.app_mode() == 'demo'
    assert any(job['analysis_type'] == 'ioc' for job in jobs)
    assert any(source['mode'] == 'demo' for source in sources)


def test_provider_build_demo_job_result_applies_input_filename(mock_config):
    mock_config['web'] = {'demo_mode': {'enabled': True, 'dataset': 'default'}}
    provider = WebDataProvider(mock_config)

    result = provider.build_demo_job_result('file', {'filename': 'custom.exe'}, 'demo-job-1')

    assert result['mode'] == 'demo'
    assert result['job_id'] == 'demo-job-1'
    assert result['file_info']['filename'] == 'custom.exe'


def test_provider_live_sources_distinguish_configured_available_and_manual(mock_config):
    mock_config['api_keys']['shodan'] = 'shodan_key_prod_abcdef12345'
    mock_config['api_keys']['urlscan'] = 'urlscan_key_prod_abcdef12345'
    provider = WebDataProvider(mock_config)
    app = SimpleNamespace(state=SimpleNamespace(mcp_client=None, sandbox_orchestrator=None, agent_loop=None))

    sources = provider.get_sources(app)
    source_map = {item['name']: item for item in sources}
    summary = provider.source_health_summary(app)

    assert source_map['Shodan']['status'] == 'configured'
    assert source_map['URLScan']['status'] == 'manual'
    assert source_map['Abuse.ch URLhaus']['status'] == 'available'
    assert summary['configured'] >= 1
    assert summary['manual'] == 1
    assert summary['ready'] >= 1


def test_feature_status_marks_static_only_sandbox_and_missing_groq_key_as_degraded(mock_config):
    mock_config['llm'] = {'provider': 'groq'}
    mock_config['analysis']['enable_sandbox'] = True
    mock_config['api_keys']['virustotal'] = ''
    provider = WebDataProvider(mock_config)

    sandbox = SimpleNamespace(
        get_sandbox_status=lambda: [
            {'id': 'docker', 'available': False},
            {'id': 'local_static', 'available': True},
        ]
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            mcp_client=None,
            sandbox_orchestrator=sandbox,
            agent_loop=None,
        )
    )

    status = provider.feature_status(app)

    assert status['llm']['status'] == 'degraded'
    assert status['sandbox']['status'] == 'degraded'
    assert status['sandbox']['label'] == 'Static-only'


def test_feature_status_distinguishes_lookup_only_sandbox_from_execution_ready(mock_config):
    mock_config['analysis']['enable_sandbox'] = True
    mock_config['api_keys']['virustotal'] = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    provider = WebDataProvider(mock_config)

    sandbox = SimpleNamespace(
        get_sandbox_status=lambda: [
            {'id': 'docker', 'available': False},
            {'id': 'vm', 'available': False},
            {'id': 'local_static', 'available': False},
            {'id': 'cloud_api', 'available': False},
        ]
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            mcp_client=None,
            sandbox_orchestrator=sandbox,
            agent_loop=None,
        )
    )

    status = provider.feature_status(app)

    assert status['sandbox']['status'] == 'degraded'
    assert status['sandbox']['label'] == 'Lookup-only'
