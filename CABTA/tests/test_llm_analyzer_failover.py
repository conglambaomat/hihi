from unittest.mock import AsyncMock

import pytest

from src.integrations.llm_analyzer import LLMAnalyzer


def _llm_config():
    return {
        'api_keys': {
            'gemini': 'AIzaSyDUMMY_valid_gemini_key_for_suite_alpha',
            'groq': 'gsk_valid_groq_key_for_suite_alpha_abcdef987654321',
            'anthropic': '',
            'openrouter': '',
        },
        'llm': {
            'provider': 'gemini',
            'gemini_model': 'gemini-3-flash-preview',
            'gemini_endpoint': 'https://generativelanguage.googleapis.com/v1beta/openai',
            'openrouter_model': 'arcee-ai/trinity-large-preview:free',
            'openrouter_endpoint': 'https://openrouter.ai/api/v1',
            'groq_model': 'meta-llama/llama-prompt-guard-2-86m',
            'groq_endpoint': 'https://api.groq.com/openai/v1',
            'auto_failover': True,
            'fallback_providers': ['groq'],
        },
    }


@pytest.mark.asyncio
async def test_llm_analyzer_fails_over_from_gemini_to_groq():
    analyzer = LLMAnalyzer(_llm_config())

    async def _gemini_failure(_prompt):
        analyzer._record_runtime_status(
            provider='gemini',
            model=analyzer._resolved_provider_model('gemini'),
            available=False,
            error='Gemini HTTP 429: quota exceeded',
            http_status=429,
        )
        return {'error': 'Gemini HTTP 429: quota exceeded'}

    async def _groq_success(_prompt):
        analyzer._record_runtime_status(
            provider='groq',
            model=analyzer._resolved_provider_model('groq'),
            available=True,
            http_status=200,
        )
        return {
            'verdict': 'MALICIOUS',
            'analysis': 'IOC evidence indicates command-and-control activity.',
            'recommendations': ['Block the infrastructure immediately.'],
        }

    analyzer._call_gemini_api = AsyncMock(side_effect=_gemini_failure)
    analyzer._call_groq_api = AsyncMock(side_effect=_groq_success)

    result = await analyzer.analyze_file({
        'filename': 'sample.txt',
        'file_type': 'text',
        'size_bytes': 128,
        'sha256': 'a' * 64,
        'hash_score': 90,
        'system_verdict': 'MALICIOUS',
        'composite_score': 85,
        'c2_patterns': [{'severity': 'high', 'description': 'beacon'}],
        'ip_addresses': [{'ip': '1.2.3.4', 'suspicious': True, 'is_private': False, 'reasons': ['known bad']}],
        'urls': [{'url': 'http://evil.test', 'suspicious': True, 'reasons': ['c2']}],
        'ioc_results': [{'ioc': '1.2.3.4', 'verdict': 'MALICIOUS', 'threat_score': 95}],
    })

    assert result['provider'] == 'groq'
    assert result['model'] == 'openai/gpt-oss-20b'
    assert result['provider_failover'] is True
    assert result['fallback_from'] == 'gemini'
    assert 'quota or rate limit' in result['note'].lower()
    assert len(result['provider_attempts']) == 2
    assert result['provider_attempts'][0]['provider'] == 'gemini'
    assert result['provider_attempts'][1]['provider'] == 'groq'


def test_llm_analyzer_rejects_prompt_guard_as_summary_model():
    analyzer = LLMAnalyzer(_llm_config())
    assert analyzer._resolved_provider_model('groq') == 'openai/gpt-oss-20b'


@pytest.mark.asyncio
async def test_llm_analyzer_nvidia_rate_limit_does_not_fail_over():
    analyzer = LLMAnalyzer({
        'api_keys': {
            'nvidia': 'nvapi-valid-build-key-abcdefghijklmnopqrstuvwxyz123456',
            'groq': 'gsk_valid_groq_key_for_suite_alpha_abcdef987654321',
        },
        'llm': {
            'provider': 'nvidia',
            'nvidia_model': 'deepseek-ai/deepseek-v3.2',
            'nvidia_endpoint': 'https://integrate.api.nvidia.com/v1',
            'auto_failover': True,
            'fallback_providers': ['groq'],
        },
    })

    async def _nvidia_failure(_prompt):
        analyzer._record_runtime_status(
            provider='nvidia',
            model=analyzer._resolved_provider_model('nvidia'),
            available=False,
            error='NVIDIA Build HTTP 429: rate limit exceeded',
            http_status=429,
        )
        return {'error': 'NVIDIA Build HTTP 429: rate limit exceeded'}

    analyzer._call_nvidia_api = AsyncMock(side_effect=_nvidia_failure)
    analyzer._call_groq_api = AsyncMock(return_value={
        'verdict': 'MALICIOUS',
        'analysis': 'unexpected fallback',
        'recommendations': [],
    })

    result = await analyzer.analyze_ioc_results('8.8.8.8', 'ip', {
        'threat_score': 5,
        'sources_checked': 1,
        'sources_flagged': 0,
        'sources': {},
    })

    assert result['provider'] == 'nvidia'
    assert result['model'] == 'deepseek-ai/deepseek-v3.2'
    assert result['rate_limited'] is True
    assert 'did not fall back' in result['note'].lower()
    analyzer._call_groq_api.assert_not_awaited()


def test_llm_analyzer_openrouter_provider_config():
    analyzer = LLMAnalyzer({
        'api_keys': {
            'openrouter': 'sk-or-v1-valid-openrouter-key-abcdefghijklmnopqrstuvwxyz123456',
        },
        'llm': {
            'provider': 'openrouter',
            'openrouter_model': 'arcee-ai/trinity-large-preview:free',
            'openrouter_endpoint': 'https://openrouter.ai/api/v1',
            'auto_failover': False,
            'fallback_providers': [],
        },
    })

    assert analyzer.provider == 'openrouter'
    assert analyzer.openrouter_key == 'sk-or-v1-valid-openrouter-key-abcdefghijklmnopqrstuvwxyz123456'
    assert analyzer._resolved_provider_model('openrouter') == 'arcee-ai/trinity-large-preview:free'
    assert analyzer.openrouter_endpoint == 'https://openrouter.ai/api/v1'
