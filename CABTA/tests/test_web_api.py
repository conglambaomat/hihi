"""
Tests for Web API (Faz 4).
Tests cover: analysis_manager, case_store, models, API endpoints.
"""

import json
import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from src.web.analysis_manager import AnalysisManager
from src.web.case_store import CaseStore
from src.web.models import (
    IOCRequest, IOCType, AnalysisState, Verdict,
    CaseCreate, CaseStatus, CaseNote, DashboardStats,
    FileUploadResponse,
)


# ========== Analysis Manager ==========

class TestAnalysisManager:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        db = str(tmp_path / 'test_jobs.db')
        self.mgr = AnalysisManager(db_path=db)

    def test_create_job(self):
        job_id = self.mgr.create_job('ioc', {'value': '8.8.8.8'})
        assert len(job_id) == 12
        job = self.mgr.get_job(job_id)
        assert job is not None
        assert job['status'] == 'queued'
        assert job['analysis_type'] == 'ioc'

    def test_get_nonexistent_job(self):
        assert self.mgr.get_job('nonexistent') is None

    def test_update_progress(self):
        job_id = self.mgr.create_job('file', {'sha256': 'abc'})
        self.mgr.update_progress(job_id, 50, 'Scanning with YARA...')
        job = self.mgr.get_job(job_id)
        assert job['status'] == 'running'
        assert job['progress'] == 50
        assert job['current_step'] == 'Scanning with YARA...'

    def test_complete_job(self):
        job_id = self.mgr.create_job('ioc', {'value': 'evil.com'})
        result = {'verdict': 'MALICIOUS', 'score': 85}
        self.mgr.complete_job(job_id, result, verdict='MALICIOUS', score=85)
        job = self.mgr.get_job(job_id)
        assert job['status'] == 'completed'
        assert job['progress'] == 100
        assert job['verdict'] == 'MALICIOUS'
        assert job['score'] == 85
        assert job['result'] == result

    def test_fail_job(self):
        job_id = self.mgr.create_job('ioc', {'value': 'test'})
        self.mgr.fail_job(job_id, 'API timeout')
        job = self.mgr.get_job(job_id)
        assert job['status'] == 'failed'
        assert 'timeout' in job['current_step']

    def test_list_jobs(self):
        self.mgr.create_job('ioc', {'v': '1'})
        self.mgr.create_job('file', {'v': '2'})
        self.mgr.create_job('email', {'v': '3'})
        jobs = self.mgr.list_jobs()
        assert len(jobs) == 3

    def test_list_jobs_with_status_filter(self):
        j1 = self.mgr.create_job('ioc', {'v': '1'})
        j2 = self.mgr.create_job('ioc', {'v': '2'})
        self.mgr.complete_job(j1, {}, verdict='CLEAN', score=5)
        queued = self.mgr.list_jobs(status='queued')
        completed = self.mgr.list_jobs(status='completed')
        assert len(queued) == 1
        assert len(completed) == 1

    def test_get_stats(self):
        j1 = self.mgr.create_job('ioc', {'v': '1'})
        j2 = self.mgr.create_job('ioc', {'v': '2'})
        j3 = self.mgr.create_job('ioc', {'v': '3'})
        self.mgr.complete_job(j1, {}, verdict='MALICIOUS', score=90)
        self.mgr.complete_job(j2, {}, verdict='CLEAN', score=5)
        self.mgr.complete_job(j3, {}, verdict='SUSPICIOUS', score=55)
        stats = self.mgr.get_stats()
        assert stats['total_analyses'] == 3
        assert stats['malicious_count'] == 1
        assert stats['clean_count'] == 1
        assert stats['suspicious_count'] == 1

    def test_list_with_limit_offset(self):
        for i in range(10):
            self.mgr.create_job('ioc', {'v': str(i)})
        page1 = self.mgr.list_jobs(limit=3, offset=0)
        page2 = self.mgr.list_jobs(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]['id'] != page2[0]['id']


# ========== Case Store ==========

class TestCaseStore:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        db = str(tmp_path / 'test_cases.db')
        self.store = CaseStore(db_path=db)

    def test_create_case(self):
        case_id = self.store.create_case('Phishing Investigation', 'Suspicious email', 'high')
        assert len(case_id) == 12
        case = self.store.get_case(case_id)
        assert case is not None
        assert case['title'] == 'Phishing Investigation'
        assert case['severity'] == 'high'
        assert case['status'] == 'Open'

    def test_get_nonexistent_case(self):
        assert self.store.get_case('nonexistent') is None

    def test_list_cases(self):
        self.store.create_case('Case 1')
        self.store.create_case('Case 2')
        cases = self.store.list_cases()
        assert len(cases) == 2

    def test_update_status(self):
        case_id = self.store.create_case('Test')
        ok = self.store.update_case_status(case_id, 'Investigating')
        assert ok is True
        case = self.store.get_case(case_id)
        assert case['status'] == 'Investigating'

    def test_update_nonexistent_returns_false(self):
        ok = self.store.update_case_status('nonexistent', 'Closed')
        assert ok is False

    def test_link_analysis(self):
        case_id = self.store.create_case('Test')
        ok = self.store.link_analysis(case_id, 'analysis123')
        assert ok is True
        case = self.store.get_case(case_id)
        assert len(case['analyses']) == 1
        assert case['analyses'][0]['analysis_id'] == 'analysis123'

    def test_add_note(self):
        case_id = self.store.create_case('Test')
        note_id = self.store.add_note(case_id, 'Found malware sample', 'john')
        assert len(note_id) == 10
        case = self.store.get_case(case_id)
        assert len(case['notes']) == 1
        assert case['notes'][0]['content'] == 'Found malware sample'
        assert case['notes'][0]['author'] == 'john'

    def test_multiple_notes(self):
        case_id = self.store.create_case('Test')
        self.store.add_note(case_id, 'Note 1')
        self.store.add_note(case_id, 'Note 2')
        self.store.add_note(case_id, 'Note 3')
        case = self.store.get_case(case_id)
        assert len(case['notes']) == 3

    def test_list_with_counts(self):
        case_id = self.store.create_case('Test')
        self.store.link_analysis(case_id, 'a1')
        self.store.link_analysis(case_id, 'a2')
        self.store.add_note(case_id, 'note1')
        cases = self.store.list_cases()
        assert cases[0]['analysis_count'] == 2
        assert cases[0]['note_count'] == 1


# ========== Pydantic Models ==========

class TestModels:
    def test_ioc_request(self):
        req = IOCRequest(value='8.8.8.8', ioc_type=IOCType.IP)
        assert req.value == '8.8.8.8'
        assert req.ioc_type == IOCType.IP

    def test_ioc_request_auto_type(self):
        req = IOCRequest(value='evil.com')
        assert req.ioc_type is None

    def test_file_upload_response(self):
        resp = FileUploadResponse(
            analysis_id='abc123',
            filename='malware.exe',
            sha256='deadbeef' * 8,
        )
        assert resp.status == AnalysisState.QUEUED

    def test_case_create(self):
        case = CaseCreate(title='Test', severity='high')
        assert case.title == 'Test'
        assert case.severity == 'high'

    def test_case_note(self):
        note = CaseNote(content='Important finding')
        assert note.author == 'analyst'

    def test_dashboard_stats_defaults(self):
        stats = DashboardStats()
        assert stats.total_analyses == 0
        assert stats.average_score == 0.0

    def test_verdict_enum(self):
        assert Verdict.MALICIOUS.value == 'MALICIOUS'
        assert Verdict.CLEAN.value == 'CLEAN'

    def test_case_status_enum(self):
        assert CaseStatus.OPEN.value == 'Open'
        assert CaseStatus.CLOSED.value == 'Closed'


# ========== FastAPI App Integration ==========

class TestFastAPIEndpoints:
    """Test API endpoints using TestClient."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test client with temp databases."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi not installed")

        from src.web.app import create_app
        from src.workflows.service import WorkflowService
        from src.case_intelligence.service import CaseIntelligenceService

        self.app = create_app()
        # Override with temp DBs
        self.app.state.analysis_manager = AnalysisManager(
            db_path=str(tmp_path / 'jobs.db')
        )
        self.app.state.case_store = CaseStore(
            db_path=str(tmp_path / 'cases.db')
        )
        self.app.state.workflow_service = WorkflowService(
            workflow_registry=self.app.state.workflow_registry,
            agent_store=self.app.state.agent_store,
            case_store=self.app.state.case_store,
        )
        self.app.state.case_intelligence = CaseIntelligenceService(
            analysis_manager=self.app.state.analysis_manager,
            agent_store=self.app.state.agent_store,
            case_store=self.app.state.case_store,
            governance_store=self.app.state.governance_store,
        )
        self.client = TestClient(self.app)

    def test_health_check(self):
        r = self.client.get('/api/config/health')
        assert r.status_code == 200
        data = r.json()
        assert data['status'] in ('healthy', 'degraded', 'unhealthy')
        assert 'checks' in data
        assert 'capabilities' in data
        assert 'issues' in data
        assert 'daemon' in data['capabilities']

    def test_health_check_renders_html_for_browser_navigation(self):
        r = self.client.get('/api/config/health', headers={'accept': 'text/html'})
        assert r.status_code == 200
        assert 'text/html' in r.headers['content-type']
        assert 'System Health' in r.text
        assert 'Raw JSON' in r.text

    def test_health_check_reports_unhealthy_when_critical_component_missing(self):
        self.app.state.email_analyzer = None

        r = self.client.get('/api/config/health')

        assert r.status_code == 200
        data = r.json()
        assert data['status'] == 'unhealthy'
        assert any('email_analyzer' in issue for issue in data['issues'])

    def test_health_check_reports_degraded_when_enabled_sandbox_is_static_only(self):
        self.app.state.config = {
            **self.app.state.config,
            'analysis': {**self.app.state.config.get('analysis', {}), 'enable_sandbox': True},
            'llm': {
                'provider': 'groq',
                'groq_endpoint': 'https://api.groq.com/openai/v1',
                'groq_model': 'openai/gpt-oss-20b',
            },
            'api_keys': {
                **self.app.state.config.get('api_keys', {}),
                'groq': 'gsk-test-key',
            },
        }
        self.app.state.web_provider.config = self.app.state.config
        self.app.state.sandbox_orchestrator = SimpleNamespace(
            get_sandbox_status=lambda: [
                {'id': 'docker', 'available': False},
                {'id': 'local_static', 'available': True},
            ]
        )

        r = self.client.get('/api/config/health')

        assert r.status_code == 200
        data = r.json()
        assert data['status'] == 'degraded'
        assert data['capabilities']['llm_runtime']['provider'] == 'groq'
        assert any('Sandboxing is enabled' in issue for issue in data['issues'])

    def test_system_info(self):
        r = self.client.get('/api/config/info')
        assert r.status_code == 200
        data = r.json()
        assert data['app'] == 'AISA'
        assert data['mode'] in ('live', 'demo')
        assert 'demo_enabled' in data

    def test_tool_status(self):
        r = self.client.get('/api/config/tools')
        assert r.status_code == 200
        assert 'tools' in r.json()

    def test_analyze_ioc(self):
        r = self.client.post('/api/analysis/ioc', json={
            'value': '8.8.8.8', 'ioc_type': 'ip'
        })
        assert r.status_code == 200
        data = r.json()
        assert 'analysis_id' in data
        assert data['status'] == 'queued'

    def test_get_analysis(self):
        # Create first
        r = self.client.post('/api/analysis/ioc', json={'value': 'evil.com'})
        aid = r.json()['analysis_id']
        # Get
        r2 = self.client.get(f'/api/analysis/{aid}')
        assert r2.status_code == 200
        data = r2.json()
        assert data['analysis_type'] == 'ioc'
        assert data['job_type'] == 'ioc'
        assert 'submitted_input' in data

    def test_get_analysis_status(self):
        r = self.client.post('/api/analysis/ioc', json={'value': 'test'})
        aid = r.json()['analysis_id']
        r2 = self.client.get(f'/api/analysis/{aid}/status')
        assert r2.status_code == 200
        # Background thread may have already started so status could be
        # queued, running, completed, or failed.
        assert r2.json()['status'] in ('queued', 'running', 'completed', 'failed')

    def test_analysis_not_found(self):
        r = self.client.get('/api/analysis/nonexistent')
        assert r.status_code == 404

    def test_dashboard_stats(self):
        r = self.client.get('/api/dashboard/stats')
        assert r.status_code == 200

    def test_dashboard_recent(self):
        r = self.client.get('/api/dashboard/recent')
        assert r.status_code == 200
        assert 'items' in r.json()

    def test_dashboard_sources(self):
        r = self.client.get('/api/dashboard/sources')
        assert r.status_code == 200
        data = r.json()
        assert 'sources' in data
        assert 'summary' in data

    def test_agent_profiles_endpoint(self):
        r = self.client.get('/api/agent/profiles')
        assert r.status_code == 200
        data = r.json()
        assert 'profiles' in data
        assert any(item['id'] == 'threat_hunter' for item in data['profiles'])
        assert any(item['id'] == 'correlator' for item in data['profiles'])

    def test_agent_profile_detail_endpoint(self):
        r = self.client.get('/api/agent/profiles/responder')
        assert r.status_code == 200
        data = r.json()
        assert data['id'] == 'responder'
        assert data['can_issue_verdict'] is False

    def test_agent_capability_catalog_endpoint(self):
        r = self.client.get('/api/agent/capabilities')
        assert r.status_code == 200
        data = r.json()
        assert data['verdict_authority']['owner'] == 'cabta_scoring'
        assert data['agent_profiles']['count'] >= 1

    def test_workflows_list_endpoint(self):
        r = self.client.get('/api/workflows')
        assert r.status_code == 200
        data = r.json()
        assert 'workflows' in data
        assert any(item['id'] == 'incident-response' for item in data['workflows'])
        assert any(item['id'] == 'full-investigation' for item in data['workflows'])
        full = next(item for item in data['workflows'] if item['id'] == 'full-investigation')
        assert full['multi_agent'] is True
        assert len(full['agents']) > 1

    def test_workflow_detail_endpoint(self):
        r = self.client.get('/api/workflows/incident-response')
        assert r.status_code == 200
        data = r.json()
        assert data['playbook_id'] == 'incident_response'
        assert data['default_agent_profile'] == 'responder'

    def test_skill_workflow_detail_endpoint(self):
        r = self.client.get('/api/workflows/full-investigation')
        assert r.status_code == 200
        data = r.json()
        assert data['definition_kind'] == 'skill'
        assert data['default_agent_profile'] == 'investigator'
        assert len(data['agents']) > 1

    def test_workflow_validate_endpoint(self):
        r = self.client.get('/api/workflows/ioc-triage/validate')
        assert r.status_code == 200
        data = r.json()
        assert data['workflow_id'] == 'ioc-triage'
        assert data['status'] in ('ready', 'degraded', 'blocked')

    def test_workflow_run_uses_playbook_backend(self):
        self.app.state.playbook_engine.execute = AsyncMock(return_value='wf-session')
        r = self.client.post('/api/workflows/incident-response/run', json={
            'goal': 'Respond to a malware incident',
            'params': {'alert_text': 'Suspicious beaconing'},
        })
        assert r.status_code == 200
        data = r.json()
        assert data['workflow_id'] == 'incident-response'
        assert data['backend'] == 'playbook'
        assert data['session_id'] == 'wf-session'

    def test_workflow_run_accepts_inputs_alias_for_params(self):
        self.app.state.playbook_engine.execute = AsyncMock(return_value='wf-session')

        r = self.client.post('/api/workflows/threat-hunt/run', json={
            'inputs': {
                'hunt_hypothesis': 'Investigate suspicious outbound beaconing',
                'known_indicators': {'ips': ['185.220.101.45']},
            },
        })

        assert r.status_code == 200
        args = self.app.state.playbook_engine.execute.await_args.args
        assert args[0] == 'threat_hunt'
        assert args[1]['hunt_hypothesis'] == 'Investigate suspicious outbound beaconing'
        assert args[1]['known_indicators']['ips'] == ['185.220.101.45']

    def test_chat_playbook_accepts_structured_json_input(self):
        self.app.state.playbook_engine.execute = AsyncMock(return_value='chat-playbook-session')

        r = self.client.post('/api/chat', json={
            'playbook_id': 'alert_triage',
            'message': json.dumps({
                'alert_text': 'Suspicious login from 10.0.0.5',
                'alert_source': 'SIEM',
                'alert_severity': 'high',
            }),
        })

        assert r.status_code == 200
        data = r.json()
        assert data['session_id'] == 'chat-playbook-session'

        args = self.app.state.playbook_engine.execute.await_args.args
        assert args[0] == 'alert_triage'
        assert args[1]['alert_text'] == 'Suspicious login from 10.0.0.5'
        assert args[1]['alert_source'] == 'SIEM'
        assert args[1]['alert_severity'] == 'high'

    def test_chat_playbook_maps_plain_text_to_first_required_input(self):
        self.app.state.playbook_engine.execute = AsyncMock(return_value='chat-playbook-session')

        r = self.client.post('/api/chat', json={
            'playbook_id': 'alert_triage',
            'message': 'SIEM alert: suspicious outbound connection to 10.0.0.5',
        })

        assert r.status_code == 200
        args = self.app.state.playbook_engine.execute.await_args.args
        assert args[0] == 'alert_triage'
        assert args[1]['alert_text'] == 'SIEM alert: suspicious outbound connection to 10.0.0.5'

    def test_delete_agent_session_endpoint_removes_session_children(self):
        session_id = self.app.state.agent_store.create_session(
            goal='Delete from investigations',
        )
        self.app.state.agent_store.add_step(
            session_id,
            1,
            'thinking',
            'Collect evidence',
        )
        self.app.state.agent_store.upsert_specialist_task(
            session_id=session_id,
            workflow_id='ioc-triage',
            profile_id='triage',
            phase_order=0,
            status='active',
            summary='Triage in progress',
        )

        r = self.client.delete(f'/api/agent/sessions/{session_id}')
        assert r.status_code == 200
        assert r.json()['status'] == 'deleted'
        assert self.app.state.agent_store.get_session(session_id) is None
        assert self.app.state.agent_store.get_steps(session_id) == []
        assert self.app.state.agent_store.list_specialist_tasks(session_id) == []

    def test_workflow_sessions_endpoint(self):
        session_id = self.app.state.agent_store.create_session(
            goal='Run workflow',
            metadata={'workflow_id': 'ioc-triage', 'current_step': 1, 'max_steps': 4},
        )
        self.app.state.agent_store.add_step(
            session_id,
            1,
            'thinking',
            'Investigate IOC 8.8.8.8',
            tool_name='investigate_ioc',
        )
        self.app.state.agent_store.upsert_specialist_task(
            session_id=session_id,
            workflow_id='ioc-triage',
            profile_id='triage',
            phase_order=0,
            status='active',
            summary='Triage is active',
        )

        r = self.client.get('/api/workflows/sessions')
        assert r.status_code == 200
        data = r.json()
        assert any(item['session_id'] == session_id for item in data['items'])

        r2 = self.client.get(f'/api/workflows/sessions/{session_id}')
        assert r2.status_code == 200
        detail = r2.json()
        assert detail['session_id'] == session_id
        assert len(detail['steps']) == 1
        assert len(detail['specialist_tasks']) == 1

        r3 = self.client.get(f'/api/agent/sessions/{session_id}/specialists')
        assert r3.status_code == 200
        assert len(r3.json()['items']) == 1

    def test_workflows_page(self):
        r = self.client.get('/agent/workflows')
        assert r.status_code == 200
        assert 'Workflow Registry' in r.text

    def test_approvals_page(self):
        approval_id = self.app.state.governance_store.create_approval(
            session_id='sess-approval',
            case_id='case-approval',
            workflow_id='incident-response',
            action_type='tool_execution',
            tool_name='block_ip',
            target={'ip': '8.8.8.8'},
            rationale='Containment requested',
        )
        assert approval_id

        r = self.client.get('/agent/approvals')
        assert r.status_code == 200
        assert 'Approvals' in r.text
        assert 'Approve' in r.text
        assert 'Reject' in r.text
        assert approval_id in r.text

    def test_decisions_page(self):
        decision_id = self.app.state.governance_store.log_ai_decision(
            session_id='sess-decision',
            case_id='case-decision',
            workflow_id='ioc-triage',
            profile_id='triage',
            decision_type='final_answer',
            summary='IOC is suspicious',
        )
        assert decision_id

        r = self.client.get('/agent/decisions')
        assert r.status_code == 200
        assert 'Decision Log' in r.text
        assert 'Save Feedback' in r.text
        assert decision_id in r.text

    def test_governance_approval_endpoints(self):
        approval_id = self.app.state.governance_store.create_approval(
            session_id='sess-approval',
            case_id='case-approval',
            workflow_id='incident-response',
            action_type='tool_execution',
            tool_name='sandbox_submit',
            target={'file_path': 'C:/samples/a.exe'},
            rationale='Need dynamic analysis',
        )

        r = self.client.get('/api/governance/approvals')
        assert r.status_code == 200
        assert any(item['id'] == approval_id for item in r.json()['items'])

        r2 = self.client.get(f'/api/governance/approvals/{approval_id}')
        assert r2.status_code == 200
        assert r2.json()['tool_name'] == 'sandbox_submit'

        r3 = self.client.post(
            f'/api/governance/approvals/{approval_id}/review',
            json={'approved': True, 'reviewer': 'lead', 'comment': 'Approved'},
        )
        assert r3.status_code == 200
        reviewed = self.app.state.governance_store.get_approval(approval_id)
        assert reviewed['status'] == 'approved'

    def test_governance_decision_endpoints(self):
        decision_id = self.app.state.governance_store.log_ai_decision(
            session_id='sess-decision',
            case_id='case-decision',
            workflow_id='threat-hunt',
            profile_id='threat_hunter',
            decision_type='run_playbook',
            summary='Escalate into structured hunt',
            rationale='IOC cluster requires hunt workflow',
        )

        r = self.client.get('/api/governance/decisions')
        assert r.status_code == 200
        assert any(item['id'] == decision_id for item in r.json()['items'])

        r2 = self.client.get(f'/api/governance/decisions/{decision_id}')
        assert r2.status_code == 200
        assert r2.json()['decision_type'] == 'run_playbook'

        r3 = self.client.post(
            f'/api/governance/decisions/{decision_id}/feedback',
            json={'feedback': 'Useful escalation', 'reviewer': 'lead'},
        )
        assert r3.status_code == 200
        decision = self.app.state.governance_store.get_ai_decision(decision_id)
        assert decision['feedback'] == 'Useful escalation'

    def test_create_case(self):
        r = self.client.post('/api/cases', json={
            'title': 'Test Case', 'severity': 'high'
        })
        assert r.status_code == 200
        assert 'id' in r.json()

    def test_list_cases(self):
        self.client.post('/api/cases', json={'title': 'C1'})
        self.client.post('/api/cases', json={'title': 'C2'})
        r = self.client.get('/api/cases')
        assert r.status_code == 200
        assert len(r.json()['items']) == 2

    def test_get_case(self):
        r = self.client.post('/api/cases', json={'title': 'Test'})
        cid = r.json()['id']
        r2 = self.client.get(f'/api/cases/{cid}')
        assert r2.status_code == 200
        assert r2.json()['title'] == 'Test'

    def test_case_not_found(self):
        r = self.client.get('/api/cases/nonexistent')
        assert r.status_code == 404

    def test_update_case_status(self):
        r = self.client.post('/api/cases', json={'title': 'Test'})
        cid = r.json()['id']
        r2 = self.client.patch(f'/api/cases/{cid}/status', json={'status': 'Investigating'})
        assert r2.status_code == 200

    def test_add_case_note(self):
        r = self.client.post('/api/cases', json={'title': 'Test'})
        cid = r.json()['id']
        r2 = self.client.post(f'/api/cases/{cid}/notes', json={
            'content': 'Important finding', 'author': 'analyst'
        })
        assert r2.status_code == 200
        assert 'id' in r2.json()

    def test_case_intelligence_endpoints(self):
        r = self.client.post('/api/cases', json={'title': 'Threat Case', 'severity': 'high'})
        cid = r.json()['id']

        aid = self.app.state.analysis_manager.create_job('ioc', {'value': '8.8.8.8'})
        self.app.state.analysis_manager.complete_job(
            aid,
            {'ioc': '8.8.8.8', 'verdict': 'SUSPICIOUS'},
            verdict='SUSPICIOUS',
            score=55,
        )
        self.app.state.case_store.link_analysis(cid, aid)
        self.app.state.case_store.add_note(cid, 'Analyst note', 'analyst')

        session_id = self.app.state.agent_store.create_session(
            goal='Investigate 8.8.8.8 on HOST-1',
            case_id=cid,
            metadata={'workflow_id': 'ioc-triage', 'agent_profile_id': 'triage', 'current_step': 1, 'max_steps': 4},
        )
        self.app.state.agent_store.add_step(
            session_id,
            1,
            'thinking',
            'Investigate IOC 8.8.8.8 on HOST-1',
            tool_name='investigate_ioc',
        )
        self.app.state.case_store.link_workflow(cid, session_id, 'ioc-triage')

        approval_id = self.app.state.governance_store.create_approval(
            session_id=session_id,
            case_id=cid,
            workflow_id='ioc-triage',
            action_type='tool_execution',
            tool_name='block_ip',
            target={'ip': '8.8.8.8'},
            rationale='Contain IOC',
        )
        decision_id = self.app.state.governance_store.log_ai_decision(
            session_id=session_id,
            case_id=cid,
            workflow_id='ioc-triage',
            profile_id='triage',
            decision_type='final_answer',
            summary='IOC is suspicious',
        )

        graph = self.client.get(f'/api/cases/{cid}/graph')
        assert graph.status_code == 200
        graph_data = graph.json()
        assert graph_data['node_count'] >= 4
        assert any(node['type'] == 'ip' for node in graph_data['nodes'])

        timeline = self.client.get(f'/api/cases/{cid}/timeline')
        assert timeline.status_code == 200
        timeline_data = timeline.json()
        assert timeline_data['event_count'] >= 4

        workflows = self.client.get(f'/api/cases/{cid}/workflows')
        assert workflows.status_code == 200
        assert any(item['session_id'] == session_id for item in workflows.json()['items'])

        approvals = self.client.get(f'/api/cases/{cid}/approvals')
        assert approvals.status_code == 200
        assert any(item['id'] == approval_id for item in approvals.json()['items'])

        decisions = self.client.get(f'/api/cases/{cid}/decisions')
        assert decisions.status_code == 200
        assert any(item['id'] == decision_id for item in decisions.json()['items'])

    def test_report_json(self):
        # Create and complete a job
        r = self.client.post('/api/analysis/ioc', json={'value': 'test'})
        aid = r.json()['analysis_id']
        mgr = self.app.state.analysis_manager
        mgr.complete_job(aid, {'verdict': 'CLEAN'}, verdict='CLEAN', score=5)
        r2 = self.client.get(f'/api/reports/{aid}/json')
        assert r2.status_code == 200
        assert r2.json()['job_id'] == aid

    def test_report_mitre_layer(self):
        # Create job directly (not via POST which spawns a bg thread that
        # may race and overwrite our result).
        mgr = self.app.state.analysis_manager
        aid = mgr.create_job('ioc', {'value': 'test'})
        mgr.complete_job(aid, {'mitre_techniques': [
            {'technique_id': 'T1059', 'tactic': 'Execution', 'technique_name': 'Scripting'}
        ]}, verdict='SUSPICIOUS', score=50)
        r2 = self.client.get(f'/api/reports/{aid}/mitre')
        assert r2.status_code == 200
        layer = r2.json()
        assert len(layer['techniques']) == 1

    def test_file_upload(self):
        import io
        file_content = b'MZ' + b'\x00' * 100
        r = self.client.post(
            '/api/analysis/file',
            files={'file': ('test.exe', io.BytesIO(file_content), 'application/octet-stream')},
        )
        assert r.status_code == 200
        data = r.json()
        assert 'analysis_id' in data
        assert data['filename'] == 'test.exe'
        assert len(data['sha256']) == 64

    def test_root_page_is_dashboard(self):
        r = self.client.get('/')
        assert r.status_code == 200
        assert 'Dashboard' in r.text

    def test_demo_mode_sources_and_seeded_report(self):
        self.app.state.config = {
            **self.app.state.config,
            'web': {'demo_mode': {'enabled': True, 'dataset': 'default'}},
        }
        self.app.state.web_provider.config = self.app.state.config

        sources = self.client.get('/api/dashboard/sources')
        assert sources.status_code == 200
        assert sources.json()['mode'] == 'demo'

        report = self.client.get('/api/reports/demo-ioc-001/json')
        assert report.status_code == 200
        assert report.json()['mode'] == 'demo'
