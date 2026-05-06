(function () {
    'use strict';

    function byId(id) { return document.getElementById(id); }
    function asArray(value) { return Array.isArray(value) ? value : []; }
    function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }
    function text(value, fallback) {
        var out = value === null || value === undefined || value === '' ? fallback : value;
        return String(out === undefined ? '' : out);
    }
    function appendText(parent, tag, className, value) {
        var el = document.createElement(tag);
        if (className) el.className = className;
        el.textContent = text(value, '');
        parent.appendChild(el);
        return el;
    }
    function safePercent(done, total) {
        if (!total) return 0;
        return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
    }

    function loadJson(url) {
        return fetch(url, { headers: { 'Accept': 'application/json' } }).then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        });
    }

    function renderMilestones(progress) {
        var node = byId('milestoneMap');
        clear(node);
        var milestones = asArray(progress.milestone_statuses);
        var done = 0;
        milestones.forEach(function (item) {
            var status = text(item.status, 'not_started').toLowerCase();
            if (status === 'satisfied' || status === 'completed') done += 1;
            var card = document.createElement('div');
            card.className = 'milestone-node milestone-' + status.replace(/[^a-z0-9_-]/g, '-');
            appendText(card, 'span', 'milestone-state', status.replace(/_/g, ' '));
            appendText(card, 'strong', '', item.name || item.milestone_id || 'Milestone');
            appendText(card, 'small', '', item.reason || item.detail || 'Evidence pending');
            node.appendChild(card);
        });
        if (!milestones.length) appendText(node, 'p', 'soc-empty', 'No milestone telemetry yet.');
        var summary = byId('milestoneSummary');
        if (summary) summary.textContent = done + '/' + milestones.length + ' complete';
        return safePercent(done, milestones.length || asArray(progress.milestones).length);
    }

    function renderActions(progress) {
        var node = byId('actionQueue');
        clear(node);
        var actions = asArray(progress.pending_required_actions).concat(asArray(progress.planned_actions));
        var seen = {};
        actions = actions.filter(function (item) {
            var key = JSON.stringify(item || {});
            if (seen[key]) return false;
            seen[key] = true;
            return true;
        });
        var count = byId('actionQueueCount');
        if (count) count.textContent = actions.length + ' pending';
        actions.slice(0, 12).forEach(function (item, index) {
            var row = document.createElement('div');
            row.className = 'action-row';
            appendText(row, 'span', 'action-index', '#' + (index + 1));
            var body = document.createElement('div');
            appendText(body, 'strong', '', item.title || item.action_type || item.name || 'Required action');
            appendText(body, 'small', '', item.rationale || item.reason || item.description || 'Awaiting connector or analyst execution');
            row.appendChild(body);
            appendText(row, 'em', '', item.priority || item.status || 'queued');
            node.appendChild(row);
        });
        if (!actions.length) appendText(node, 'p', 'soc-empty', 'No queued actions.');
    }

    function renderReviewer(progress) {
        var node = byId('reviewerPanel');
        clear(node);
        var reviewer = progress.final_reviewer || {};
        var verdict = byId('reviewerVerdict');
        if (verdict) verdict.textContent = text(reviewer.verdict || progress.completion_status, 'Pending');
        [['Readiness', reviewer.readiness || progress.completion_status], ['Confidence', reviewer.confidence || reviewer.confidence_score], ['Blocking gaps', asArray(progress.open_gaps).length], ['Report shape', Object.keys(progress.final_report_shape || {}).length + ' sections']].forEach(function (pair) {
            appendText(node, 'dt', '', pair[0]);
            appendText(node, 'dd', '', pair[1]);
        });
    }

    function renderEvidence(progress) {
        var node = byId('evidenceBoard');
        clear(node);
        var gaps = asArray(progress.open_gaps);
        var metrics = progress.progress_metrics || {};
        var chips = [
            ['Evidence events', metrics.investigation_evidence_events || metrics.evidence_events || 0],
            ['Hypotheses tested', metrics.investigation_hypotheses_tested || metrics.hypotheses_tested || 0],
            ['Open gaps', gaps.length]
        ];
        chips.forEach(function (pair) {
            var chip = document.createElement('div');
            chip.className = 'evidence-chip-card';
            appendText(chip, 'span', '', pair[0]);
            appendText(chip, 'strong', '', pair[1]);
            node.appendChild(chip);
        });
        gaps.slice(0, 8).forEach(function (gap) { appendText(node, 'p', 'gap-line', gap); });
        var gapCount = byId('gapCount');
        if (gapCount) gapCount.textContent = gaps.length + ' gaps';
    }

    function renderTimeline(progress) {
        var node = byId('progressTimeline');
        clear(node);
        var events = asArray(progress.progress_events).slice().reverse();
        var count = byId('timelineCount');
        if (count) count.textContent = events.length + ' events';
        events.forEach(function (item) {
            var li = document.createElement('li');
            appendText(li, 'time', '', item.timestamp || item.time || 'recent');
            appendText(li, 'strong', '', item.event || item.type || item.phase || 'Progress event');
            appendText(li, 'p', '', item.message || item.detail || item.status || 'State updated');
            node.appendChild(li);
        });
        if (!events.length) appendText(node, 'li', 'soc-empty', 'No progress events persisted yet.');
    }

    function renderConnectors(catalog) {
        var node = byId('connectorStatus');
        clear(node);
        var connectors = asArray(catalog.connectors).concat(asArray(catalog.availability));
        var available = 0;
        connectors.slice(0, 14).forEach(function (item) {
            var ok = Boolean(item.available || item.status === 'available' || item.resolved_tool);
            if (ok) available += 1;
            var row = document.createElement('div');
            row.className = 'connector-row ' + (ok ? 'is-online' : 'is-offline');
            appendText(row, 'span', 'connector-dot', '');
            appendText(row, 'strong', '', item.name || item.action_type || item.tool_name || 'Connector');
            appendText(row, 'small', '', ok ? 'available' : text(item.reason, 'not ready'));
            node.appendChild(row);
        });
        if (!connectors.length) appendText(node, 'p', 'soc-empty', 'Connector catalog unavailable.');
        var summary = byId('connectorSummary');
        if (summary) summary.textContent = available + '/' + connectors.length + ' online';
    }

    function render(progress, connectors) {
        var milestoneScore = renderMilestones(progress);
        renderActions(progress);
        renderReviewer(progress);
        renderEvidence(progress);
        renderTimeline(progress);
        renderConnectors(connectors || {});
        var readiness = progress.progress_metrics && progress.progress_metrics.report_readiness_percent;
        if (readiness === undefined) readiness = milestoneScore;
        var score = Math.max(0, Math.min(100, Number(readiness) || 0));
        byId('reportReadinessScore').textContent = Math.round(score) + '%';
        byId('reportReadinessBar').style.width = score + '%';
        byId('cockpitStatus').textContent = text(progress.completion_status, 'unknown');
        byId('cockpitUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    }

    function initAgenticCockpit() {
        var root = byId('agenticCockpit');
        if (!root) return;
        var sid = root.getAttribute('data-session-id');
        Promise.all([
            loadJson('/api/agent/sessions/' + encodeURIComponent(sid) + '/investigation-progress'),
            loadJson('/api/agent/action-connectors').catch(function () { return loadJson('/api/agent/connectors/availability'); })
        ]).then(function (results) { render(results[0], results[1]); }).catch(function (err) {
            appendText(byId('progressTimeline'), 'li', 'soc-empty', 'Cockpit data unavailable: ' + err.message);
        });
    }

    window.AgenticCockpit = { init: initAgenticCockpit, render: render };
    document.addEventListener('DOMContentLoaded', initAgenticCockpit);
}());
