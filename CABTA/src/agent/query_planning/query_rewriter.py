"""Bounded query fallback generation for missing coverage facets."""

from __future__ import annotations

from typing import Any, Dict, List

from ..log_query_coverage import build_query_fingerprint


class QueryRewriter:
    """Create safe fallback query variants; execution remains policy-gated elsewhere."""

    def fallback_variants(self, *, focus: str, missing_facets: List[str], max_results: int = 200) -> List[Dict[str, Any]]:
        safe_focus = str(focus or "").replace('"', '\\"')
        variants: List[Dict[str, Any]] = []
        templates = {
            "session": 'search index=* (session_id=* OR logon_id=* OR Logon_ID=*) "{focus}" | head {max_results}',
            "process": 'search index=* (process_name=* OR image=* OR command_line=* OR cmdline=*) "{focus}" | head {max_results}',
            "host": 'search index=* (host=* OR hostname=* OR ComputerName=* OR device=*) "{focus}" | head {max_results}',
            "network": 'search index=* (dest_ip=* OR src_ip=* OR domain=* OR url=*) "{focus}" | head {max_results}',
            "source_ip": 'search index=* (src_ip=* OR source_ip=* OR client_ip=* OR ip_address=*) "{focus}" | head {max_results}',
            "timeline": 'search index=* "{focus}" | sort 0 _time | head {max_results}',
        }
        for facet in missing_facets[:4]:
            query = templates.get(facet, 'search index=* "{focus}" | head {max_results}').format(focus=safe_focus or "*", max_results=max_results)
            variants.append({
                "variant_id": f"fallback_{facet}",
                "backend": "splunk",
                "strategy": "coverage_gap_fallback",
                "target_facets": [facet],
                "query": query,
                "fingerprint": build_query_fingerprint(query),
                "reason": f"Bounded fallback for missing coverage facet: {facet}.",
            })
        return variants
