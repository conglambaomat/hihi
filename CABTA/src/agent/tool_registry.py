"""
Tool Registry - Unified registry for local analysis tools and remote MCP tools.

Each tool is described by a ToolDefinition (JSON-schema parameters, source, category)
and optionally backed by a local async executor function.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolDefinition:
    """Schema for a single tool available to the agent."""

    name: str                           # e.g. "investigate_ioc" or "remnux.analyze_file"
    description: str
    parameters: Dict[str, Any]          # JSON Schema for the params
    source: str                         # "local" or MCP server name
    category: str                       # analysis, threat_intel, sandbox, forensics, edr, re
    requires_approval: bool = False
    is_dangerous: bool = False          # If True, should run in sandbox

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "source": self.source,
            "category": self.category,
            "requires_approval": self.requires_approval,
            "is_dangerous": self.is_dangerous,
        }


class ToolRegistry:
    """Hold local + MCP tools and their executors."""

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, Callable[..., Coroutine]] = {}

    # ------------------------------------------------------------------ #
    #  Registration
    # ------------------------------------------------------------------ #

    def register_local_tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        category: str,
        executor: Callable[..., Coroutine],
        requires_approval: bool = False,
        is_dangerous: bool = False,
    ) -> None:
        """Register a local async tool executor."""
        td = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            source="local",
            category=category,
            requires_approval=requires_approval,
            is_dangerous=is_dangerous,
        )
        self._tools[name] = td
        self._executors[name] = executor
        logger.debug(f"[TOOLS] Registered local tool: {name} ({category})")

    def register_mcp_tools(
        self, server_name: str, tools_list: List[Dict[str, Any]],
    ) -> None:
        """Bulk-register tools discovered from an MCP server's list_tools response."""
        for t in tools_list:
            tool_name = f"{server_name}.{t['name']}"
            td = ToolDefinition(
                name=tool_name,
                description=t.get("description", ""),
                parameters=t.get("inputSchema", t.get("parameters", {})),
                source=server_name,
                category=t.get("category", "mcp"),
                requires_approval=t.get("requires_approval", False),
                is_dangerous=t.get("is_dangerous", False),
            )
            self._tools[tool_name] = td

        logger.info(
            f"[TOOLS] Registered {len(tools_list)} tools from MCP server: {server_name}"
        )

    def unregister_server(self, server_name: str) -> int:
        """Remove every tool that belongs to *server_name*. Returns count removed."""
        to_remove = [
            name for name, td in self._tools.items()
            if td.source == server_name
        ]
        for name in to_remove:
            del self._tools[name]
            self._executors.pop(name, None)
        logger.info(f"[TOOLS] Unregistered {len(to_remove)} tools from {server_name}")
        return len(to_remove)

    # ------------------------------------------------------------------ #
    #  Lookup
    # ------------------------------------------------------------------ #

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(
        self,
        category: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[ToolDefinition]:
        """Return tools filtered by category and/or source."""
        result = list(self._tools.values())
        if category:
            result = [t for t in result if t.category == category]
        if source:
            result = [t for t in result if t.source == source]
        return result

    def get_tools_for_llm(self) -> List[Dict[str, Any]]:
        """Return tool definitions formatted for LLM tool_use / function calling."""
        out: List[Dict[str, Any]] = []
        for td in self._tools.values():
            out.append({
                "type": "function",
                "function": {
                    "name": td.name,
                    "description": td.description + (
                        " [REQUIRES APPROVAL]" if td.requires_approval else ""
                    ),
                    "parameters": td.parameters,
                },
            })
        return out

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    async def execute_local_tool(self, name: str, **kwargs) -> Dict[str, Any]:
        """Execute a registered local tool by name. Returns result dict.

        Performs intelligent parameter mapping: if the executor's required
        parameters are missing from *kwargs*, attempts to infer them from
        the first available value (handles LLM sending ``value`` instead of
        ``ioc``, etc.).
        """
        executor = self._executors.get(name)
        if executor is None:
            return {"error": f"No local executor for tool: {name}"}
        try:
            import inspect
            sig = inspect.signature(executor)
            mapped_kwargs = dict(kwargs)

            logger.info(
                f"[TOOLS] execute_local_tool('{name}') called with kwargs keys: "
                f"{list(kwargs.keys())} values: {kwargs}"
            )

            # ---- Strategy 0: unwrap nested 'params' dict ----
            # Sometimes the LLM stuffs the decision JSON into tool args:
            #   {"params": {"ioc": "..."}, "action": "use_tool", ...}
            if 'params' in mapped_kwargs and isinstance(mapped_kwargs['params'], dict):
                nested = mapped_kwargs['params']
                # Check if 'params' isn't actually a tool parameter
                if 'params' not in sig.parameters or any(
                    k in mapped_kwargs for k in ('action', 'tool', 'reasoning')
                ):
                    logger.info(f"[TOOLS] Unwrapping nested params for {name}: {nested}")
                    # Remove decision-level keys
                    for k in ('action', 'tool', 'reasoning', 'params'):
                        mapped_kwargs.pop(k, None)
                    # Merge the real params
                    mapped_kwargs.update(nested)

            # ---- smart parameter mapping ----
            # Comprehensive alias pool: covers all common names LLMs use
            alias_pool = [
                'value', 'input', 'query', 'target', 'indicator', 'data',
                'ip', 'ip_address', 'address', 'domain', 'url', 'hash',
                'ioc_value', 'host', 'hostname', 'file', 'path', 'text_input',
                'email', 'content', 'findings', 'result',
            ]

            # Collect required params that are missing
            missing_required = []
            for param_name, param in sig.parameters.items():
                if param_name in ('self', '_kw'):
                    continue
                if param.kind == inspect.Parameter.VAR_KEYWORD:
                    continue
                if param_name not in mapped_kwargs and param.default is inspect.Parameter.empty:
                    missing_required.append(param_name)

            for param_name in missing_required:
                # Strategy 1: try alias pool
                found = False
                for alias in alias_pool:
                    if alias in mapped_kwargs:
                        mapped_kwargs[param_name] = mapped_kwargs.pop(alias)
                        logger.info(
                            f"[TOOLS] Mapped '{alias}' -> '{param_name}' for {name}"
                        )
                        found = True
                        break

                if found:
                    continue

                # Strategy 2: if exactly one kwarg remains, use its value
                non_kw = {
                    k: v for k, v in mapped_kwargs.items()
                    if k not in ('_kw',) and k not in [
                        p for p in sig.parameters if p != param_name
                    ]
                }
                if len(non_kw) == 1:
                    only_key = next(iter(non_kw))
                    mapped_kwargs[param_name] = mapped_kwargs.pop(only_key)
                    logger.info(
                        f"[TOOLS] Mapped sole arg '{only_key}' -> '{param_name}' for {name}"
                    )
                    continue

                # Strategy 3: use ANY remaining string value as the param
                # (LLMs sometimes use arbitrary key names)
                for k, v in list(mapped_kwargs.items()):
                    if k.startswith('_'):
                        continue
                    if isinstance(v, str) and v.strip():
                        mapped_kwargs[param_name] = mapped_kwargs.pop(k)
                        logger.info(
                            f"[TOOLS] Mapped arbitrary arg '{k}' -> '{param_name}' for {name}"
                        )
                        found = True
                        break

            # Final check: log what we're calling with
            logger.info(
                f"[TOOLS] Calling {name} with mapped_kwargs: {mapped_kwargs}"
            )

            result = await executor(**mapped_kwargs)
            if not isinstance(result, dict):
                result = {"result": result}
            return result
        except TypeError as exc:
            # Catch the specific "missing required positional argument" error
            # and provide a helpful message
            logger.error(
                f"[TOOLS] Parameter mapping failed for {name}: {exc}. "
                f"Original kwargs: {kwargs}, Tool schema: "
                f"{self._tools.get(name, {})}"
            )
            return {"error": f"Parameter mapping failed for {name}: {exc}. The LLM sent: {kwargs}"}
        except Exception as exc:
            logger.error(f"[TOOLS] Execution failed for {name}: {exc}", exc_info=True)
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    #  Default tool wiring
    # ------------------------------------------------------------------ #

    def register_default_tools(
        self,
        config: Dict,
        ioc_investigator=None,
        malware_analyzer=None,
        email_analyzer=None,
        sandbox_orchestrator=None,
    ) -> None:
        """Wire up the built-in Blue Team Assistant tools as agent-callable tools.

        Each wrapper is an async function that delegates to the existing tool
        instances (IOCInvestigator, MalwareAnalyzer, EmailAnalyzer) so the agent
        can call them via the ReAct loop.
        """

        def _coerce_json_like(value: Any) -> Any:
            if isinstance(value, str):
                text = value.strip()
                if text.startswith("{") and text.endswith("}") or text.startswith("[") and text.endswith("]"):
                    try:
                        import json

                        return json.loads(text)
                    except Exception:
                        return value
            return value

        def _ensure_list(value: Any) -> List[str]:
            value = _coerce_json_like(value)
            if value is None:
                return []
            if isinstance(value, list):
                return [str(item) for item in value if str(item).strip()]
            if isinstance(value, tuple):
                return [str(item) for item in value if str(item).strip()]
            if isinstance(value, set):
                return [str(item) for item in value if str(item).strip()]
            if isinstance(value, dict):
                flattened: List[str] = []
                for nested in value.values():
                    flattened.extend(_ensure_list(nested))
                return flattened
            text = str(value).strip()
            return [text] if text else []

        def _normalize_indicator_map(raw: Any) -> Dict[str, List[str]]:
            raw = _coerce_json_like(raw)
            if not isinstance(raw, dict):
                raw = {}

            return {
                "ips": _ensure_list(raw.get("ips") or raw.get("ipv4") or raw.get("ip_addresses")),
                "domains": _ensure_list(raw.get("domains")),
                "hashes": _ensure_list(raw.get("hashes") or raw.get("sha256") or raw.get("sha1") or raw.get("md5")),
                "urls": _ensure_list(raw.get("urls")),
                "emails": _ensure_list(raw.get("emails")),
                "cves": _ensure_list(raw.get("cve_ids") or raw.get("cves")),
            }

        def _indicator_terms(raw: Any) -> List[str]:
            normalized = _normalize_indicator_map(raw)
            ordered: List[str] = []
            for key in ("ips", "domains", "hashes", "urls", "emails", "cves"):
                for value in normalized[key]:
                    if value not in ordered:
                        ordered.append(value)
            return ordered

        def _truthy_threat(result: Dict[str, Any]) -> bool:
            verdict = str(result.get("verdict", "")).upper()
            if verdict in {"MALICIOUS", "SUSPICIOUS", "PHISHING", "SPAM"}:
                return True
            for key in ("malicious", "found", "blocklisted", "confirmed", "is_tor_exit_node"):
                if result.get(key) is True:
                    return True
            try:
                if float(result.get("threat_score", 0)) >= 60:
                    return True
            except Exception:
                pass
            return False

        def _safe_snort_sid(seed: str) -> int:
            return 1000000 + (abs(hash(seed)) % 899999)

        # -------------------------------------------------------------- #
        # 1. investigate_ioc
        # -------------------------------------------------------------- #
        if ioc_investigator is not None:
            async def _investigate_ioc(ioc: str, **_kw) -> Dict:
                return await ioc_investigator.investigate(ioc)

            self.register_local_tool(
                name="investigate_ioc",
                description=(
                    "Investigate an IOC (IP, domain, URL, or hash) against 20+ threat "
                    "intelligence sources. Returns threat score, verdict, and source details."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "ioc": {
                            "type": "string",
                            "description": "The indicator of compromise to investigate.",
                        },
                    },
                    "required": ["ioc"],
                },
                category="threat_intel",
                executor=_investigate_ioc,
            )

        # -------------------------------------------------------------- #
        # 2. analyze_malware
        # -------------------------------------------------------------- #
        if malware_analyzer is not None:
            async def _analyze_malware(file_path: str, **_kw) -> Dict:
                return await malware_analyzer.analyze(file_path)

            self.register_local_tool(
                name="analyze_malware",
                description=(
                    "Perform static analysis on a file (PE, ELF, PDF, Office, scripts). "
                    "Returns YARA matches, string analysis, imports, entropy, and threat score."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to analyze.",
                        },
                    },
                    "required": ["file_path"],
                },
                category="analysis",
                executor=_analyze_malware,
            )

        # -------------------------------------------------------------- #
        # 3. analyze_email
        # -------------------------------------------------------------- #
        if email_analyzer is not None:
            async def _analyze_email(email_path: str, **_kw) -> Dict:
                return await email_analyzer.analyze(email_path)

            self.register_local_tool(
                name="analyze_email",
                description=(
                    "Analyze an .eml email file for phishing indicators, header anomalies, "
                    "authentication results, IOCs, and attachments."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "email_path": {
                            "type": "string",
                            "description": "Absolute path to the .eml file.",
                        },
                    },
                    "required": ["email_path"],
                },
                category="analysis",
                executor=_analyze_email,
            )

        # -------------------------------------------------------------- #
        # 4. extract_iocs
        # -------------------------------------------------------------- #
        async def _extract_iocs(text: str, **_kw) -> Dict:
            import re
            from ..utils.ioc_extractor import IOCExtractor
            iocs = IOCExtractor.extract_all(text)
            ipv4 = list(iocs.get("ipv4", []))
            ipv6 = list(iocs.get("ipv6", [])) if isinstance(iocs.get("ipv6"), list) else []
            domains = list(iocs.get("domains", []))
            urls = list(iocs.get("urls", []))
            emails = list(iocs.get("emails", []))
            hashes_map = iocs.get("hashes", {}) if isinstance(iocs.get("hashes"), dict) else {}
            md5 = list(hashes_map.get("md5", []))
            sha1 = list(hashes_map.get("sha1", []))
            sha256 = list(hashes_map.get("sha256", []))
            cve_ids = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))
            windows_paths = re.findall(r"\b[A-Za-z]:\\[^\s\"'<>|]+", text)
            linux_paths = re.findall(r"(?<!\w)(/[^\s\"'<>|]+)", text)
            file_paths = list(dict.fromkeys(windows_paths + linux_paths))
            executables = [
                path for path in file_paths
                if str(path).lower().endswith(
                    (".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".pf")
                )
            ]
            sender_domains = sorted({email.split("@", 1)[1].lower() for email in emails if "@" in email})
            all_iocs = []
            for bucket in (ipv4, ipv6, domains, urls, emails, md5, sha1, sha256, cve_ids, file_paths):
                all_iocs.extend(bucket)
            return {
                "ips": list(dict.fromkeys(ipv4 + ipv6)),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "domains": domains,
                "urls": urls,
                "emails": emails,
                "sender_domains": sender_domains,
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "hashes": list(dict.fromkeys(md5 + sha1 + sha256)),
                "hashes_by_type": hashes_map,
                "cve_ids": cve_ids,
                "vulnerability_refs": cve_ids,
                "file_paths": file_paths,
                "executables": executables,
                "all_iocs": list(dict.fromkeys(all_iocs)),
                "total_iocs": len(set(all_iocs)),
                "iocs": iocs,
            }

        self.register_local_tool(
            name="extract_iocs",
            description=(
                "Extract IOCs (IPs, domains, URLs, hashes, emails) from arbitrary text."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to extract IOCs from.",
                    },
                },
                "required": ["text"],
            },
            category="analysis",
            executor=_extract_iocs,
        )

        # -------------------------------------------------------------- #
        # 5. generate_rules
        # -------------------------------------------------------------- #
        async def _generate_rules(
            analysis_result: Dict = None,
            rule_type: str = 'all',
            rule_types: List[str] = None,
            **_kw,
        ) -> Dict:
            from ..detection.rule_generator import RuleGenerator

            def _build_generic_hunt_queries(
                hypothesis: str,
                selected_types: List[str],
                mitre_techniques: Any,
            ) -> Dict[str, List[str]]:
                hypothesis = (hypothesis or "Threat hunting hypothesis").strip()
                techniques = []
                if isinstance(mitre_techniques, list):
                    techniques = [str(item) for item in mitre_techniques if str(item).strip()]
                elif mitre_techniques:
                    techniques = [str(mitre_techniques)]
                technique_hint = ", ".join(techniques[:5]) if techniques else "unknown TTPs"

                generic_queries: Dict[str, List[str]] = {}
                if "kql" in selected_types:
                    generic_queries["kql"] = [
                        "\n".join(
                            [
                                f"// Hypothesis hunt: {hypothesis}",
                                f"// Related ATT&CK techniques: {technique_hint}",
                                "union isfuzzy=true DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents",
                                "| where Timestamp > ago(7d)",
                                "| where tostring(AdditionalFields) contains \"suspicious\"",
                                "| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, FolderPath, RemoteIP, RemoteUrl",
                                "| take 100",
                            ]
                        )
                    ]
                if "spl" in selected_types:
                    generic_queries["spl"] = [
                        "\n".join(
                            [
                                f"# Hypothesis hunt: {hypothesis}",
                                f"# Related ATT&CK techniques: {technique_hint}",
                                "index=* earliest=-7d",
                                "| search suspicious OR malware OR beacon OR phishing",
                                "| stats count by host, sourcetype, user, process_name, dest_ip, url",
                                "| sort - count",
                            ]
                        )
                    ]
                if "sigma" in selected_types:
                    generic_queries["sigma"] = [
                        "\n".join(
                            [
                                "title: Hypothesis Driven Hunt",
                                "status: experimental",
                                f"description: Generated from threat hunting hypothesis: {hypothesis[:120]}",
                                "logsource:",
                                "    category: process_creation",
                                "detection:",
                                "    selection:",
                                "        CommandLine|contains:",
                                "            - 'powershell'",
                                "            - 'cmd.exe'",
                                "            - 'rundll32'",
                                "    condition: selection",
                                "level: medium",
                            ]
                        )
                    ]
                if "yara" in selected_types:
                    generic_queries["yara"] = [
                        "\n".join(
                            [
                                "rule AISA_Hypothesis_Hunt",
                                "{",
                                "    meta:",
                                f"        description = \"Generated from hypothesis: {hypothesis[:80]}\"",
                                "        author = \"AISA\"",
                                "    strings:",
                                "        $ps1 = \"powershell\" ascii wide nocase",
                                "        $ps2 = \"cmd.exe\" ascii wide nocase",
                                "        $ps3 = \"rundll32\" ascii wide nocase",
                                "    condition:",
                                "        any of them",
                                "}",
                            ]
                        )
                    ]
                if "snort" in selected_types:
                    generic_queries["snort"] = [
                        "\n".join(
                            [
                                (
                                    'alert tcp any any -> any any '
                                    f'(msg:"AISA Hypothesis Hunt - {hypothesis[:40]}"; flow:established,to_server; sid:{_safe_snort_sid(hypothesis)}; rev:1;)'
                                )
                            ]
                        )
                    ]
                return generic_queries

            analysis_result = analysis_result or {}
            if _kw.get("iocs") and not analysis_result.get("known_iocs"):
                analysis_result = {
                    **analysis_result,
                    "known_iocs": _kw.get("iocs"),
                }
            selected_types = list(rule_types or [])
            if rule_type and rule_type != "all":
                selected_types.append(rule_type)
            if not selected_types or "all" in selected_types:
                selected_types = ["kql", "sigma", "spl", "yara", "snort"]
            selected_types = [
                value for value in dict.fromkeys(selected_types)
                if value in {"kql", "sigma", "spl", "yara", "snort"}
            ]

            hypothesis = str(
                analysis_result.get("hypothesis")
                or analysis_result.get("query")
                or analysis_result.get("summary")
                or ""
            ).strip()
            known_iocs = _normalize_indicator_map(
                analysis_result.get("known_iocs") or analysis_result.get("indicators")
            )
            context = {
                "malware_family": analysis_result.get("malware_family", "Unknown"),
                "verdict": analysis_result.get("verdict", "SUSPICIOUS"),
            }

            query_buckets: Dict[str, List[str]] = {
                key: [] for key in selected_types
            }

            for ip in known_iocs["ips"]:
                generated = RuleGenerator.generate_ioc_rules(ip, "ipv4", context)
                for query_type in selected_types:
                    if generated.get(query_type):
                        query_buckets[query_type].append(generated[query_type])

            for domain in known_iocs["domains"]:
                generated = RuleGenerator.generate_ioc_rules(domain, "domain", context)
                for query_type in selected_types:
                    if generated.get(query_type):
                        query_buckets[query_type].append(generated[query_type])

            for hash_value in known_iocs["hashes"]:
                generated = RuleGenerator.generate_ioc_rules(hash_value, "hash", context)
                for query_type in selected_types:
                    if generated.get(query_type):
                        query_buckets[query_type].append(generated[query_type])

            for url in known_iocs["urls"]:
                generated = RuleGenerator.generate_ioc_rules(url, "url", context)
                for query_type in selected_types:
                    if generated.get(query_type):
                        query_buckets[query_type].append(generated[query_type])

            if "snort" in selected_types:
                for ip in known_iocs["ips"]:
                    query_buckets.setdefault("snort", []).append(
                        f'alert ip any any <> {ip} any (msg:"AISA IOC IP {ip}"; sid:{_safe_snort_sid(ip)}; rev:1;)'
                    )
                for domain in known_iocs["domains"]:
                    query_buckets.setdefault("snort", []).append(
                        f'alert udp any any -> any 53 (msg:"AISA IOC Domain {domain}"; content:"{domain}"; nocase; sid:{_safe_snort_sid(domain)}; rev:1;)'
                    )
                for url in known_iocs["urls"]:
                    query_buckets.setdefault("snort", []).append(
                        f'alert http any any -> any any (msg:"AISA IOC URL {url[:40]}"; http_uri; content:"{url[:200]}"; nocase; sid:{_safe_snort_sid(url)}; rev:1;)'
                    )

            if not any(query_buckets.values()):
                generic = _build_generic_hunt_queries(
                    hypothesis=hypothesis,
                    selected_types=selected_types,
                    mitre_techniques=analysis_result.get("mitre_techniques"),
                )
                for query_type, values in generic.items():
                    query_buckets.setdefault(query_type, []).extend(values)

            normalized_queries = {
                query_type: values
                for query_type, values in query_buckets.items()
                if values
            }
            flat_preview = {
                query_type: "\n\n".join(values[:3])
                for query_type, values in normalized_queries.items()
            }

            return {
                "status": "generated",
                "query_count": sum(len(values) for values in normalized_queries.values()),
                "query_languages": list(normalized_queries.keys()),
                "queries": normalized_queries,
                "hypothesis": hypothesis,
                "known_iocs": known_iocs,
                "kql": flat_preview.get("kql", ""),
                "spl": flat_preview.get("spl", ""),
                "sigma": flat_preview.get("sigma", ""),
                "yara": flat_preview.get("yara", ""),
                "snort": flat_preview.get("snort", ""),
            }

        self.register_local_tool(
            name="generate_rules",
            description=(
                "Generate detection rules and hunt queries (KQL, Sigma, YARA, SPL, Snort) from analysis results."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "analysis_result": {
                        "type": "object",
                        "description": "Analysis result dict to generate rules from.",
                    },
                    "rule_type": {
                        "type": "string",
                        "enum": ["kql", "sigma", "yara", "spl", "snort", "all"],
                        "description": "Type of rule to generate. Default 'all'.",
                    },
                    "rule_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["kql", "sigma", "yara", "spl", "snort"],
                        },
                        "description": "Optional list of rule/query languages to generate.",
                    },
                },
                "required": [],
            },
            category="detection",
            executor=_generate_rules,
        )

        # -------------------------------------------------------------- #
        # 5b. search_logs
        # -------------------------------------------------------------- #
        async def _search_logs(query: Any = None, timerange: str = "", **_kw) -> Dict:
            """Return generated hunt queries and an honest status when no log backend is wired."""

            def _normalize_queries(raw: Any) -> Dict[str, List[str]]:
                if raw is None:
                    return {}
                if isinstance(raw, dict):
                    normalized: Dict[str, List[str]] = {}
                    for key, value in raw.items():
                        if isinstance(value, list):
                            items = [str(item) for item in value if str(item).strip()]
                        elif value in (None, ""):
                            items = []
                        else:
                            items = [str(value)]
                        if items:
                            normalized[str(key)] = items
                    return normalized
                if isinstance(raw, list):
                    items = [str(item) for item in raw if str(item).strip()]
                    return {"generic": items} if items else {}
                if isinstance(raw, str):
                    text = raw.strip()
                    if not text:
                        return {}
                    if text.startswith("{") and text.endswith("}"):
                        try:
                            import json

                            parsed = json.loads(text)
                            if isinstance(parsed, dict):
                                return _normalize_queries(parsed)
                        except Exception:
                            pass
                    return {"generic": [text]}
                return {"generic": [str(raw)]}

            normalized_queries = _normalize_queries(query)
            query_count = sum(len(values) for values in normalized_queries.values())
            configured_backends = []
            status = "manual_lookup_required"
            mode = "query_generation_only"
            message = (
                "No SIEM/log backend is configured for automated log search. "
                "AISA generated hunt queries for analyst-driven execution."
            )

            return {
                "status": status,
                "mode": mode,
                "timerange": timerange or "7d",
                "configured_backends": configured_backends,
                "query_count": query_count,
                "executed_queries": [],
                "queries": normalized_queries,
                "results_count": 0,
                "suspicious_indicators": [],
                "suspicious_files": [],
                "suspicious_executables": [],
                "message": message,
            }

        self.register_local_tool(
            name="search_logs",
            description=(
                "Execute or stage hunt queries against a configured log backend. "
                "If no SIEM/log backend is wired, returns generated queries with a "
                "manual/degraded status instead of failing."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "description": "Generated hunt queries grouped by language/backend.",
                    },
                    "timerange": {
                        "type": "string",
                        "description": "Search timerange such as 24h, 7d, or 30d.",
                    },
                },
                "required": [],
            },
            category="analysis",
            executor=_search_logs,
        )

        # -------------------------------------------------------------- #
        # 6. yara_scan
        # -------------------------------------------------------------- #
        async def _yara_scan(file_path: str, **_kw) -> Dict:
            from ..utils.yara_scanner import YaraScanner
            scanner = YaraScanner()
            matches = scanner.scan(file_path)
            return {"matches": matches}

        self.register_local_tool(
            name="yara_scan",
            description="Scan a file against built-in YARA rules for malware signatures.",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to scan.",
                    },
                },
                "required": ["file_path"],
            },
            category="analysis",
            executor=_yara_scan,
        )

        # -------------------------------------------------------------- #
        # 7. search_threat_intel
        # -------------------------------------------------------------- #
        if ioc_investigator is not None:
            async def _search_threat_intel(
                query: str = "",
                source: str = 'all',
                hypothesis: str = "",
                indicators: Any = None,
                **_kw,
            ) -> Dict:
                """Search threat intel for a query string or a playbook hypothesis bundle."""
                search_terms: List[str] = []
                if query and str(query).strip():
                    search_terms.append(str(query).strip())
                if hypothesis and str(hypothesis).strip() and str(hypothesis).strip() not in search_terms:
                    search_terms.append(str(hypothesis).strip())
                for value in _indicator_terms(indicators):
                    if value not in search_terms:
                        search_terms.append(value)

                if not search_terms:
                    return {"error": "No query or indicators supplied"}

                results = []
                for term in search_terms[:10]:
                    result = await ioc_investigator.investigate(term)
                    results.append({"query": term, "result": result})

                flagged_results = sum(
                    1 for item in results
                    if isinstance(item.get("result"), dict) and _truthy_threat(item["result"])
                )

                if len(results) == 1 and not hypothesis and not indicators and query:
                    single = dict(results[0]["result"])
                    single.update(
                        {
                            "searched_terms": search_terms,
                            "results_count": 1,
                            "results": results,
                            "flagged_results": flagged_results,
                        }
                    )
                    return single

                return {
                    "query": query or hypothesis,
                    "searched_terms": search_terms,
                    "results_count": len(results),
                    "flagged_results": flagged_results,
                    "results": results,
                    "indicators": _normalize_indicator_map(indicators),
                    "source": source,
                }

            self.register_local_tool(
                name="search_threat_intel",
                description=(
                    "Search threat intelligence sources for any indicator or keyword. "
                    "Accepts IPs, domains, URLs, hashes, or keywords."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Indicator or keyword to search.",
                        },
                        "hypothesis": {
                            "type": "string",
                            "description": "Optional threat-hunting hypothesis to search by keyword.",
                        },
                        "indicators": {
                            "description": "Optional structured IOC bundle used by playbooks.",
                        },
                        "source": {
                            "type": "string",
                            "description": "Specific source to query, or 'all'.",
                            "default": "all",
                        },
                    },
                    "required": [],
                },
                category="threat_intel",
                executor=_search_threat_intel,
            )

        # -------------------------------------------------------------- #
        # 8. sandbox_submit - Submit file to sandboxed analysis
        # -------------------------------------------------------------- #
        async def _sandbox_submit(file_path: str, **_kw) -> Dict:
            """Submit a file for sandbox analysis (Docker/VM/Cloud - NEVER host)."""
            try:
                orch = sandbox_orchestrator
                if orch is None:
                    from ..agent.sandbox_orchestrator import SandboxOrchestrator
                    orch = SandboxOrchestrator(config)
                sandbox_info = orch.select_sandbox(file_path)
                if "error" in sandbox_info:
                    return sandbox_info
                result = await orch.submit_to_sandbox(
                    file_path,
                    sandbox_info.get("sandbox_type"),
                )
                return result
            except Exception as e:
                return {"error": f"Sandbox submission failed: {e}"}

        self.register_local_tool(
            name="sandbox_submit",
            description=(
                "Submit a file for dynamic analysis in an isolated sandbox (Docker/VM/Cloud). "
                "NEVER executes on host. Returns analysis results from the sandbox."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to submit.",
                    },
                },
                "required": ["file_path"],
            },
            category="sandbox",
            executor=_sandbox_submit,
            is_dangerous=True,
            requires_approval=True,
        )

        # -------------------------------------------------------------- #
        # 9. correlate_findings - Cross-correlate analysis findings
        # -------------------------------------------------------------- #
        async def _correlate_findings(findings_text: str = "", **_kw) -> Dict:
            """Correlate findings to identify related IOCs and MITRE ATT&CK TTPs."""
            try:
                from ..agent.correlation import CorrelationEngine
                engine = CorrelationEngine()
                findings = []
                if findings_text:
                    findings.append({"tool": "findings_text", "text": findings_text})
                for key, value in _kw.items():
                    if value in (None, "", [], {}):
                        continue
                    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                        findings.extend(value)
                    else:
                        findings.append({"tool": key, "result": value})
                if not findings:
                    return {"error": "No findings provided for correlation"}
                result = engine.correlate(findings)
                return result
            except Exception as e:
                return {"error": f"Correlation failed: {e}"}

        self.register_local_tool(
            name="correlate_findings",
            description=(
                "Cross-correlate analysis findings to identify related IOCs, "
                "MITRE ATT&CK TTP patterns, and severity assessments."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "findings_text": {
                        "type": "string",
                        "description": "Text containing analysis findings to correlate.",
                    },
                },
                "required": ["findings_text"],
            },
            category="analysis",
            executor=_correlate_findings,
        )

        # -------------------------------------------------------------- #
        # 10. remediation helpers
        # -------------------------------------------------------------- #
        async def _isolate_device(target: Any, isolation_type: str = "network", **_kw) -> Dict:
            targets = _ensure_list(target)
            return {
                "status": "staged_remediation",
                "action": "isolate_device",
                "applied": False,
                "requires_backend": True,
                "isolation_type": isolation_type,
                "targets": targets,
                "target_count": len(targets),
                "message": (
                    "Isolation request was staged for analyst-controlled execution. "
                    "No endpoint was modified automatically."
                ),
            }

        self.register_local_tool(
            name="isolate_device",
            description=(
                "Stage a device isolation request for analyst-approved containment workflows."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "description": "Host, IP, or structured target bundle to isolate.",
                    },
                    "isolation_type": {
                        "type": "string",
                        "description": "Type of containment to apply, such as network.",
                        "default": "network",
                    },
                },
                "required": ["target"],
            },
            category="response",
            executor=_isolate_device,
            requires_approval=True,
            is_dangerous=True,
        )

        async def _block_ip(indicators: Any = None, **_kw) -> Dict:
            values = _ensure_list(indicators)
            return {
                "status": "staged_remediation",
                "action": "block_indicator",
                "applied": False,
                "requires_backend": True,
                "indicators": values,
                "indicator_count": len(values),
                "message": (
                    "Indicator block request was staged for firewall/proxy/EDR execution. "
                    "No perimeter control was changed automatically."
                ),
            }

        self.register_local_tool(
            name="block_ip",
            description=(
                "Stage indicator blocking actions for analyst-approved firewall, proxy, or EDR workflows."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "indicators": {
                        "description": "IP/domain/hash indicators to block or contain.",
                    },
                },
                "required": ["indicators"],
            },
            category="response",
            executor=_block_ip,
            requires_approval=True,
            is_dangerous=True,
        )

        async def _quarantine_file(targets: Any = None, **_kw) -> Dict:
            values = _ensure_list(targets)
            return {
                "status": "staged_remediation",
                "action": "quarantine_file",
                "applied": False,
                "requires_backend": True,
                "targets": values,
                "target_count": len(values),
                "message": (
                    "Quarantine request was staged for analyst-controlled execution. "
                    "No file was moved or deleted automatically."
                ),
            }

        self.register_local_tool(
            name="quarantine_file",
            description=(
                "Stage suspicious files or artifacts for analyst-approved quarantine workflows."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "targets": {
                        "description": "File paths or artifact references to quarantine.",
                    },
                },
                "required": ["targets"],
            },
            category="response",
            executor=_quarantine_file,
            requires_approval=True,
            is_dangerous=True,
        )

        # -------------------------------------------------------------- #
        # 11. recall_ioc - Check investigation memory for past results
        # -------------------------------------------------------------- #
        async def _recall_ioc(ioc: str = "", text: str = "", hypothesis: str = "", known_indicators: Any = None, **_kw) -> Dict:
            """Recall previously investigated IOC results from memory."""
            try:
                from ..agent.memory import InvestigationMemory
                from ..utils.ioc_extractor import IOCExtractor

                mem = InvestigationMemory()
                requested: List[str] = []
                if ioc and str(ioc).strip():
                    requested.append(str(ioc).strip())

                blob = " ".join(part for part in [text, hypothesis] if isinstance(part, str) and part.strip()).strip()
                if blob:
                    extracted = IOCExtractor.extract_all(blob)
                    for bucket in ("urls", "domains", "emails", "ipv4", "ipv6"):
                        for value in extracted.get(bucket, []):
                            if value not in requested:
                                requested.append(value)
                    hashes_map = extracted.get("hashes", {}) if isinstance(extracted.get("hashes"), dict) else {}
                    for bucket in ("md5", "sha1", "sha256"):
                        for value in hashes_map.get(bucket, []):
                            if value not in requested:
                                requested.append(value)

                for value in _indicator_terms(known_indicators):
                    if value not in requested:
                        requested.append(value)

                if not requested:
                    return {"cached": False, "message": "No IOC or structured indicators supplied"}

                hits = []
                for candidate in requested[:25]:
                    cached = mem.recall_ioc(candidate)
                    if cached:
                        hits.append({"ioc": candidate, "result": cached})

                if len(requested) == 1 and ioc and not text and not hypothesis and known_indicators in (None, "", {}, []):
                    if hits:
                        return {"cached": True, "result": hits[0]["result"], "ioc": hits[0]["ioc"]}
                    return {"cached": False, "message": f"No prior investigation found for {requested[0]}", "ioc": requested[0]}

                return {
                    "cached": bool(hits),
                    "cached_count": len(hits),
                    "requested_iocs": requested,
                    "matched_iocs": [item["ioc"] for item in hits],
                    "results": hits,
                    "result": hits[0]["result"] if len(hits) == 1 else None,
                }
            except Exception as e:
                return {"error": f"Memory recall failed: {e}"}

        self.register_local_tool(
            name="recall_ioc",
            description=(
                "Check investigation memory for previously analyzed IOC results. "
                "Avoids redundant lookups by returning cached verdicts."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "IOC to recall from memory.",
                    },
                    "text": {
                        "type": "string",
                        "description": "Optional free-text blob to extract IOCs from before recall.",
                    },
                    "hypothesis": {
                        "type": "string",
                        "description": "Optional threat hunting hypothesis used to recall prior IOCs.",
                    },
                    "known_indicators": {
                        "description": "Optional structured IOC bundle used by playbooks.",
                    },
                },
                "required": [],
            },
            category="analysis",
            executor=_recall_ioc,
        )

        logger.info(
            f"[TOOLS] Registered {len(self._tools)} default tools"
        )
