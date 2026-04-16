"""
Author: Ugur AtesDetection rule generator for multiple SIEM/EDR platforms."""

import hashlib
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class RuleGenerator:
    """
    Generate detection rules for multiple platforms.

    Supports:
    - KQL (Microsoft Defender/Sentinel)
    - SPL (Splunk)
    - SIGMA (Universal)
    - XQL (Cortex XDR)
    - YARA (File signatures)
    """

    @staticmethod
    def _dedupe_non_empty(values: List[str], limit: Optional[int] = None) -> List[str]:
        unique: List[str] = []
        seen = set()
        for value in values:
            text = re.sub(r"\s+", " ", str(value or "")).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            unique.append(text)
            if limit is not None and len(unique) >= limit:
                break
        return unique

    @staticmethod
    def _flatten_values(value) -> List[str]:
        if isinstance(value, dict):
            flattened: List[str] = []
            for item in value.values():
                flattened.extend(RuleGenerator._flatten_values(item))
            return flattened
        if isinstance(value, list):
            flattened: List[str] = []
            for item in value:
                flattened.extend(RuleGenerator._flatten_values(item))
            return flattened
        if value:
            return [str(value)]
        return []

    @staticmethod
    def _safe_rule_id(prefix: str, *parts: str) -> str:
        seed = "|".join(str(part) for part in parts if part)
        digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
        return f"{prefix}-{digest}"

    @staticmethod
    def _sanitize_rule_name(value: str, prefix: str = "CABTA_File") -> str:
        sanitized = re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "")).strip("_")
        if not sanitized:
            sanitized = prefix
        if not sanitized[0].isalpha():
            sanitized = f"{prefix}_{sanitized}"
        return sanitized[:64]

    @staticmethod
    def _escape_double_quoted(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _escape_single_quoted(value: str) -> str:
        return str(value).replace("'", "''")

    @staticmethod
    def _escape_yara_literal(value: str) -> str:
        cleaned = "".join(ch for ch in str(value or "") if ch.isprintable())
        cleaned = cleaned.replace("\\", "\\\\").replace('"', '\\"')
        return cleaned[:96]

    @staticmethod
    def _is_hash_literal(value: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value or ""))

    @staticmethod
    def _file_magic_condition(file_type: str) -> Optional[str]:
        return {
            "pe": "uint16(0) == 0x5A4D",
            "elf": "uint32(0) == 0x464C457F",
            "pdf": "uint32(0) == 0x25504446",
        }.get(str(file_type or "").strip().lower())

    @staticmethod
    def generate_ioc_rules(ioc: str, ioc_type: str, context: Dict = None) -> Dict[str, str]:
        """
        Generate detection rules for IOC.

        Args:
            ioc: Indicator of Compromise
            ioc_type: Type (ipv4, domain, url, hash)
            context: Additional context (malware family, etc.)

        Returns:
            Dict with rules for each platform
        """
        rules = {
            'kql': RuleGenerator._generate_kql_ioc(ioc, ioc_type, context),
            'spl': RuleGenerator._generate_spl_ioc(ioc, ioc_type, context),
            'sigma': RuleGenerator._generate_sigma_ioc(ioc, ioc_type, context),
            'xql': RuleGenerator._generate_xql_ioc(ioc, ioc_type, context)
        }

        return rules

    @staticmethod
    def generate_file_rules(file_data: Dict) -> Dict[str, str]:
        """
        Generate detection rules for malicious file.

        Args:
            file_data: File analysis results

        Returns:
            Dict with rules for each platform
        """
        normalized = RuleGenerator._normalize_file_rule_data(file_data)

        rules = {
            'kql': RuleGenerator._generate_kql_file(normalized),
            'spl': RuleGenerator._generate_spl_file(normalized),
            'yara': RuleGenerator._generate_yara_file(normalized),
            'sigma': RuleGenerator._generate_sigma_file(normalized)
        }

        return rules

    @staticmethod
    def _normalize_file_rule_data(file_data: Dict) -> Dict:
        filename = str(file_data.get("filename") or "unknown.bin")
        file_type = str(file_data.get("file_type") or "").strip().lower()
        sha256 = str(file_data.get("sha256") or "").strip()
        sha1 = str(file_data.get("sha1") or "").strip()
        md5 = str(file_data.get("md5") or "").strip()
        verdict = str(file_data.get("verdict") or "UNKNOWN").upper()

        malware_family = (
            file_data.get("malware_family")
            or next(iter(file_data.get("yara_families", []) or []), "")
            or next(iter(file_data.get("yara_tags", []) or []), "")
            or "Unknown"
        )

        suspicious_literals = []
        suspicious_literals.extend(RuleGenerator._flatten_values(file_data.get("suspicious_strings")))
        suspicious_literals.extend(RuleGenerator._flatten_values(file_data.get("interesting_strings")))
        suspicious_literals.extend(RuleGenerator._flatten_values(file_data.get("suspicious_string_categories")))
        suspicious_literals.extend(RuleGenerator._flatten_values(file_data.get("registry_keys")))
        suspicious_literals.extend(RuleGenerator._flatten_values(file_data.get("mutexes")))

        ioc_literals = []
        ioc_literals.extend(RuleGenerator._flatten_values(file_data.get("iocs")))
        ioc_literals.extend(RuleGenerator._flatten_values(file_data.get("urls")))
        ioc_literals.extend(RuleGenerator._flatten_values(file_data.get("domains")))
        ioc_literals.extend(RuleGenerator._flatten_values(file_data.get("ips")))

        filtered_literals: List[str] = []
        for item in suspicious_literals:
            text = re.sub(r"\s+", " ", item).strip()
            if len(text) < 4 or len(text) > 140 or RuleGenerator._is_hash_literal(text):
                continue
            filtered_literals.append(text)

        filtered_iocs: List[str] = []
        for item in ioc_literals:
            text = re.sub(r"\s+", " ", item).strip()
            if len(text) < 4 or len(text) > 140 or RuleGenerator._is_hash_literal(text):
                continue
            filtered_iocs.append(text)

        filtered_literals = RuleGenerator._dedupe_non_empty(filtered_literals, limit=10)
        filtered_iocs = RuleGenerator._dedupe_non_empty(filtered_iocs, limit=8)

        if not filtered_literals and filename and filename != "unknown.bin":
            filtered_literals = [filename]

        commandline_keywords = (
            "powershell", "cmd.exe", "rundll32", "regsvr32", "wscript", "cscript",
            "mshta", "bitsadmin", "curl ", "wget ", "invoke-webrequest",
            "downloadstring", "downloadfile", "encodedcommand", "-enc", "-nop",
        )
        commandline_literals = [
            item for item in filtered_literals
            if any(keyword in item.lower() for keyword in commandline_keywords)
        ]

        return {
            "filename": filename,
            "file_type": file_type,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "verdict": verdict,
            "malware_family": str(malware_family or "Unknown"),
            "rule_name": RuleGenerator._sanitize_rule_name(
                malware_family if malware_family and malware_family != "Unknown" else filename
            ),
            "rule_id": RuleGenerator._safe_rule_id("cabta-file", sha256, md5, filename, malware_family),
            "suspicious_literals": filtered_literals,
            "ioc_literals": filtered_iocs,
            "commandline_literals": RuleGenerator._dedupe_non_empty(commandline_literals, limit=5),
        }

    @staticmethod
    def _generate_kql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate KQL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""// KQL - Hunt for IP: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "{ioc}" or InitiatingProcessFileName == "{ioc}"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteIP"""

        elif ioc_type == 'domain':
            return f"""// KQL - Hunt for Domain: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteUrl"""

        elif ioc_type == 'hash':
            return f"""// KQL - Hunt for Hash: {ioc}
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{ioc}" or SHA1 == "{ioc}" or MD5 == "{ioc}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| summarize count() by DeviceName, FileName"""

        elif ioc_type == 'url':
            return f"""// KQL - Hunt for URL: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl == "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"""

        return "// KQL - IOC type not supported"

    @staticmethod
    def _generate_spl_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate SPL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""# SPL - Hunt for IP: {ioc}
index=* earliest=-30d
| search dest_ip="{ioc}" OR src_ip="{ioc}"
| stats count by host, dest_ip, src_ip, dest_port"""

        elif ioc_type == 'domain':
            return f"""# SPL - Hunt for Domain: {ioc}
index=* earliest=-30d
| search url="*{ioc}*" OR domain="*{ioc}*"
| stats count by host, url, domain"""

        elif ioc_type == 'hash':
            return f"""# SPL - Hunt for Hash: {ioc}
index=* earliest=-30d
| search hash="{ioc}" OR sha256="{ioc}" OR md5="{ioc}"
| stats count by host, file_name, file_path, hash"""

        return "# SPL - IOC type not supported"

    @staticmethod
    def _generate_sigma_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate complete SIGMA rule for IOC."""
        malware_family = context.get('malware_family', 'Unknown') if context else 'Unknown'
        verdict = context.get('verdict', 'Unknown') if context else 'Unknown'
        level = 'critical' if verdict == 'MALICIOUS' else 'high' if verdict == 'SUSPICIOUS' else 'medium'

        rule = f"""title: Detection of {malware_family} IOC - {ioc}
id: {RuleGenerator._safe_rule_id('cabta-ioc', ioc_type, ioc)}
status: experimental
description: Detects network activity related to {verdict} IOC
author: CABTA
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://github.com/conglambaomat/hihi
tags:
    - attack.command_and_control
    - attack.t1071"""

        if ioc_type == 'ipv4':
            rule += f"""
logsource:
    category: firewall
detection:
    selection_dst:
        dst_ip: '{ioc}'
    selection_src:
        src_ip: '{ioc}'
    condition: selection_dst or selection_src
fields:
    - src_ip
    - dst_ip
    - dst_port
    - action"""

        elif ioc_type == 'domain':
            rule += f"""
logsource:
    category: dns
detection:
    selection:
        query|contains: '{ioc}'
    condition: selection
fields:
    - query
    - answer
    - src_ip"""

        elif ioc_type == 'url':
            rule += f"""
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '{ioc}'
    condition: selection
fields:
    - c-uri
    - cs-host
    - src_ip"""

        elif ioc_type in ['sha256', 'md5', 'sha1', 'hash']:
            rule += f"""
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains: '{ioc}'
    condition: selection
fields:
    - TargetFilename
    - Hashes
    - User"""

        else:
            rule += f"""
logsource:
    category: network_connection
detection:
    selection:
        - dst_ip: '{ioc}'
        - query: '{ioc}'
        - url|contains: '{ioc}'
    condition: selection"""

        rule += f"""
falsepositives:
    - Legitimate traffic to this destination
level: {level}
"""

        return rule

    @staticmethod
    def _generate_xql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate XQL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""// XQL - Hunt for IP: {ioc}
dataset = xdr_data
| filter event_type = NETWORK_CONNECTION and remote_ip = "{ioc}"
| fields agent_hostname, remote_ip, remote_port, process_name
| limit 100"""

        elif ioc_type == 'domain':
            return f"""// XQL - Hunt for Domain: {ioc}
dataset = xdr_data
| filter event_type = DNS_QUERY and dns_query_name contains "{ioc}"
| fields agent_hostname, dns_query_name, process_name
| limit 100"""

        return "// XQL - IOC type not supported"

    @staticmethod
    def _generate_kql_file(file_data: Dict) -> str:
        """Generate KQL rule for file."""
        clauses = []
        if file_data.get('sha256'):
            clauses.append(f'SHA256 == "{RuleGenerator._escape_double_quoted(file_data["sha256"])}"')
        if file_data.get('sha1'):
            clauses.append(f'SHA1 == "{RuleGenerator._escape_double_quoted(file_data["sha1"])}"')
        if file_data.get('md5'):
            clauses.append(f'MD5 == "{RuleGenerator._escape_double_quoted(file_data["md5"])}"')
        if file_data.get('filename'):
            clauses.append(f'FileName =~ "{RuleGenerator._escape_double_quoted(file_data["filename"])}"')

        predicate = " or ".join(clauses) if clauses else "false"
        return f"""// KQL - Hunt for analyzed file
// Primary artifacts: hash and filename
DeviceFileEvents
| where Timestamp > ago(30d)
| where {predicate}
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, FileName, FolderPath, SHA256
| order by Hits desc, LastSeen desc"""

    @staticmethod
    def _generate_spl_file(file_data: Dict) -> str:
        """Generate SPL rule for file."""
        predicates = []
        if file_data.get('sha256'):
            predicates.append(f'sha256="{RuleGenerator._escape_double_quoted(file_data["sha256"])}"')
        if file_data.get('sha1'):
            predicates.append(f'sha1="{RuleGenerator._escape_double_quoted(file_data["sha1"])}"')
        if file_data.get('md5'):
            predicates.append(f'md5="{RuleGenerator._escape_double_quoted(file_data["md5"])}"')
        if file_data.get('filename'):
            predicates.append(f'file_name="{RuleGenerator._escape_double_quoted(file_data["filename"])}"')

        search_clause = " OR ".join(predicates) if predicates else "file_name=*"
        return f"""# SPL - Hunt for analyzed file
index=* earliest=-30d
| search ({search_clause})
| stats count AS hits earliest(_time) AS first_seen latest(_time) AS last_seen by host, file_name, file_path, sha256, sha1, md5
| convert ctime(first_seen) ctime(last_seen)
| sort - hits - last_seen"""

    @staticmethod
    def _generate_yara_file(file_data: Dict) -> str:
        """Generate comprehensive YARA rule for file."""
        filename = file_data.get('filename', 'unknown')
        sha256 = file_data.get('sha256', '')
        md5 = file_data.get('md5', '')
        file_type = file_data.get('file_type', '')
        malware_family = file_data.get('malware_family', 'Unknown')

        string_lines: List[str] = []
        condition_terms: List[str] = []
        strong_refs: List[str] = []
        ioc_refs: List[str] = []
        behavior_refs: List[str] = []

        for i, indicator in enumerate(file_data.get('suspicious_literals', [])[:8]):
            escaped = RuleGenerator._escape_yara_literal(indicator)
            if not escaped:
                continue
            string_lines.append(f'        $str_{i} = "{escaped}" ascii wide nocase')
            strong_refs.append(f"$str_{i}")

        for i, ioc in enumerate(file_data.get('ioc_literals', [])[:6]):
            escaped = RuleGenerator._escape_yara_literal(ioc)
            if not escaped:
                continue
            string_lines.append(f'        $ioc_{i} = "{escaped}" ascii wide nocase')
            ioc_refs.append(f"$ioc_{i}")

        if file_type in {"script", "text"} or file_data.get("commandline_literals"):
            for name, pattern in (
                ("beh_0", r"/powershell(\.exe)?\s+.*(-enc|EncodedCommand|DownloadString|DownloadFile|Invoke-WebRequest)/ nocase"),
                ("beh_1", r"/(wscript|cscript|mshta|rundll32|regsvr32)\.exe/i"),
            ):
                string_lines.append(f"        ${name} = {pattern}")
                behavior_refs.append(f"${name}")

        if strong_refs and ioc_refs:
            condition_terms.append("(1 of ($str_*) and 1 of ($ioc_*))")
        if strong_refs:
            condition_terms.append("2 of ($str_*)" if len(strong_refs) >= 2 else strong_refs[0])
        if ioc_refs:
            condition_terms.append("any of ($ioc_*)")
        if behavior_refs:
            condition_terms.append("1 of ($beh_*)")

        if not string_lines:
            fallback = RuleGenerator._escape_yara_literal(filename)
            string_lines.append(f'        $str_0 = "{fallback}" ascii wide nocase')
            condition_terms = ["$str_0"]

        magic_condition = RuleGenerator._file_magic_condition(file_type)
        joined_condition = " or ".join(condition_terms) if condition_terms else "$str_0"
        final_condition = f"{magic_condition} and ({joined_condition})" if magic_condition else joined_condition

        rule = f"""rule {file_data.get('rule_name') or RuleGenerator._sanitize_rule_name(filename)} {{
    meta:
        description = "Auto-generated rule for {filename}"
        author = "CABTA"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash_sha256 = "{sha256}"
        hash_md5 = "{md5}"
        malware_family = "{malware_family}"
        severity = "high"
        reference = "https://github.com/conglambaomat/hihi"

    strings:
"""
        for line in string_lines:
            rule += line + "\n"

        rule += f"""

    condition:
        {final_condition}
}}
"""
        return rule

    @staticmethod
    def _generate_sigma_file(file_data: Dict) -> str:
        """Generate SIGMA rule for file detection."""
        filename = file_data.get('filename', 'unknown')
        malware_family = file_data.get('malware_family', 'Unknown')
        verdict = file_data.get('verdict', 'UNKNOWN')
        level = 'high' if verdict == 'MALICIOUS' else 'medium' if verdict == 'SUSPICIOUS' else 'low'
        hash_values = [value for value in [file_data.get('sha256'), file_data.get('sha1'), file_data.get('md5')] if value]
        filename_escaped = RuleGenerator._escape_single_quoted(filename)

        rule = f"""title: Detection of {malware_family} - {filename}
id: {file_data.get('rule_id')}
status: experimental
description: Detects presence of an analyzed file based on stable file artifacts extracted by CABTA
author: CABTA
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://github.com/conglambaomat/hihi
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1027

logsource:
    category: file_event
    product: windows

detection:
"""
        if hash_values:
            rule += """    selection_hash:
        Hashes|contains:
"""
            for hash_value in hash_values:
                rule += f"            - '{RuleGenerator._escape_single_quoted(hash_value)}'\n"

        rule += f"""    selection_filename:
        - TargetFilename|endswith: '\\\\{filename_escaped}'
        - OriginalFileName: '{filename_escaped}'

    condition: 1 of selection_*
fields:
    - TargetFilename
    - Hashes
    - Image
    - User
    - ComputerName
falsepositives:
    - Legitimate internal distribution of the same file
    - Security team testing with a known sample

level: {level}
"""
        return rule
    
    @staticmethod
    def generate_email_rules(email_data: Dict) -> Dict[str, str]:
        """
        Generate comprehensive detection rules for phishing email.
        
        Args:
            email_data: Email analysis results
        
        Returns:
            Dict with rules for each platform (KQL, SPL, SIGMA, YARA)
        """
        from datetime import datetime
        
        sender = email_data.get('from', '')
        sender_domain = email_data.get('sender_domain', '')
        if not sender_domain and '@' in sender:
            sender_domain = sender.split('@')[-1].split('>')[0]
        subject = email_data.get('subject', '')[:50]
        urls = email_data.get('urls', [])
        malicious_iocs = email_data.get('malicious_iocs', [])
        
        # KQL Rule
        kql = f"""// KQL - Hunt for Phishing Campaign
// Sender-based detection
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress == "{sender}" 
    or SenderFromDomain == "{sender_domain}"
    or Subject contains "{subject}"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| summarize 
    Recipients = make_set(RecipientEmailAddress),
    Count = count() 
    by SenderFromAddress, Subject

// URL-based detection
let malicious_urls = dynamic([{', '.join([f'"{u[:50]}"' for u in urls[:5]])}]);
EmailUrlInfo
| where Timestamp > ago(30d)
| where Url has_any (malicious_urls)
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Url
"""

        # SIGMA Rule
        sigma = f"""title: Phishing Email Detection - {sender_domain}
id: mcp-soc-email-{hash(sender) % 10000:04d}
status: experimental
description: Detects emails from known phishing sender or containing malicious indicators
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1566.002
logsource:
    category: email
    product: exchange
    service: messagetrace
detection:
    selection_sender:
        sender|endswith: '@{sender_domain}'
    selection_subject:
        subject|contains: '{subject[:30]}'"""

        if urls:
            sigma += """
    selection_url:
        url|contains:"""
            for u in urls[:3]:
                sigma += f"\n            - '{u[:50]}'"
        
        sigma += """
    condition: selection_sender or selection_subject"""
        if urls:
            sigma += " or selection_url"
        
        sigma += """
falsepositives:
    - Legitimate emails from similar domains
level: high
"""

        # SPL Rule
        spl = f"""# SPL - Hunt for Phishing Email
index=email earliest=-30d
| search sender="{sender}" OR sender_domain="{sender_domain}" OR subject="*{subject[:30]}*"
| stats count by recipient, sender, subject, src_ip
| where count > 1

# URL-based hunt
index=email earliest=-30d
| search url IN ("{('", "'.join(urls[:5]))}")
| stats count by recipient, sender, url
"""

        # YARA for attachments (if any IOCs)
        yara = ""
        if malicious_iocs:
            yara = f"""rule Phishing_Email_IOCs {{
    meta:
        description = "IOCs from phishing email analysis"
        author = "Blue Team Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        sender = "{sender}"
    strings:"""
            for i, ioc in enumerate(malicious_iocs[:10]):
                escaped = str(ioc).replace('\\', '\\\\').replace('"', '\\"')[:50]
                yara += f'\n        $ioc{i} = "{escaped}" ascii wide nocase'
            yara += """
    condition:
        any of them
}"""

        # ==================== EMAIL GATEWAY RULES ====================
        
        # FortiMail Content Filter
        fortimail = f"""# FortiMail Content Filter Rule
# Auto-generated by Blue Team Assistant - Block phishing campaign

config antispam profile
    edit "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}"
        config spam-filtering
            set heuristic enable
        end
        config banned-word
            set status enable
            set entries "{subject[:30]}"
        end
    next
end

# Sender Domain Block
config domain
    edit "{sender_domain}"
        set spam on
        set virus on
        set banned-word on
    next
end

# URL Block Rule (if malicious URLs found)
"""
        if urls:
            fortimail += """config webfilter content
    edit "BTA-Blocked-URLs"
        config entries"""
            for url in urls[:10]:
                url_escaped = url[:60].replace('"', '\\"')
                fortimail += f'\n            edit "{url_escaped}"\n            next'
            fortimail += """
        end
    next
end
"""
        
        # Proofpoint Email Protection Rule
        proofpoint = f"""# Proofpoint Email Protection Rule
# Auto-generated by Blue Team Assistant

# Sender Block Rule (JSON format for API)
{{
    "rule_name": "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}",
    "description": "Block phishing campaign from {sender_domain}",
    "enabled": true,
    "conditions": {{
        "from_header": {{
            "contains": ["{sender_domain}"]
        }},
        "subject": {{
            "contains": ["{subject[:30].replace('"', "'")}"]
        }}
    }},
    "actions": {{
        "quarantine": true,
        "add_header": "X-BTA-Blocked: phishing",
        "notify_admin": true,
        "log_action": true
    }}
}}

# URL Rewrite/Block Rule
{{
    "rule_name": "BTA-URL-Block-{hash(sender) % 1000:03d}",
    "description": "Block malicious URLs from phishing campaign",
    "enabled": true,
    "conditions": {{
        "url_in_body": {{
            "matches": [
"""
        for url in urls[:5]:
            url_escaped = url[:70].replace('"', '\\"')
            proofpoint += f'                "{url_escaped}",\n'
        proofpoint += """            ]
        }
    },
    "actions": {
        "rewrite_urls": true,
        "block_url_click": true,
        "quarantine": true,
        "sandbox_attachment": true
    }
}
"""
        
        # Mimecast Policy
        mimecast = f"""# Mimecast Content Examination Policy
# Auto-generated by Blue Team Assistant

Policy Name: BTA-Block-{sender_domain[:15] if sender_domain else 'unknown'}
Policy Type: Content Examination
Status: Enabled
Priority: High

Conditions:
- Header From Contains: {sender_domain}
- Subject Contains: {subject[:30]}
- Attachment Name Pattern: *.exe, *.js, *.vbs, *.ps1, *.hta

Actions:
- Hold Message for Review
- Admin Notification: Enabled
- Add X-Header: X-BTA-Flagged: true
- Send to Sandbox: Enabled

# Blocked Sender Entry
Type: Blocked Sender
Address: *@{sender_domain}
Reason: Phishing campaign detected by Blue Team Assistant
Duration: Permanent

# URL Protection Policy
URL Categories to Block:
"""
        for url in urls[:5]:
            mimecast += f"- {url[:50]}\n"
        
        # Microsoft 365 Defender / Exchange Online Protection
        microsoft365 = f"""# Microsoft 365 Defender / Exchange Online Protection
# PowerShell commands - Run in Exchange Online PowerShell

# 1. Create Transport Rule to block sender domain
New-TransportRule -Name "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}" `
    -FromAddressMatchesPatterns "*@{sender_domain}" `
    -SubjectContainsWords "{subject[:30].replace('"', "'")}" `
    -DeleteMessage $true `
    -SetAuditSeverity "High" `
    -Comments "Auto-generated by Blue Team Assistant - Phishing campaign block"

# 2. Add sender to blocked senders list
Set-HostedContentFilterPolicy -Identity Default `
    -BlockedSenders @{{Add="{sender}"}} `
    -BlockedSenderDomains @{{Add="{sender_domain}"}}

# 3. Create anti-phishing policy
New-AntiPhishPolicy -Name "BTA-AntiPhish-{hash(sender) % 1000:03d}" `
    -Enabled $true `
    -EnableOrganizationDomainsProtection $true `
    -EnableMailboxIntelligence $true `
    -EnableMailboxIntelligenceProtection $true `
    -MailboxIntelligenceProtectionAction Quarantine

# 4. Create Safe Links block for malicious URLs
# Note: Requires Microsoft Defender for Office 365 P1/P2
$urls_to_block = @(
"""
        for url in urls[:10]:
            url_escaped = url[:70].replace('"', '`"')
            microsoft365 += f'    "{url_escaped}",\n'
        microsoft365 += """)
# Add to blocked URLs in Defender portal or via API

# 5. Create mail flow rule for URL blocking
New-TransportRule -Name "BTA-Block-URLs" `
    -HeaderContainsMessageHeader "Content-Type" `
    -HeaderContainsWords "text/html" `
    -SubjectOrBodyContainsWords $urls_to_block `
    -Quarantine $true

# 6. Alert rule for SOC
New-ProtectionAlert -Name "BTA-Phishing-Alert" `
    -Category ThreatManagement `
    -NotifyUser "soc@yourdomain.com" `
    -Operation "ThreatIntelligenceUrl"
"""

        return {
            'kql': kql,
            'sigma': sigma,
            'spl': spl,
            'yara': yara,
            'fortimail': fortimail,
            'proofpoint': proofpoint,
            'mimecast': mimecast,
            'microsoft365': microsoft365
        }
