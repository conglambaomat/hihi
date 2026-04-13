# CABTA Usage Guide

Practical CLI and MCP usage examples for CABTA.

## Table of Contents
- [IOC Investigation](#ioc-investigation)
- [Malware Analysis](#malware-analysis)
- [Email Analysis](#email-analysis)
- [Report Generation](#report-generation)
- [MCP Server Mode](#mcp-server-mode)
- [Batch Processing](#batch-processing)

---

## IOC Investigation

### Basic Usage

```bash
# Investigate an IP address
python -m src.soc_agent ioc 192.168.1.100

# Investigate a domain
python -m src.soc_agent ioc evil-domain.com

# Investigate a URL
python -m src.soc_agent ioc "https://malicious-site.com/payload.exe"

# Investigate a file hash
python -m src.soc_agent ioc d41d8cd98f00b204e9800998ecf8427e
```

### With HTML Report

```bash
python -m src.soc_agent ioc 185.199.108.153 --report ip_investigation.html
```

### Understanding Results

```
═══════════════════════════════════════════════════════════════════════════════
                    BLUE TEAM ASSISTANT - IOC INVESTIGATION
═══════════════════════════════════════════════════════════════════════════════

 IOC: 185.199.108.153
 Type: IPv4                          ← Automatically detected type
 Verdict: SUSPICIOUS (Score: 45/100) ← Overall verdict with score

┌─ THREAT INTELLIGENCE RESULTS       ← Individual source results
│
│  VirusTotal      : 3/94 detections ← X engines flagged / total checked
│  AbuseIPDB       : Confidence 25%  ← Abuse confidence percentage
│  Shodan          : Open ports: 80, 443
│  GreyNoise       : Not seen scanning
│  AlienVault OTX  : 2 pulses        ← Number of threat intel reports
│
│  Sources Checked: 12               ← Total APIs queried
│  Sources Flagged: 3                ← APIs that flagged this IOC
└─────────────────────────────────────────────────────────────────────────────

┌─ DETECTION RULES                    ← Auto-generated rules
│
│  KQL Query:
│  DeviceNetworkEvents
│  | where RemoteIP == "185.199.108.153"
│  | project Timestamp, DeviceName, InitiatingProcessFileName
│
│  SIGMA Rule: [Copy button available in HTML report]
└─────────────────────────────────────────────────────────────────────────────

┌─ RECOMMENDATIONS                    ← Actionable next steps
│
│  • Monitor network traffic to this IP
│  • Check historical connections in SIEM
│  • Consider adding to watchlist
└─────────────────────────────────────────────────────────────────────────────
```

### Verdict Interpretation

| Score | Verdict | Action |
|-------|---------|--------|
| 0-25 | CLEAN | No action required |
| 26-50 | SUSPICIOUS | Monitor and investigate further |
| 51-75 | LIKELY MALICIOUS | Block and investigate |
| 76-100 | MALICIOUS | Immediate block and incident response |

---

## Malware Analysis

### Basic Usage

```bash
# Analyze a Windows executable
python -m src.soc_agent file suspicious.exe

# Analyze a DLL
python -m src.soc_agent file malware.dll

# Analyze an Office document
python -m src.soc_agent file macro_doc.docm

# Analyze a PDF
python -m src.soc_agent file evil.pdf

# Analyze a script
python -m src.soc_agent file payload.ps1
```

### With HTML Report

```bash
python -m src.soc_agent file suspicious.exe --report analysis_report.html
```

### Understanding Results

```
═══════════════════════════════════════════════════════════════════════════════
                    BLUE TEAM ASSISTANT - MALWARE ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

 SECTION 1: FILE OVERVIEW
┌─────────────────────────────────────────────────────────────────────────────
│  File Name       : suspicious.exe
│  File Size       : 1.85 MB
│  File Type       : PE32 executable (GUI) Intel 80386
│  
│  Hashes:
│  ├── MD5         : d41d8cd98f00b204e9800998ecf8427e
│  ├── SHA1        : da39a3ee5e6b4b0d3255bfef95601890afd80709
│  └── SHA256      : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
│
│  Verdict         : 🔴 MALICIOUS (Score: 87/100)
│  First Seen      : 2024-01-15 (VirusTotal)
└─────────────────────────────────────────────────────────────────────────────

 SECTION 2: THREAT INTELLIGENCE
┌─────────────────────────────────────────────────────────────────────────────
│  VirusTotal      : 45/72 detections
│  │ └── Top detections: Trojan.GenericKD, Malware.Emotet, Win32.Packed
│  
│  Hybrid Analysis : Threat Score 100/100
│  │ └── Family: Emotet | Verdict: malicious
│  
│  MalwareBazaar   : Found
│  │ └── Tags: Emotet, Trojan, Loader
│  
│  Triage          : Found
│  │ └── Sandbox score: 10/10
│  
│  Sources Checked : 8
│  Sources Flagged : 6
└─────────────────────────────────────────────────────────────────────────────

 SECTION 3: STATIC ANALYSIS
┌─────────────────────────────────────────────────────────────────────────────
│  PE Header
│  ├── Architecture    : x86 (32-bit)
│  ├── Compile Time    : 2024-01-10 08:23:45
│  ├── Entry Point     : 0x00012340
│  ├── Subsystem       : Windows GUI
│  └── Security        : ASLR: ✅ | DEP: ✅ | CFG: ❌
│
│  Entropy Analysis
│  ├── Overall         : 7.89/8.00
│  ├── Interpretation  : 🔴 Packed/Encrypted
│  └── Sections:
│      ├── .text       : 6.21 (normal)
│      ├── .data       : 4.85 (normal)
│      ├── .rsrc       : 7.95 (HIGH - encrypted)
│      └── .reloc      : 7.88 (HIGH - packed)
│
│  Suspicious Imports (12 found)
│  ├── VirtualAllocEx     → Process Injection
│  ├── WriteProcessMemory → Process Injection  
│  ├── CreateRemoteThread → Process Injection
│  ├── NtUnmapViewOfSection → Process Hollowing
│  ├── InternetOpenUrlA   → Network Activity
│  └── ... 7 more
│
│  Suspicious Strings (8 found)
│  ├── "cmd.exe /c"        → Command execution
│  ├── "powershell -enc"   → Encoded PowerShell
│  ├── "HKEY_CURRENT_USER" → Registry access
│  └── ... 5 more
└─────────────────────────────────────────────────────────────────────────────

 SECTION 4: MITRE ATT&CK MAPPING
┌─────────────────────────────────────────────────────────────────────────────
│  🔴 T1055 : Process Injection
│     └─ Tactic: Defense Evasion, Privilege Escalation
│
│  🔴 T1059.001 : PowerShell
│     └─ Tactic: Execution
│
│  🟡 T1082 : System Information Discovery
│     └─ Tactic: Discovery
│
│  🟡 T1547.001 : Registry Run Keys
│     └─ Tactic: Persistence
│
│  Total Techniques: 12
│  Navigator Export: analysis_navigator.json
└─────────────────────────────────────────────────────────────────────────────

 SECTION 5: DETECTION RULES
┌─────────────────────────────────────────────────────────────────────────────
│  YARA Rule:
│  rule suspicious_exe_d41d8cd9 {
│      meta:
│          description = "Detects suspicious.exe"
│          author = "Ugur Ates"
│          hash = "e3b0c44298fc1c149..."
│      strings:
│          $s1 = "VirtualAllocEx"
│          $s2 = "WriteProcessMemory"
│      condition:
│          uint16(0) == 0x5A4D and all of them
│  }
│
│  KQL Query:
│  DeviceFileEvents
│  | where SHA256 == "e3b0c44298fc1c149afbf4c8996fb924..."
│  | project Timestamp, DeviceName, FileName, FolderPath
└─────────────────────────────────────────────────────────────────────────────
```

### Entropy Interpretation

| Range | Interpretation | Implication |
|-------|----------------|-------------|
| 0.0 - 1.0 | Empty/Sparse | Null bytes, minimal content |
| 1.0 - 4.5 | Plain text | Source code, documents |
| 4.5 - 6.5 | Normal executable | Standard compiled code |
| 6.5 - 7.2 | Compressed | UPX, standard packers |
| 7.2 - 7.8 | Packed | Custom packers, protectors |
| 7.8 - 8.0 | Encrypted | Crypters, ransomware payloads |

---

## Email Analysis

### Basic Usage

```bash
# Analyze an EML file
python -m src.soc_agent email suspicious.eml

# Analyze with HTML report
python -m src.soc_agent email phishing.eml --report email_report.html
```

### Understanding Results

```
═══════════════════════════════════════════════════════════════════════════════
                    BLUE TEAM ASSISTANT - EMAIL ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

 SECTION 1: EMAIL OVERVIEW
┌─────────────────────────────────────────────────────────────────────────────
│  Subject         : Urgent: Your account has been compromised!
│  From            : security@micros0ft.com ← Note: typosquatting!
│  To              : victim@company.com
│  Date            : 2024-01-15 10:23:45
│
│  Verdict         : 🔴 PHISHING (Score: 92/100)
└─────────────────────────────────────────────────────────────────────────────

 SECTION 2: AUTHENTICATION RESULTS
┌─────────────────────────────────────────────────────────────────────────────
│  SPF             : ❌ FAIL (sender not authorized)
│  DKIM            : ❌ FAIL (signature invalid)
│  DMARC           : ❌ FAIL (policy: reject)
│
│  🔴 All authentication checks failed - high confidence phishing
└─────────────────────────────────────────────────────────────────────────────

 SECTION 3: PHISHING INDICATORS
┌─────────────────────────────────────────────────────────────────────────────
│  ⚠️  Domain Spoofing
│      └── micros0ft.com looks like microsoft.com (typosquatting)
│
│  ⚠️  Urgency Keywords
│      └── "Urgent", "immediately", "suspended"
│
│  ⚠️  Suspicious Links
│      └── Display text: "Click here to verify"
│          Actual URL: http://evil-site.com/steal-creds.php
│
│  ⚠️  Sender Mismatch
│      └── From header doesn't match Return-Path
└─────────────────────────────────────────────────────────────────────────────

 SECTION 4: EXTRACTED IOCs
┌─────────────────────────────────────────────────────────────────────────────
│  URLs (3):
│  ├── http://evil-site.com/steal-creds.php (MALICIOUS)
│  ├── http://tracking.malware.com/1x1.gif (SUSPICIOUS)
│  └── https://legitimate-link.com (CLEAN)
│
│  Domains (2):
│  ├── evil-site.com (newly registered, no reputation)
│  └── tracking.malware.com (known malware host)
│
│  IPs (1):
│  └── 192.168.100.50 (hosting evil-site.com)
└─────────────────────────────────────────────────────────────────────────────

 SECTION 5: ATTACHMENTS
┌─────────────────────────────────────────────────────────────────────────────
│  invoice.pdf (45 KB)
│  ├── Type: PDF
│  ├── Contains: JavaScript
│  └── Verdict: 🔴 MALICIOUS (embedded JS downloader)
└─────────────────────────────────────────────────────────────────────────────
```

---

## Report Generation

### HTML Reports

```bash
# Generate HTML report for any analysis
python -m src.soc_agent ioc 8.8.8.8 --report ioc_report.html
python -m src.soc_agent file malware.exe --report file_report.html
python -m src.soc_agent email phish.eml --report email_report.html
```

### HTML Report Features

- **Interactive**: Collapsible sections, tabs
- **Downloadable**: Detection rules, IOC lists
- **Visual**: Charts, color-coded verdicts
- **Shareable**: Self-contained single file

### JSON Output

```bash
# Get JSON output (useful for automation)
python -m src.soc_agent ioc 8.8.8.8 --format json > result.json
```

---

## MCP Server Mode

CABTA can run as an MCP (Model Context Protocol) server for integration with Claude Desktop or other MCP clients.

### Starting the Server

```bash
python -m src.server
```

### Available Tools

| Tool | Description |
|------|-------------|
| `investigate_ioc` | Investigate an IOC |
| `analyze_file` | Analyze a file |
| `analyze_email` | Analyze an email |
| `generate_rules` | Generate detection rules |

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blue-team-assistant": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/blue-team-assistant"
    }
  }
}
```

---

## Batch Processing

### Process Multiple IOCs

```bash
# From a file (one IOC per line)
while read ioc; do
    python -m src.soc_agent ioc "$ioc" >> results.txt
done < iocs.txt

# Using xargs
cat iocs.txt | xargs -I {} python -m src.soc_agent ioc {}
```

### Process Multiple Files

```bash
# Analyze all EXE files in a directory
for file in /path/to/samples/*.exe; do
    python -m src.soc_agent file "$file" --report "reports/$(basename $file).html"
done
```

### PowerShell Batch Processing

```powershell
# Analyze multiple files
Get-ChildItem -Path .\samples\*.exe | ForEach-Object {
    python -m src.soc_agent file $_.FullName --report "reports\$($_.BaseName).html"
}
```

---

## Tips & Best Practices

### 1. Use HTML Reports for Sharing
HTML reports are self-contained and can be shared with non-technical stakeholders.

### 2. Check Configuration
Ensure API keys are configured for full functionality:
```bash
python test_setup.py
```

### 3. Interpret Scores in Context
A score of 50 doesn't mean "50% malicious" - it means multiple signals indicate suspicion. Always review the detailed findings.

### 4. Use Detection Rules
Copy the auto-generated YARA/SIGMA/KQL rules to your security tools for proactive detection.

### 5. Trust the FP Reduction
If the tool marks something as CLEAN despite being extracted from a suspicious file, it's likely legitimate infrastructure (DigiCert, Microsoft, etc.).
