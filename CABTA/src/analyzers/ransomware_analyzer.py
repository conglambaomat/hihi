"""
Ransomware-Specific Analysis Module
Detects ransomware indicators: crypto constants, ransom notes, bitcoin/onion URLs,
known ransomware extensions, encryption mechanism analysis.
"""
import re
import struct
import math
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class RansomwareIndicator:
    indicator_type: str    # crypto_constant, ransom_extension, ransom_note, bitcoin_addr, onion_url, encryption_detected
    name: str
    severity: str          # CRITICAL, HIGH, MEDIUM
    confidence: int        # 0-100
    details: str
    offset: Optional[int] = None
    mitre_technique: str = ""


class RansomwareAnalyzer:
    """Analyzes files for ransomware-specific indicators"""

    # Known ransomware file extensions (25+)
    RANSOMWARE_EXTENSIONS = {
        '.lockbit': 'LockBit', '.lockbit3': 'LockBit 3.0',
        '.BlackCat': 'BlackCat/ALPHV', '.cl0p': 'Cl0p', '.clop': 'Cl0p',
        '.royal': 'Royal', '.akira': 'Akira', '.rhysida': 'Rhysida',
        '.blacksuit': 'BlackSuit', '.medusa': 'MedusaLocker',
        '.8base': '8Base', '.bianlian': 'BianLian',
        '.encrypted': 'Generic', '.locked': 'Generic', '.crypt': 'Generic',
        '.enc': 'Generic', '.ryk': 'Ryuk', '.conti': 'Conti',
        '.hive': 'Hive', '.maze': 'Maze', '.revil': 'REvil/Sodinokibi',
        '.sodinokibi': 'REvil/Sodinokibi', '.darkside': 'DarkSide',
        '.babuk': 'Babuk', '.phobos': 'Phobos', '.dharma': 'Dharma',
        '.stop': 'STOP/Djvu', '.djvu': 'STOP/Djvu',
        '.play': 'Play', '.trigona': 'Trigona', '.noescape': 'NoEscape',
        '.monti': 'Monti', '.blackbasta': 'Black Basta',
    }

    # Ransom note filename patterns
    RANSOM_NOTE_PATTERNS = [
        r'README[\w\-]*\.txt', r'DECRYPT[\w\-]*\.txt', r'HOW[\s_\-]?TO[\s_\-]?RECOVER[\w\-]*',
        r'RESTORE[\s_\-]?FILES[\w\-]*', r'!README![\w\-]*', r'_readme\.txt',
        r'RECOVER[\s_\-]?YOUR[\s_\-]?FILES', r'YOUR[\s_\-]?FILES[\s_\-]?ARE[\s_\-]?ENCRYPTED',
        r'ATTENTION[\s_\-]?[\w\-]*\.txt', r'HELP[\s_\-]?DECRYPT[\w\-]*',
        r'[\w]*RANSOM[\w\-]*\.txt', r'UNLOCK[\s_\-]?FILES[\w\-]*',
        r'[\w]*PAYMENT[\s_\-]?INFO[\w\-]*\.txt',
    ]

    # AES S-Box (first 16 bytes are enough for detection)
    AES_SBOX_PARTIAL = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                              0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])

    # AES Inverse S-Box (first 16 bytes)
    AES_INV_SBOX_PARTIAL = bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                                   0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB])

    # RSA markers
    RSA_MARKER = bytes([0x30, 0x82])

    # ChaCha20/Salsa20 constant
    CHACHA_CONSTANT = b"expand 32-byte k"

    # SHA-256 initial hash values (H0)
    SHA256_INIT = struct.pack(">I", 0x6a09e667)

    # RC4 state init pattern
    RC4_STATE_INIT = bytes(range(8))

    def __init__(self):
        self.crypto_constants = [
            ('AES S-Box', self.AES_SBOX_PARTIAL, 'CRITICAL', 90, 'T1486'),
            ('AES Inverse S-Box', self.AES_INV_SBOX_PARTIAL, 'CRITICAL', 90, 'T1486'),
            ('RSA Public Key Marker', self.RSA_MARKER, 'MEDIUM', 40, 'T1486'),
            ('ChaCha20/Salsa20', self.CHACHA_CONSTANT, 'CRITICAL', 95, 'T1486'),
            ('SHA-256 Init', self.SHA256_INIT, 'LOW', 30, 'T1486'),
            ('RC4 State Init', self.RC4_STATE_INIT, 'MEDIUM', 50, 'T1486'),
        ]
        self._text_scan_limit_bytes = 512 * 1024
        self._max_line_window = 512
        self._compiled_ransom_note_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.RANSOM_NOTE_PATTERNS
        ]
        self._compiled_bitcoin_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        self._compiled_bech32_pattern = re.compile(r'\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,87}\b')
        self._compiled_onion_pattern = re.compile(r'[\w]{16,56}\.onion')
        self._ransom_string_patterns = [
            (re.compile(r'your\s+files\s+(have\s+been|are)\s+encrypted', re.IGNORECASE), 'encryption_notice', 'CRITICAL', 85),
            (re.compile(r'pay\s+(the\s+)?ransom', re.IGNORECASE), 'ransom_demand', 'CRITICAL', 90),
            (re.compile(r'decrypt(ion)?\s+(key|tool|software)', re.IGNORECASE), 'decryption_reference', 'HIGH', 70),
            (re.compile(r'all\s+your\s+(files|data|documents)\s+(have\s+been|are|were)', re.IGNORECASE), 'data_threat', 'HIGH', 65),
            (re.compile(r'(contact\s+us|write\s+to\s+us|send\s+email).{0,50}(decrypt|restore|recover)', re.IGNORECASE), 'contact_ransom', 'HIGH', 75),
            (re.compile(r'do\s+not\s+(try\s+to\s+)?(rename|move|delete|modify)\s+(the\s+)?(encrypted|locked)\s+files', re.IGNORECASE), 'warning_notice', 'HIGH', 80),
            (re.compile(r'(unique\s+)?decryption\s+(id|key|code|token)', re.IGNORECASE), 'decryption_id', 'HIGH', 70),
        ]
        self._vss_patterns = [
            (re.compile(r'vssadmin\s+(delete\s+shadows|resize\s+shadowstorage)', re.IGNORECASE), 'vss_delete', 'CRITICAL', 90),
            (re.compile(r'wmic\s+shadowcopy\s+delete', re.IGNORECASE), 'wmic_vss_delete', 'CRITICAL', 90),
            (re.compile(r'bcdedit\s+.*(/set|/delete).*recoveryenabled', re.IGNORECASE), 'bcdedit_recovery', 'CRITICAL', 85),
            (re.compile(r'wbadmin\s+delete\s+(catalog|systemstatebackup)', re.IGNORECASE), 'wbadmin_delete', 'CRITICAL', 85),
            (re.compile(r'cipher\s+/w:', re.IGNORECASE), 'cipher_wipe', 'HIGH', 70),
        ]

    def _build_text_view(self, data: bytes) -> str:
        """
        Decode once and normalize long single-line artifacts into bounded windows.

        Some log/text artifacts contain extremely long uninterrupted lines. Running
        ransom-note regexes directly over those blobs can backtrack badly, so we
        sample the content and reflow oversized lines into smaller windows first.
        """
        if not data:
            return ''

        sample = data
        if len(sample) > self._text_scan_limit_bytes:
            head = sample[: self._text_scan_limit_bytes // 2]
            tail = sample[-(self._text_scan_limit_bytes // 2):]
            sample = head + b"\n[... CABTA RANSOMWARE ANALYZER TRUNCATED MIDDLE CONTENT ...]\n" + tail

        try:
            text = sample.decode('utf-8', errors='ignore')
        except Exception:
            text = sample.decode('latin-1', errors='ignore')

        if not text:
            return ''

        normalized_lines = []
        for line in text.splitlines():
            if len(line) <= self._max_line_window:
                normalized_lines.append(line)
                continue
            for idx in range(0, len(line), self._max_line_window):
                normalized_lines.append(line[idx:idx + self._max_line_window])
        return '\n'.join(normalized_lines)

    def analyze_file(self, file_path: str, file_data: Optional[bytes] = None) -> Dict[str, Any]:
        """Full ransomware analysis of a file"""
        indicators: List[RansomwareIndicator] = []

        if file_data is None:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except Exception as e:
                return {'error': str(e), 'is_ransomware': False, 'indicators': []}

        text_view = self._build_text_view(file_data)

        # 1. Check file entropy (encryption detection)
        entropy_result = self._analyze_encryption_entropy(file_data)
        indicators.extend(entropy_result)

        # 2. Scan for crypto constants
        crypto_indicators = self._scan_crypto_constants(file_data)
        indicators.extend(crypto_indicators)

        # 3. Check for ransomware extension references in strings
        ext_indicators = self._scan_ransomware_extensions(text_view)
        indicators.extend(ext_indicators)

        # 4. Check for ransom note filename patterns
        note_indicators = self._scan_ransom_note_patterns(text_view)
        indicators.extend(note_indicators)

        # 5. Extract bitcoin addresses
        btc_indicators = self._extract_bitcoin_addresses(text_view)
        indicators.extend(btc_indicators)

        # 6. Extract onion URLs
        onion_indicators = self._extract_onion_urls(text_view)
        indicators.extend(onion_indicators)

        # 7. Check for ransom-related strings
        string_indicators = self._scan_ransom_strings(text_view)
        indicators.extend(string_indicators)

        # 8. Volume shadow copy deletion patterns
        vss_indicators = self._scan_vss_deletion(text_view)
        indicators.extend(vss_indicators)

        # Calculate ransomware score
        ransomware_score = self._calculate_score(indicators)

        # Determine family
        family = self._guess_family(indicators)

        # Determine encryption type from entropy
        overall_entropy = self._shannon_entropy(file_data)
        if overall_entropy > 7.9:
            encryption_type = 'full'
        elif overall_entropy > 6.0:
            encryption_type = 'partial'
        else:
            encryption_type = 'none'

        is_ransomware = ransomware_score >= 40

        return {
            'is_ransomware': is_ransomware,
            'ransomware_score': min(ransomware_score, 100),
            'verdict': 'RANSOMWARE' if ransomware_score >= 70 else ('SUSPECTED_RANSOMWARE' if ransomware_score >= 40 else 'NOT_RANSOMWARE'),
            'family': family,
            'encryption_type': encryption_type,
            'overall_entropy': round(overall_entropy, 4),
            'indicator_count': len(indicators),
            'indicators': [
                {
                    'type': i.indicator_type,
                    'name': i.name,
                    'severity': i.severity,
                    'confidence': i.confidence,
                    'details': i.details,
                    'offset': i.offset,
                    'mitre_technique': i.mitre_technique
                }
                for i in indicators
            ],
            'crypto_constants_found': [i.name for i in indicators if i.indicator_type == 'crypto_constant'],
            'bitcoin_addresses': [i.details.split(': ')[-1] for i in indicators if i.indicator_type == 'bitcoin_addr'],
            'onion_urls': [i.details.split(': ')[-1] for i in indicators if i.indicator_type == 'onion_url'],
            'ransomware_extensions_referenced': [i.name for i in indicators if i.indicator_type == 'ransom_extension'],
            'mitre_techniques': list(set(i.mitre_technique for i in indicators if i.mitre_technique))
        }

    # Implement all the helper methods:

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _analyze_encryption_entropy(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        entropy = self._shannon_entropy(data)
        if entropy > 7.9:
            indicators.append(RansomwareIndicator(
                indicator_type='encryption_detected',
                name='Full File Encryption',
                severity='CRITICAL',
                confidence=85,
                details=f'Overall entropy {entropy:.4f} indicates full encryption',
                mitre_technique='T1486'
            ))
        elif entropy > 7.0:
            indicators.append(RansomwareIndicator(
                indicator_type='encryption_detected',
                name='Partial/Intermittent Encryption',
                severity='HIGH',
                confidence=60,
                details=f'Overall entropy {entropy:.4f} suggests partial encryption',
                mitre_technique='T1486'
            ))
        return indicators

    def _scan_crypto_constants(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        for name, pattern, severity, confidence, mitre in self.crypto_constants:
            offset = data.find(pattern)
            if offset != -1:
                # RSA marker is very common, only flag if near other indicators
                if name == 'RSA Public Key Marker':
                    # Check for actual RSA key structure (length field after marker)
                    if offset + 4 < len(data):
                        key_len = struct.unpack(">H", data[offset+2:offset+4])[0]
                        if key_len < 100 or key_len > 4096:
                            continue  # Not a real RSA key

                indicators.append(RansomwareIndicator(
                    indicator_type='crypto_constant',
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    details=f'{name} found at offset 0x{offset:X}',
                    offset=offset,
                    mitre_technique=mitre
                ))
        return indicators

    def _scan_ransomware_extensions(self, text: str) -> List[RansomwareIndicator]:
        indicators = []
        if not text:
            return indicators

        lowered = text.lower()

        for ext, family in self.RANSOMWARE_EXTENSIONS.items():
            if ext.lower() in lowered:
                indicators.append(RansomwareIndicator(
                    indicator_type='ransom_extension',
                    name=f'{ext} ({family})',
                    severity='CRITICAL',
                    confidence=80,
                    details=f'Ransomware extension {ext} ({family} family) found in file strings',
                    mitre_technique='T1486'
                ))
        return indicators

    def _scan_ransom_note_patterns(self, text: str) -> List[RansomwareIndicator]:
        indicators = []
        if not text:
            return indicators

        seen = set()
        for compiled in self._compiled_ransom_note_patterns:
            match = compiled.search(text)
            if match:
                found = match.group(0)
                if found.lower() in seen:
                    continue
                seen.add(found.lower())
                indicators.append(RansomwareIndicator(
                    indicator_type='ransom_note',
                    name=found,
                    severity='HIGH',
                    confidence=75,
                    details=f'Ransom note filename pattern detected: {found}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _extract_bitcoin_addresses(self, text: str) -> List[RansomwareIndicator]:
        indicators = []
        if not text:
            return indicators

        # Bitcoin address: starts with 1 or 3, 25-34 chars base58
        matches = self._compiled_bitcoin_pattern.findall(text)
        seen = set()
        for addr in matches:
            if addr not in seen:
                seen.add(addr)
                indicators.append(RansomwareIndicator(
                    indicator_type='bitcoin_addr',
                    name='Bitcoin Address',
                    severity='HIGH',
                    confidence=70,
                    details=f'Bitcoin address found: {addr}',
                    mitre_technique='T1486'
                ))
        # Also check for bc1 (bech32) addresses
        bc1_matches = self._compiled_bech32_pattern.findall(text)
        for addr in bc1_matches:
            if addr not in seen:
                seen.add(addr)
                indicators.append(RansomwareIndicator(
                    indicator_type='bitcoin_addr',
                    name='Bitcoin Bech32 Address',
                    severity='HIGH',
                    confidence=70,
                    details=f'Bitcoin bech32 address found: {addr}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _extract_onion_urls(self, text: str) -> List[RansomwareIndicator]:
        indicators = []
        if not text:
            return indicators

        matches = self._compiled_onion_pattern.findall(text)
        seen = set()
        for url in matches:
            if url not in seen:
                seen.add(url)
                indicators.append(RansomwareIndicator(
                    indicator_type='onion_url',
                    name='Tor Onion URL',
                    severity='HIGH',
                    confidence=80,
                    details=f'Onion URL found: {url}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _scan_ransom_strings(self, text: str) -> List[RansomwareIndicator]:
        """Scan for ransom-related strings"""
        indicators = []
        if not text:
            return indicators

        for compiled, name, severity, confidence in self._ransom_string_patterns:
            if compiled.search(text):
                indicators.append(RansomwareIndicator(
                    indicator_type='ransom_string',
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    details=f'Ransom-related string pattern detected: {name}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _scan_vss_deletion(self, text: str) -> List[RansomwareIndicator]:
        """Scan for Volume Shadow Copy deletion patterns"""
        indicators = []
        if not text:
            return indicators

        for compiled, name, severity, confidence in self._vss_patterns:
            if compiled.search(text):
                indicators.append(RansomwareIndicator(
                    indicator_type='recovery_inhibition',
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    details=f'Recovery inhibition pattern detected: {name}',
                    mitre_technique='T1490'
                ))
        return indicators

    def _calculate_score(self, indicators: List[RansomwareIndicator]) -> int:
        if not indicators:
            return 0

        score = 0
        has_crypto = any(i.indicator_type == 'crypto_constant' for i in indicators)
        has_extension = any(i.indicator_type == 'ransom_extension' for i in indicators)
        has_note = any(i.indicator_type == 'ransom_note' for i in indicators)
        has_btc = any(i.indicator_type == 'bitcoin_addr' for i in indicators)
        has_onion = any(i.indicator_type == 'onion_url' for i in indicators)
        has_strings = any(i.indicator_type == 'ransom_string' for i in indicators)
        has_vss = any(i.indicator_type == 'recovery_inhibition' for i in indicators)
        has_encryption = any(i.indicator_type == 'encryption_detected' for i in indicators)

        # Base scores
        if has_crypto: score += 20
        if has_extension: score += 20
        if has_note: score += 15
        if has_btc: score += 15
        if has_onion: score += 15
        if has_strings: score += 15
        if has_vss: score += 20
        if has_encryption: score += 10

        # Combo bonuses
        if has_crypto and has_strings: score += 10
        if has_btc and has_onion: score += 10
        if has_vss and (has_crypto or has_strings): score += 10
        if has_extension and has_note: score += 10

        return min(score, 100)

    def _guess_family(self, indicators: List[RansomwareIndicator]) -> str:
        """Guess ransomware family from indicators"""
        families = []
        for ind in indicators:
            if ind.indicator_type == 'ransom_extension':
                # Extract family from name like ".lockbit (LockBit)"
                if '(' in ind.name:
                    family = ind.name.split('(')[-1].rstrip(')')
                    families.append(family)

        if families:
            # Return most specific family
            for f in families:
                if f != 'Generic':
                    return f
            return families[0]
        return 'Unknown'
