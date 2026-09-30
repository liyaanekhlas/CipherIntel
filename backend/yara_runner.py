"""
SentinelScope YARA Execution & Rules Engine.

Includes:
- Built-in baseline ruleset for common packers (UPX, ASPack) and suspicious payload behaviors.
- Safe execution engine with timeout and syntax error isolation for custom rule evaluation.
"""

from typing import Any, Dict, List, Optional
import yara

# Baseline YARA rules compiled on startup
BASELINE_YARA_RULES = """
rule UPX_Packer_Signature {
    meta:
        description = "Detects UPX executable packer headers and section tags"
        threat_level = "Medium"
        mitre_technique = "T1027.002"
        reference = "MITRE ATT&CK Software Packing"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx_hdr = { 55 50 58 21 }
    condition:
        2 of them
}

rule Suspicious_Process_Injection_APIs {
    meta:
        description = "Detects co-occurrence of process allocation and remote memory write APIs"
        threat_level = "High"
        mitre_technique = "T1055"
        reference = "MITRE ATT&CK Process Injection"
    strings:
        $valloc = "VirtualAllocEx" ascii nocase
        $wpm = "WriteProcessMemory" ascii nocase
        $crt = "CreateRemoteThread" ascii nocase
        $vprot = "VirtualProtectEx" ascii nocase
    condition:
        2 of them
}

rule Suspicious_PowerShell_Cradle {
    meta:
        description = "Detects hidden PowerShell execution or automated web download cradle"
        threat_level = "High"
        mitre_technique = "T1059.001"
        reference = "MITRE ATT&CK PowerShell"
    strings:
        $ps1 = "powershell" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $enc = "-EncodedCommand" ascii nocase
        $wc1 = "DownloadFile" ascii nocase
        $wc2 = "DownloadString" ascii nocase
        $iex = "IEX" ascii nocase
    condition:
        $ps1 and (2 of ($hidden, $enc, $wc1, $wc2, $iex))
}

rule Suspicious_Ransomware_Inhibit_Recovery {
    meta:
        description = "Detects commands inhibiting system recovery and deleting volume shadow copies"
        threat_level = "Critical"
        mitre_technique = "T1490"
        reference = "MITRE ATT&CK Inhibit System Recovery"
    strings:
        $vss = "vssadmin delete shadows" ascii nocase
        $bcd = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
        $rec = "recoveryenabled no" ascii nocase
        $wbadmin = "wbadmin delete catalog -quiet" ascii nocase
    condition:
        any of them
}

rule Suspicious_Keylogger_Hook {
    meta:
        description = "Detects keyboard hook procedures associated with credential interception"
        threat_level = "Medium"
        mitre_technique = "T1056.001"
        reference = "MITRE ATT&CK Input Capture: Keylogging"
    strings:
        $hook = "SetWindowsHookEx" ascii nocase
        $async_key = "GetAsyncKeyState" ascii nocase
        $log_key = "GetKeyState" ascii nocase
    condition:
        $hook and ($async_key or $log_key)
}

rule Anti_Debugging_Checks {
    meta:
        description = "Detects debugger detection routines often used in evasion"
        threat_level = "Medium"
        mitre_technique = "T1497"
        reference = "MITRE ATT&CK Virtualization/Sandbox Evasion"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii nocase
        $dbg2 = "CheckRemoteDebuggerPresent" ascii nocase
        $dbg3 = "OutputDebugString" ascii nocase
    condition:
        2 of them
}
"""

# Compile baseline rules once at module load
try:
    COMPILED_BASELINE = yara.compile(source=BASELINE_YARA_RULES)
except Exception as _compile_err:
    COMPILED_BASELINE = None


def format_yara_matches(matches: List[Any]) -> List[Dict[str, Any]]:
    """Formats raw yara.Match objects into clean JSON-serializable dictionaries."""
    formatted = []
    for match in matches:
        matched_strings: List[Dict[str, Any]] = []

        for sm in match.strings:
            if hasattr(sm, "instances"):
                for inst in sm.instances:
                    preview_bytes = inst.matched_data[:64]
                    matched_strings.append({
                        "identifier": getattr(sm, "identifier", ""),
                        "offset": inst.offset,
                        "length": getattr(inst, "matched_length", len(preview_bytes)),
                        "data_preview": preview_bytes.decode("latin1", errors="replace"),
                        "hex_preview": preview_bytes.hex(),
                    })
            elif isinstance(sm, (tuple, list)):
                offset = sm[0]
                identifier = sm[1] if len(sm) > 1 else ""
                data_bytes = sm[2][:64] if len(sm) > 2 and isinstance(sm[2], bytes) else b""
                matched_strings.append({
                    "identifier": str(identifier),
                    "offset": int(offset),
                    "length": len(data_bytes),
                    "data_preview": data_bytes.decode("latin1", errors="replace"),
                    "hex_preview": data_bytes.hex(),
                })

        formatted.append({
            "rule_name": match.rule,
            "tags": match.tags,
            "meta": match.meta,
            "strings": matched_strings,
        })

    return formatted


def scan_with_baseline(data: bytes, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Evaluates byte buffer against SentinelScope built-in baseline YARA ruleset.
    Returns list of matched rule objects.
    """
    if not COMPILED_BASELINE or not data:
        return []

    try:
        matches = COMPILED_BASELINE.match(data=data, timeout=timeout)
        return format_yara_matches(matches)
    except Exception as exc:
        return []


def scan_with_custom_rule(data: bytes, rule_source: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Compiles and matches user-provided YARA rule string against uploaded byte buffer.
    Isolates compilation syntax errors and enforces safe execution timeout.

    Returns:
    {
        "success": bool,
        "error": Optional[str],
        "matches": List[Dict[str, Any]],
        "match_count": int
    }
    """
    if not rule_source or not rule_source.strip():
        return {
            "success": False,
            "error": "Rule source cannot be empty.",
            "matches": [],
            "match_count": 0,
        }

    try:
        compiled_custom = yara.compile(source=rule_source)
    except yara.SyntaxError as syn_err:
        return {
            "success": False,
            "error": f"YARA Syntax Error: {str(syn_err)}",
            "matches": [],
            "match_count": 0,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"YARA Compilation Error: {str(exc)}",
            "matches": [],
            "match_count": 0,
        }

    try:
        raw_matches = compiled_custom.match(data=data, timeout=timeout)
        matches = format_yara_matches(raw_matches)
        return {
            "success": True,
            "error": None,
            "matches": matches,
            "match_count": len(matches),
        }
    except yara.TimeoutError:
        return {
            "success": False,
            "error": f"YARA execution timed out after {timeout} seconds.",
            "matches": [],
            "match_count": 0,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"YARA Evaluation Error: {str(exc)}",
            "matches": [],
            "match_count": 0,
        }
