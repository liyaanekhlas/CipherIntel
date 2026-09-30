"""
SentinelScope MITRE ATT&CK Mapping Module.

Maps threat intelligence IOC categories and static PE analysis telemetry
to MITRE ATT&CK Enterprise tactics and techniques with contextual reasoning.
"""

from typing import Any, Dict, List, Optional

# MITRE ATT&CK Enterprise Techniques Catalog
TECHNIQUES_CATALOG = {
    "T1071": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering.",
    },
    "T1590": {
        "technique_id": "T1590",
        "technique_name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about victim networks such as IP ranges and domain names.",
    },
    "T1566": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages with malicious attachments or links to gain initial access.",
    },
    "T1204": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
        "description": "An adversary may rely upon specific actions by a user to execute malicious code.",
    },
    "T1204.002": {
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "An adversary may rely upon a user opening a malicious file to initiate code execution.",
    },
    "T1059": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
    },
    "T1059.001": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution and download cradles.",
    },
    "T1059.003": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse cmd.exe for execution of system commands and batch files.",
    },
    "T1055": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade process-based defenses and elevate privileges.",
    },
    "T1056.001": {
        "technique_id": "T1056.001",
        "technique_name": "Input Capture: Keylogging",
        "tactic": "Collection, Credential Access",
        "description": "Adversaries may log user keystrokes to intercept credentials, sensitive emails, or keystroke input.",
    },
    "T1497": {
        "technique_id": "T1497",
        "technique_name": "Virtualization/Sandbox Evasion",
        "tactic": "Defense Evasion, Discovery",
        "description": "Adversaries may employ checks for debugging or virtualization environments to alter behavior.",
    },
    "T1057": {
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get information about running processes on a system.",
    },
    "T1027.002": {
        "technique_id": "T1027.002",
        "technique_name": "Software Packing",
        "tactic": "Defense Evasion",
        "description": "Adversaries may compress or encrypt executable code to suppress signatures and hinder analysis.",
    },
    "T1490": {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or modify system recovery data (e.g. shadow copies) to impair recovery.",
    },
}

# Suspicious Windows API to MITRE Mapping
API_MITRE_MAP = {
    # Memory allocation & Process injection
    "VirtualAlloc": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "reason": "Allocates executable memory space in process virtual memory, a common prerequisite for shellcode injection.",
    },
    "VirtualAllocEx": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "reason": "Allocates memory within a remote process address space for remote thread or cross-process injection.",
    },
    "WriteProcessMemory": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "reason": "Writes malicious payloads or shellcode directly into another process's virtual memory space.",
    },
    "CreateRemoteThread": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "reason": "Spawns an execution thread in the address space of a target process to execute injected code.",
    },
    "VirtualProtect": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "reason": "Alters memory page protections (e.g. PAGE_EXECUTE_READWRITE) to execute unpacked code in non-executable segments.",
    },
    "VirtualProtectEx": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "reason": "Modifies protection on a committed region of pages in a remote process, indicative of DLL injection.",
    },
    "QueueUserAPC": {
        "technique_id": "T1055",
        "technique_name": "Process Injection: APC Injection",
        "tactic": "Defense Evasion",
        "reason": "Queues an Asynchronous Procedure Call to a target thread, often used in Early Bird injection.",
    },
    # Process / System Access
    "WinExec": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "reason": "Direct execution of arbitrary executable programs and command lines.",
    },
    "ShellExecute": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "reason": "Invokes shell execution routines to launch external processes, files, or URLs.",
    },
    "ShellExecuteA": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "reason": "ANSI variant: launches external processes, commands, or batch scripts.",
    },
    "ShellExecuteW": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "reason": "Unicode variant: launches external processes or executes secondary payloads.",
    },
    "OpenProcess": {
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "Discovery",
        "reason": "Opens an existing local process object with elevated rights (PROCESS_ALL_ACCESS) for inspection or injection.",
    },
    "CreateProcessA": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "reason": "Spawns new processes, commonly used for secondary payload execution or process hollowing.",
    },
    "CreateProcessW": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "reason": "Unicode variant of CreateProcess, frequently used in staged execution.",
    },
    # Evasion & Hooking
    "SetWindowsHookEx": {
        "technique_id": "T1056.001",
        "technique_name": "Input Capture: Keylogging",
        "tactic": "Collection, Credential Access",
        "reason": "Installs an application-defined hook procedure into a hook chain to monitor message traffic (keylogging/hooking).",
    },
    "SetWindowsHookExA": {
        "technique_id": "T1056.001",
        "technique_name": "Input Capture: Keylogging",
        "tactic": "Collection, Credential Access",
        "reason": "ANSI variant: installs system-wide keyboard/mouse hooks for input capture.",
    },
    "SetWindowsHookExW": {
        "technique_id": "T1056.001",
        "technique_name": "Input Capture: Keylogging",
        "tactic": "Collection, Credential Access",
        "reason": "Unicode variant: intercepts low-level keyboard messages across the operating system.",
    },
    "IsDebuggerPresent": {
        "technique_id": "T1497",
        "technique_name": "Virtualization/Sandbox Evasion",
        "tactic": "Defense Evasion, Discovery",
        "reason": "Determines if the calling process is being debugged by a user-mode debugger to alter control flow.",
    },
    "CheckRemoteDebuggerPresent": {
        "technique_id": "T1497",
        "technique_name": "Virtualization/Sandbox Evasion",
        "tactic": "Defense Evasion, Discovery",
        "reason": "Queries the kernel for a remote debugger attachment to evade dynamic sandbox execution.",
    },
}


def map_ioc_to_mitre(
    ioc_type: str,
    raw_metrics: Dict[str, Any],
    threat_score: float = 0.0,
    severity: str = "",
) -> List[Dict[str, Any]]:
    """
    Maps IOC telemetry categories and threat feeds to MITRE ATT&CK Enterprise techniques:
    - High reputation / spamming IPs -> T1071 (Application Layer Protocol: C2), T1590 (Gather Victim Network Information).
    - Phishing / Suspicious domains/URLs -> T1566 (Phishing), T1204 (User Execution).
    - Malware hashes -> T1204.002 (Malicious File), T1059 (Command and Scripting Interpreter).

    Returns a list of structured technique objects:
    [
        {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "reason": "Contextual justification string"
        }
    ]
    """
    techniques: List[Dict[str, Any]] = []
    vt_data = raw_metrics.get("virustotal", {})
    vt_malicious = int(vt_data.get("malicious", 0))

    if ioc_type == "ip":
        abuse_data = raw_metrics.get("abuseipdb", {})
        abuse_score = int(abuse_data.get("abuse_confidence_score", 0))
        total_reports = int(abuse_data.get("total_reports", 0))
        usage_type = str(abuse_data.get("usage_type", ""))

        # Check for C2 / spam / scanning telemetry
        is_suspicious_ip = (abuse_score > 0 or vt_malicious > 0 or threat_score >= 20.0)

        if is_suspicious_ip:
            # T1071: C2 Communication
            reason_c2 = (
                f"IP exhibits an abuse confidence score of {abuse_score}% across {total_reports} reports "
                f"with {vt_malicious} AV detections, matching active Command & Control infrastructure."
                if (abuse_score > 0 or vt_malicious > 0)
                else f"Telemetry indicates external communication endpoint matching C2 protocol traffic ({usage_type or 'Network Host'})."
            )
            techniques.append({
                "technique_id": "T1071",
                "technique_name": TECHNIQUES_CATALOG["T1071"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1071"]["tactic"],
                "reason": reason_c2,
            })

            # T1590: Gather Victim Network Information
            reason_recon = (
                f"Host is actively documented in threat feeds for automated port scanning, "
                f"brute-force attacks, and victim network profiling."
            )
            techniques.append({
                "technique_id": "T1590",
                "technique_name": TECHNIQUES_CATALOG["T1590"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1590"]["tactic"],
                "reason": reason_recon,
            })
        else:
            # Benign baseline context
            techniques.append({
                "technique_id": "T1590",
                "technique_name": TECHNIQUES_CATALOG["T1590"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1590"]["tactic"],
                "reason": "Network indicator evaluated for external ingress/egress reconnaissance profiling (currently benign).",
            })

    elif ioc_type in ("domain", "url"):
        urlhaus_data = raw_metrics.get("urlhaus", {})
        urlhaus_status = str(urlhaus_data.get("urlhaus_status", "")).lower()
        threat = str(urlhaus_data.get("threat", "")).lower()
        active_threat = urlhaus_data.get("active_threat", False)

        is_suspicious = (vt_malicious > 0 or active_threat or urlhaus_status in ("active", "online", "historical") or threat_score >= 20.0)

        if is_suspicious:
            # T1566: Phishing
            reason_phish = (
                f"Domain/URL flagged for active payload delivery or credential harvesting "
                f"({threat or 'suspicious web telemetry'}, {vt_malicious} security engines flagging threat)."
            )
            techniques.append({
                "technique_id": "T1566",
                "technique_name": TECHNIQUES_CATALOG["T1566"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1566"]["tactic"],
                "reason": reason_phish,
            })

            # T1204: User Execution
            reason_exec = (
                "Indicator relies on social engineering lures and user execution to deliver malicious payloads, "
                "browser exploits, or credential interception pages."
            )
            techniques.append({
                "technique_id": "T1204",
                "technique_name": TECHNIQUES_CATALOG["T1204"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1204"]["tactic"],
                "reason": reason_exec,
            })
        else:
            techniques.append({
                "technique_id": "T1566",
                "technique_name": TECHNIQUES_CATALOG["T1566"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1566"]["tactic"],
                "reason": "Evaluated against phishing delivery and spearphishing link repositories.",
            })

    elif ioc_type == "hash":
        mb_data = raw_metrics.get("malwarebazaar", {})
        confirmed = mb_data.get("confirmed", False)
        signature = mb_data.get("signature", "")

        is_malware = (confirmed or vt_malicious > 0 or threat_score >= 20.0)

        if is_malware:
            # T1204.002: Malicious File
            reason_file = (
                f"Cryptographic hash confirmed as weaponized malware payload "
                f"({signature or 'malware sample'}) across threat intelligence repositories."
                if confirmed or signature
                else f"File hash flagged by {vt_malicious} antivirus detection engines as a malicious binary."
            )
            techniques.append({
                "technique_id": "T1204.002",
                "technique_name": TECHNIQUES_CATALOG["T1204.002"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1204.002"]["tactic"],
                "reason": reason_file,
            })

            # T1059: Command and Scripting Interpreter
            techniques.append({
                "technique_id": "T1059",
                "technique_name": TECHNIQUES_CATALOG["T1059"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1059"]["tactic"],
                "reason": "Payload exhibits capabilities to spawn shell interpreters (cmd.exe, powershell) for persistence and secondary execution.",
            })
        else:
            techniques.append({
                "technique_id": "T1204.002",
                "technique_name": TECHNIQUES_CATALOG["T1204.002"]["technique_name"],
                "tactic": TECHNIQUES_CATALOG["T1204.002"]["tactic"],
                "reason": "Hash cataloged and evaluated against known malware binaries (clean profile).",
            })

    return techniques


def map_api_to_mitre(api_name: str) -> Optional[Dict[str, Any]]:
    """
    Maps a detected Windows PE API name to its MITRE ATT&CK technique object.
    Returns clean dictionary or None if not flagged.
    """
    clean_name = api_name.strip()
    if clean_name in API_MITRE_MAP:
        mapping = API_MITRE_MAP[clean_name]
        return {
            "api_name": clean_name,
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "tactic": mapping["tactic"],
            "reason": mapping["reason"],
        }
    return None


def get_technique_details(technique_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full metadata for a technique from the catalog."""
    return TECHNIQUES_CATALOG.get(technique_id)
