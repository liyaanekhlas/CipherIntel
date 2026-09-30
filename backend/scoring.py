"""
SentinelScope Threat Intelligence Scoring & SOC Action Engine.

Implements proprietary formulas:
- IP: Score = (VT_malicious / VT_total * 50) + (AbuseIPDB_confidence / 100 * 50)
- Domain/URL: Score = (VT_malicious / VT_total * 60) + (40 if active/online/malware_download else 20 if historical/offline else 0)
- Hash: Score = (VT_malicious / VT_total * 60) + (40 if confirmed in MalwareBazaar else 0)
- Clamped between 0 and 100.
- Classifications:
  * 0-19: Clean (Low)
  * 20-59: Suspicious (Medium)
  * 60-100: Malicious (High)
"""

from typing import Any, Dict, List, Tuple


def generate_recommended_actions(ioc_type: str, severity: str) -> List[str]:
    """Generates rule-based SOC Recommended Action Checklists based on IOC type and severity."""
    actions: List[str] = []

    if ioc_type == "ip":
        if severity == "High":
            actions = [
                "Immediately block inbound and outbound traffic to this IP on perimeter firewalls and border routers.",
                "Inject IP into SIEM and EDR automated blacklists (CrowdStrike, SentinelOne, Defender for Endpoint).",
                "Terminate all active internal user sessions, SSH tunnels, or VPN connections associated with this IP.",
                "Search NetFlow, proxy, and perimeter firewall logs for communication history over the past 30 days.",
                "Isolate any internal endpoints identified with persistent bidirectional beaconing to this IP.",
            ]
        elif severity == "Medium":
            actions = [
                "Implement targeted rate-limiting and deep packet inspection (DPI) on perimeter firewalls and WAF.",
                "Create a high-priority SIEM alert rule for any internal attempts to contact this IP.",
                "Review internal authentication and firewall logs for brute-force or port-scanning signatures.",
                "Verify ASN reputation and cross-reference with internal threat intelligence feeds.",
            ]
        else:  # Low / Clean
            actions = [
                "No immediate perimeter block required; indicator exhibits a benign reputation profile.",
                "Retain query telemetry in SIEM for baseline correlation and passive trend monitoring.",
                "Re-evaluate if parent ASN or associated subnet is cited in future threat advisories.",
            ]

    elif ioc_type == "domain":
        if severity == "High":
            actions = [
                "Sinkhole domain immediately on recursive enterprise DNS resolvers (Infoblox, Cisco Umbrella, Bind9).",
                "Add domain and wildcard subdomains (*.domain) to Secure Web Gateway (SWG) and web proxy deny lists.",
                "Query DNS resolver telemetry and endpoint EDR logs for historical resolution requests.",
                "Perform endpoint compromise assessment on all machines that resolved this domain within the last 14 days.",
                "Revoke and inspect any internal SSL/TLS connections or self-signed certificates referencing this domain.",
            ]
        elif severity == "Medium":
            actions = [
                "Apply strict SSL/TLS inspection and web category enforcement on Secure Web Gateway for this domain.",
                "Add domain to DNS threat monitoring watch-lists to track query frequency and detect DGA activity.",
                "Inspect domain registration details (WHOIS age, registrar, nameservers) for newly registered status.",
            ]
        else:  # Low / Clean
            actions = [
                "No blocking required. Domain has negligible malicious detections across intelligence repositories.",
                "Standard DNS filtering policies and web reputation checks remain sufficient.",
            ]

    elif ioc_type == "url":
        if severity == "High":
            actions = [
                "Block the exact URL and parent path on Secure Web Gateway (SWG), perimeter proxies, and web filters.",
                "Purge matching phishing or malicious messages from all user mailboxes via Email Security Gateway (SEG).",
                "Audit web proxy and browser telemetry to identify users who requested or downloaded content from this URL.",
                "Isolate user workstations that accessed the link and scan browser storage/downloads folder for malware.",
                "Force credential resets for users who visited this URL if phishing or credential harvesting is suspected.",
            ]
        elif severity == "Medium":
            actions = [
                "Configure email gateway to enforce link detonation and dynamic sandboxing on all inbound messages.",
                "Display a warning or interstitial caution banner on Secure Web Gateway before allowing navigation.",
                "Analyze destination webpage headers, TLS certificate, and embedded form fields for suspicious behavior.",
            ]
        else:  # Low / Clean
            actions = [
                "URL is currently evaluated as clean by external feeds; standard web protections apply.",
                "Re-scan destination if HTTP redirects (301/302) or infrastructure hosting changes occur.",
            ]

    elif ioc_type == "hash":
        if severity == "High":
            actions = [
                "Apply fleet-wide hash quarantine and execution block across all workstations via EDR.",
                "Immediately isolate all host systems where this file hash was detected or executed.",
                "Perform live memory dumps and triage forensic artifacts (registry keys, scheduled tasks, dropped files).",
                "Sweep email gateway and network proxy logs to identify the initial intrusion vector (phishing, drive-by).",
                "Submit binary sample to automated sandbox for dynamic behavioral analysis and C2 IOC extraction.",
            ]
        elif severity == "Medium":
            actions = [
                "Configure EDR policies to alert and quarantine upon detection of this file signature.",
                "Conduct automated static analysis (PE headers, import table, digital signature verification).",
                "Search endpoint telemetry across enterprise fleet to measure infection prevalence.",
            ]
        else:  # Low / Clean
            actions = [
                "Hash is not flagged as malicious by verified threat intelligence repositories.",
                "If file was observed during a suspicious event, submit to an internal sandbox for dynamic detonation.",
            ]

    else:
        actions = ["Review indicator manually against internal security operations runbooks."]

    return actions


def calculate_threat_score(ioc_type: str, raw_metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates threat score, classification, severity, score breakdown, and recommended actions.
    """
    vt_data = raw_metrics.get("virustotal", {})
    vt_malicious = float(vt_data.get("malicious", 0))
    vt_total = float(vt_data.get("total", 0))

    vt_component = 0.0
    vendor2_component = 0.0
    breakdown: Dict[str, float] = {}

    if ioc_type == "ip":
        # IP Formula: (VT_malicious / VT_total * 50) + (AbuseIPDB_confidence / 100 * 50)
        if vt_total > 0:
            vt_component = (vt_malicious / vt_total) * 50.0

        abuse_data = raw_metrics.get("abuseipdb", {})
        abuse_confidence = float(abuse_data.get("abuse_confidence_score", 0))
        vendor2_component = (abuse_confidence / 100.0) * 50.0

        raw_score = vt_component + vendor2_component
        breakdown = {
            "virustotal_component": round(vt_component, 2),
            "abuseipdb_component": round(vendor2_component, 2),
        }

    elif ioc_type in ("domain", "url"):
        # Domain/URL Formula: (VT_malicious / VT_total * 60) + (40 if active/online/malware_download else 20 if historical/offline else 0)
        if vt_total > 0:
            vt_component = (vt_malicious / vt_total) * 60.0

        urlhaus_data = raw_metrics.get("urlhaus", {})
        status_tag = str(urlhaus_data.get("urlhaus_status", "")).lower()
        url_status = str(urlhaus_data.get("url_status", "")).lower()
        threat = str(urlhaus_data.get("threat", "")).lower()

        # Check for active / online / malware_download
        active_indicators = {"active", "online", "malware_download"}
        if (
            status_tag in active_indicators
            or url_status in active_indicators
            or threat in active_indicators
            or urlhaus_data.get("active_threat", False)
        ):
            vendor2_component = 40.0
        elif (
            status_tag in {"historical", "offline"}
            or url_status in {"historical", "offline"}
            or urlhaus_data.get("historical_threat", False)
        ):
            vendor2_component = 20.0
        else:
            vendor2_component = 0.0

        raw_score = vt_component + vendor2_component
        breakdown = {
            "virustotal_component": round(vt_component, 2),
            "urlhaus_component": round(vendor2_component, 2),
        }

    elif ioc_type == "hash":
        # Hash Formula: (VT_malicious / VT_total * 60) + (40 if confirmed in MalwareBazaar else 0)
        if vt_total > 0:
            vt_component = (vt_malicious / vt_total) * 60.0

        mb_data = raw_metrics.get("malwarebazaar", {})
        mb_confirmed = bool(mb_data.get("confirmed", False))
        if mb_confirmed:
            vendor2_component = 40.0
        else:
            vendor2_component = 0.0

        raw_score = vt_component + vendor2_component
        breakdown = {
            "virustotal_component": round(vt_component, 2),
            "malwarebazaar_component": round(vendor2_component, 2),
        }

    else:
        raw_score = 0.0

    # Clamp final score between 0 and 100
    final_score = max(0.0, min(100.0, round(raw_score, 1)))

    # Determine Classification and Severity:
    # 0-19 Clean (Low), 20-59 Suspicious (Medium), 60-100 Malicious (High)
    if final_score < 20.0:
        classification = "Clean"
        severity = "Low"
    elif final_score < 60.0:
        classification = "Suspicious"
        severity = "Medium"
    else:
        classification = "Malicious"
        severity = "High"

    recommended_actions = generate_recommended_actions(ioc_type, severity)

    return {
        "threat_score": final_score,
        "classification": classification,
        "severity": severity,
        "score_breakdown": breakdown,
        "recommended_actions": recommended_actions,
    }
