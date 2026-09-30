"""
SentinelScope Stage 4 & Stage 5 Verification Suite.
Validates:
1. MITRE ATT&CK Matrix Mapping (mitre_mapper.py)
2. Multi-Factor Contextual Risk Engine (risk_engine.py)
3. Binary & Static PE Analyzer (static_analyzer.py)
4. YARA Signature & Execution Runner (yara_runner.py)
5. Authenticated Endpoints:
   - POST /api/analyze (integrated with score_breakdown and mitre_techniques)
   - POST /api/artifact/analyze (multipart PE file upload)
   - POST /api/artifact/yara-test (custom YARA rule test)
"""

import io
import math
import os
import pefile
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import USERS_DB
from backend.mitre_mapper import map_ioc_to_mitre, map_api_to_mitre, get_technique_details
from backend.risk_engine import (
    calculate_risk_score,
    evaluate_attribute_heuristics,
    extract_threat_taxonomy,
    evaluate_structural_heuristics,
)
from backend.static_analyzer import (
    calculate_shannon_entropy,
    extract_strings_and_iocs,
    parse_pe_artifact,
)
from backend.yara_runner import scan_with_baseline, scan_with_custom_rule


def run_stage4_stage5_tests():
    client = TestClient(app)
    print("=" * 65)
    print("[*] STARTING SENTINELSCOPE STAGE 4 & 5 VERIFICATION SUITE")
    print("=" * 65)

    # -------------------------------------------------------------------------
    # 1. MITRE ATT&CK Mapper Verification
    # -------------------------------------------------------------------------
    print("\n[+] 1. Testing MITRE ATT&CK Mapper (mitre_mapper.py):")

    # A. IP mapping -> T1071 (C2) & T1590 (Gather Network Info)
    ip_mitre = map_ioc_to_mitre("ip", {
        "virustotal": {"malicious": 10, "total": 80},
        "abuseipdb": {"abuse_confidence_score": 85, "total_reports": 42},
    })
    tech_ids = [t["technique_id"] for t in ip_mitre]
    assert "T1071" in tech_ids, f"Expected T1071 in IP mapping: {tech_ids}"
    assert "T1590" in tech_ids, f"Expected T1590 in IP mapping: {tech_ids}"
    for t in ip_mitre:
        assert "technique_id" in t and "technique_name" in t and "tactic" in t and "reason" in t
        assert len(t["reason"]) > 10
    print(f"    - IP Telemetry mapped to T1071 ({ip_mitre[0]['tactic']}) & T1590: PASSED")

    # B. Domain/URL mapping -> T1566 (Phishing) & T1204 (User Execution)
    domain_mitre = map_ioc_to_mitre("domain", {
        "virustotal": {"malicious": 15, "total": 90},
        "urlhaus": {"urlhaus_status": "active", "threat": "malware_download"},
    })
    d_tech_ids = [t["technique_id"] for t in domain_mitre]
    assert "T1566" in d_tech_ids, f"Expected T1566 in Domain mapping: {d_tech_ids}"
    assert "T1204" in d_tech_ids, f"Expected T1204 in Domain mapping: {d_tech_ids}"
    print(f"    - Phishing Domain/URL mapped to T1566 (Phishing) & T1204 (User Execution): PASSED")

    # C. Hash mapping -> T1204.002 (Malicious File) & T1059 (Command/Scripting)
    hash_mitre = map_ioc_to_mitre("hash", {
        "virustotal": {"malicious": 45, "total": 70},
        "malwarebazaar": {"confirmed": True, "signature": "RedLineStealer"},
    })
    h_tech_ids = [t["technique_id"] for t in hash_mitre]
    assert "T1204.002" in h_tech_ids, f"Expected T1204.002 in Hash mapping: {h_tech_ids}"
    assert "T1059" in h_tech_ids, f"Expected T1059 in Hash mapping: {h_tech_ids}"
    print(f"    - Malware Hash mapped to T1204.002 (Malicious File) & T1059: PASSED")

    # D. API to MITRE mapping
    valloc_map = map_api_to_mitre("VirtualAllocEx")
    assert valloc_map is not None
    assert valloc_map["technique_id"] == "T1055"
    assert "Process Injection" in valloc_map["technique_name"]

    dbg_map = map_api_to_mitre("IsDebuggerPresent")
    assert dbg_map is not None
    assert dbg_map["technique_id"] == "T1497"

    hook_map = map_api_to_mitre("SetWindowsHookExA")
    assert hook_map is not None
    assert hook_map["technique_id"] == "T1056.001"
    print("    - Windows APIs mapped to MITRE (VirtualAllocEx -> T1055, IsDebuggerPresent -> T1497): PASSED")

    # -------------------------------------------------------------------------
    # 2. Risk Engine Multi-Factor Algorithm Verification
    # -------------------------------------------------------------------------
    print("\n[+] 2. Testing Multi-Factor Risk Engine (risk_engine.py):")

    # Attribute Heuristics: Dynamic DNS, Suspicious TLD, and Punycode
    dyn_score, dyn_matched = evaluate_attribute_heuristics("domain", "c2-stealer.duckdns.org")
    assert dyn_score >= 5.0
    assert any("Dynamic DNS" in m for m in dyn_matched)

    tld_score, tld_matched = evaluate_attribute_heuristics("url", "http://evil-payload.xyz:4444/download.exe")
    assert tld_score >= 8.0  # TLD (3) + Port (4) + Ext (3) -> 10.0
    assert any("Top-Level Domain" in m for m in tld_matched)

    puny_score, puny_matched = evaluate_attribute_heuristics("domain", "xn--pple-43d.com")
    assert puny_score >= 5.0
    assert any("Punycode" in m for m in puny_matched)
    print("    - Attribute Heuristics (Dynamic DNS, Suspicious TLD, Anomalous Port, Punycode): PASSED")

    # Multi-Factor Score: IP with 50% VT detection, C2 flag, 90% AbuseIPDB confidence
    risk_res = calculate_risk_score("ip", "185.220.101.5", {
        "virustotal": {"malicious": 40, "total": 80},  # Dual-feed consensus bonus
        "abuseipdb": {"abuse_confidence_score": 90, "total_reports": 150, "usage_type": "C2 Server"},
    })
    assert 0.0 <= risk_res["total_score"] <= 100.0
    assert risk_res["verdict"] in ("High", "Critical")
    bd = risk_res["breakdown"]
    # Check new factor keys (35%, 30%, 25%, 10%)
    assert "vendor_consensus" in bd
    assert "threat_taxonomy" in bd
    assert "infrastructure_telemetry" in bd
    assert "structural_heuristics" in bd
    # Check legacy compatibility keys
    assert "cross_vendor_consensus" in bd
    assert "reputation_confidence" in bd
    assert "external_engines" in bd
    assert "threat_category" in bd
    assert "confidence_prevalence" in bd
    assert "attribute_heuristics" in bd
    assert bd["vendor_consensus_score"] == 27.5  # (0.5 * 25 = 12.5) + 15 agreement bonus = 27.5 / 35.0
    assert bd["threat_taxonomy_score"] == 30.0  # C2 Server tier 1
    assert bd["infrastructure_telemetry_score"] >= 20.0  # Data Center / Cloud + 90% abuse confidence
    print(f"    - Transparent factor breakdown: Total={risk_res['total_score']} Verdict={risk_res['verdict']}: PASSED")

    # False-positive dampener: 1 detection out of 72 engines with 0 secondary confirmation
    fp_res = calculate_risk_score("ip", "1.2.3.4", {
        "virustotal": {"malicious": 1, "total": 72},
        "abuseipdb": {"abuse_confidence_score": 0},
    })
    assert fp_res["breakdown"]["vendor_consensus_score"] == 0.0
    assert fp_res["breakdown"]["vendor_consensus"]["dampener_applied"] is True
    assert fp_res["breakdown"]["vendor_consensus"]["consensus_verdict"] == "Isolated Flag"
    assert "Likely isolated vendor false-positive" in fp_res["breakdown"]["vendor_consensus"]["details"]
    print(f"    - False-positive dampener (1/72 VT detection dampened to 0.0 pts with 'Isolated Flag' verdict): PASSED")

    # Clean Override: 8.8.8.8 (VT == 0 and AbuseIPDB confidence == 0) strictly evaluates to 0.0
    clean_ip_res = calculate_risk_score("ip", "8.8.8.8", {
        "virustotal": {"malicious": 0, "total": 85},
        "abuseipdb": {"abuse_confidence_score": 0, "total_reports": 500, "usage_type": "Data Center"},
    })
    assert clean_ip_res["total_score"] == 0.0
    assert clean_ip_res["verdict"] == "Low"
    assert clean_ip_res["is_clean_override"] is True
    assert clean_ip_res["breakdown"]["vendor_consensus_score"] == 0.0
    assert clean_ip_res["breakdown"]["threat_taxonomy_score"] == 0.0
    assert clean_ip_res["breakdown"]["infrastructure_telemetry_score"] == 0.0
    assert clean_ip_res["breakdown"]["structural_heuristics_score"] == 0.0
    # Card 1 Consensus Verdict
    assert clean_ip_res["breakdown"]["vendor_consensus"]["consensus_verdict"] == "Unanimously Clean"
    # Card 2 Benign Fallback String
    assert clean_ip_res["breakdown"]["threat_taxonomy"]["details"] == "No adversary threat tags reported by threat feeds"
    # Card 3 Infrastructure & ASN Telemetry
    assert clean_ip_res["breakdown"]["infrastructure_telemetry"]["asn"] == "AS15169"
    assert "US" in clean_ip_res["breakdown"]["infrastructure_telemetry"]["country"]
    # Card 4 Always at least 2 distinct heuristic checks
    assert len(clean_ip_res["breakdown"]["structural_heuristics"]["checks_evaluated"]) >= 2
    assert "ASN Classification:" in clean_ip_res["breakdown"]["structural_heuristics"]["details"]
    print("    - Clean Override for 8.8.8.8 (VT=0, Abuse=0 strictly evaluates to 0.0 across all 4 refactored cards): PASSED")

    # Card 2 & Card 4 IOC Type 1: IP with AbuseIPDB Port Scan & Non-Residential Hosting Heuristics
    ip_scanner_res = calculate_risk_score("ip", "198.51.100.10:4444", {
        "virustotal": {"malicious": 2, "total": 70, "tags": ["scanner"], "asn": 14061, "as_owner": "DigitalOcean, LLC", "country": "DE"},
        "abuseipdb": {
            "abuse_confidence_score": 60,
            "total_reports": 45,
            "usage_type": "Data Center/Web Hosting/Transit",
            "attack_categories": ["Port Scan", "SSH Brute-Force"],
            "is_tor": False,
            "country_code": "DE",
        }
    })
    ip_tax = ip_scanner_res["breakdown"]["threat_taxonomy"]
    assert any(t in ip_tax["matched_tags"] for t in ["Scanner", "Brute-Force"])
    assert ip_tax["score"] >= 10.0
    ip_infra = ip_scanner_res["breakdown"]["infrastructure_telemetry"]
    assert ip_infra["asn"] == "AS14061"
    assert "DigitalOcean" in ip_infra["as_org"]
    assert ip_infra["country"] == "DE"
    assert "🇩🇪" in ip_infra["country_flag"]
    assert ip_infra["score"] >= 8.0  # Data Center base risk + abuse confidence
    ip_heur = ip_scanner_res["breakdown"]["structural_heuristics"]
    assert len(ip_heur["checks_evaluated"]) >= 2
    assert ip_heur["score"] >= 5.0  # Data center + anomalous port 4444
    assert any("Hosting" in a or "Data Center" in a for a in ip_heur["anomalies"])
    assert any("4444" in a for a in ip_heur["anomalies"])
    print(f"    - IP Telemetry: Card 1 Consensus ({ip_scanner_res['breakdown']['vendor_consensus']['consensus_verdict']}), Card 2 Scanner ({ip_tax['score']} pts), Card 3 ASN {ip_infra['asn']} ({ip_infra['score']} pts), Card 4 Heuristics ({ip_heur['score']} pts): PASSED")

    # Card 2 & Card 4 IOC Type 2: Domain (Clean vs Malicious DGA & High-Abuse TLD)
    clean_dom_res = calculate_risk_score("domain", "example.com", {
        "virustotal": {"malicious": 0, "total": 85},
        "urlhaus": {"urlhaus_status": "offline", "threat": None, "tags": []}
    })
    assert clean_dom_res["breakdown"]["threat_taxonomy"]["details"] == "No adversary threat tags reported by threat feeds"
    assert clean_dom_res["breakdown"]["threat_taxonomy_score"] == 0.0
    assert len(clean_dom_res["breakdown"]["structural_heuristics"]["checks_evaluated"]) >= 2
    assert any("Standard" in c for c in clean_dom_res["breakdown"]["structural_heuristics"]["checks_evaluated"])

    dga_dom_res = calculate_risk_score("domain", "c2-892183917409174092.top", {
        "virustotal": {
            "malicious": 35,
            "total": 80,
            "popular_threat_classification": {"suggested_threat_label": "cobaltstrike"}
        },
        "urlhaus": {
            "urlhaus_status": "active",
            "threat": "c2_server",
            "tags": ["CobaltStrike", "Botnet"]
        }
    })
    dga_tax = dga_dom_res["breakdown"]["threat_taxonomy"]
    assert any(t in dga_tax["matched_tags"] for t in ["C2", "Botnet"])
    assert dga_tax["score"] == 30.0  # Critical tier
    dga_heur = dga_dom_res["breakdown"]["structural_heuristics"]
    assert len(dga_heur["checks_evaluated"]) >= 2
    assert dga_heur["score"] >= 5.0  # .top TLD + high digit ratio
    assert any("Top-Level Domain" in a for a in dga_heur["anomalies"])
    assert any("DGA" in a for a in dga_heur["anomalies"])
    print(f"    - Domain Telemetry: Clean domain 0 pts & 3 checks; DGA domain mapped to C2 ({dga_tax['score']} pts) & DGA/TLD Heuristics ({dga_heur['score']} pts): PASSED")

    # Card 2 & Card 4 IOC Type 3: URL (Clean vs Phishing with Embedded '@' & Executable Download)
    clean_url_res = calculate_risk_score("url", "https://docs.python.org/3/library/unittest.html", {
        "virustotal": {"malicious": 0, "total": 90},
        "urlhaus": {"urlhaus_status": "none"}
    })
    assert clean_url_res["breakdown"]["threat_taxonomy"]["details"] == "No adversary threat tags reported by threat feeds"
    assert len(clean_url_res["breakdown"]["structural_heuristics"]["checks_evaluated"]) >= 2

    phish_url_res = calculate_risk_score("url", "http://operator:session_auth@185.220.101.5:8080/stage2_payload.exe", {
        "virustotal": {
            "malicious": 45,
            "total": 90,
            "tags": ["phishing", "trojan"]
        },
        "urlhaus": {
            "urlhaus_status": "active",
            "threat": "malware_download",
            "tags": ["AgentTesla", "infostealer"]
        }
    })
    url_tax = phish_url_res["breakdown"]["threat_taxonomy"]
    assert any(t in url_tax["matched_tags"] for t in ["Stealer", "Trojan", "Phishing", "Malware Download"])
    assert url_tax["score"] >= 25.0
    url_heur = phish_url_res["breakdown"]["structural_heuristics"]
    assert len(url_heur["checks_evaluated"]) >= 2
    assert url_heur["score"] >= 6.0  # Embedded '@' + direct IP + .exe + anomalous port 8080
    assert any("Embedded '@'" in a for a in url_heur["anomalies"])
    assert any("Direct Executable" in a for a in url_heur["anomalies"])
    print(f"    - URL Telemetry: Clean URL benign Card 2/4; Phishing URL mapped to Stealer/Trojan ({url_tax['score']} pts) & Authority/Executable Heuristics ({url_heur['score']} pts): PASSED")

    # Card 2 & Card 4 IOC Type 4: Hash (Clean vs Confirmed LockBit Ransomware Sample)
    clean_hash_res = calculate_risk_score("hash", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", {
        "virustotal": {"malicious": 0, "total": 70},
        "malwarebazaar": {"confirmed": False}
    })
    assert clean_hash_res["breakdown"]["threat_taxonomy"]["details"] == "No adversary threat tags reported by threat feeds"
    assert clean_hash_res["breakdown"]["threat_taxonomy_score"] == 0.0
    assert len(clean_hash_res["breakdown"]["structural_heuristics"]["checks_evaluated"]) >= 2

    ransom_hash_res = calculate_risk_score("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", {
        "virustotal": {
            "malicious": 60,
            "total": 72,
            "popular_threat_classification": {"suggested_threat_label": "ransomware/lockbit"},
            "tags": ["ransomware", "encryptor"]
        },
        "malwarebazaar": {
            "confirmed": True,
            "signature": "LockBit",
            "file_type": "exe",
            "tags": ["ransomware", "LockBit 3.0"]
        },
        "overall_entropy": 7.6,
        "is_packed": True
    })
    hash_tax = ransom_hash_res["breakdown"]["threat_taxonomy"]
    assert "Ransomware" in hash_tax["matched_tags"]
    assert hash_tax["score"] == 30.0  # Critical ransomware tier
    hash_heur = ransom_hash_res["breakdown"]["structural_heuristics"]
    assert len(hash_heur["checks_evaluated"]) >= 2
    assert hash_heur["score"] >= 7.0  # EXE format + packed high entropy
    assert any("Executable Binary" in a for a in hash_heur["anomalies"])
    assert any("High Binary Entropy" in a for a in hash_heur["anomalies"])
    # Factor 3 Infrastructure Telemetry MUST strictly evaluate to 0.0 pts for file hashes
    hash_infra = ransom_hash_res["breakdown"]["infrastructure_telemetry"]
    assert hash_infra["score"] == 0.0
    assert hash_infra["network_type"] == "N/A (File Artifact)"
    assert hash_infra["asn"] == "N/A"
    print(f"    - Hash Telemetry: Clean Hash 0 pts; Ransomware Hash mapped to Ransomware ({hash_tax['score']} pts), Factor 3 Hash Infra strictly 0.0 pts & EXE/Packed Heuristics ({hash_heur['score']} pts): PASSED")

    # -------------------------------------------------------------------------
    # 3. Static Binary & PE Analyzer Verification
    # -------------------------------------------------------------------------
    print("\n[+] 3. Testing Static Binary Analyzer (static_analyzer.py):")

    # Shannon Entropy formula check
    # Low entropy: uniform bytes
    low_ent = calculate_shannon_entropy(b"\x00" * 1000)
    assert low_ent == 0.0

    # High entropy: randomized bytes
    random_bytes = os.urandom(2000)
    high_ent = calculate_shannon_entropy(random_bytes)
    assert high_ent > 7.0, f"Expected high entropy > 7.0, got {high_ent}"
    print(f"    - Shannon Entropy calculation (Uniform={low_ent}, Pseudo-Random={high_ent}): PASSED")

    # Strings and IOC Extraction with Assembly/Manifest Version Filtering
    test_blob = (
        b"MZ\x90\x00Some garbage binary code \x00\x01\x02"
        b"<assemblyIdentity version=\"1.0.0.0\" name=\"MyComponent\"/>"
        b"dependency version='6.0.0.0' or version=10.0.19041.1 or version=\"4.0.30319.1\" "
        b"raw version tag 2.0.0.0 and FileVersion: 1.0.0.0 "
        b"Contact C2 server at https://c2-beacon.darkweb.top/api/gate.php immediately. "
        b"Secondary backup IP address is 198.51.100.45 or port scan 203.0.113.19. "
        b"Also report to support@phish-domain.online\x00"
    )
    str_results = extract_strings_and_iocs(test_blob)
    extracted = str_results["extracted_iocs"]
    assert "https://c2-beacon.darkweb.top/api/gate.php" in extracted["urls"]
    assert "198.51.100.45" in extracted["ips"]
    assert "203.0.113.19" in extracted["ips"]
    # Ensure manifest/assembly version numbers were filtered out
    for false_ip in ["1.0.0.0", "6.0.0.0", "2.0.0.0", "10.0.19041.1", "4.0.30319.1"]:
        assert false_ip not in extracted["ips"], f"False positive version {false_ip} should have been filtered out"
    assert any("darkweb.top" in d for d in extracted["domains"])
    print(f"    - String & Public IOC extraction with version filtering (URLs={len(extracted['urls'])}, IPs={len(extracted['ips'])}, Domains={len(extracted['domains'])}): PASSED")

    # Safe In-Memory PE Parsing (Using notepad.exe or a generated PE buffer)
    sample_pe_path = r"C:\Windows\System32\notepad.exe"
    if os.path.exists(sample_pe_path):
        with open(sample_pe_path, "rb") as f:
            pe_bytes = f.read()
        pe_report = parse_pe_artifact(pe_bytes, filename="notepad.exe")
        assert pe_report["is_pe"] is True
        assert len(pe_report["sections"]) > 0
        assert "machine" in pe_report["headers"]
        assert "compilation_timestamp" in pe_report["headers"]
        assert 0.0 <= pe_report["static_risk_score"] <= 100.0
        assert pe_report["verdict"] in ("Low", "Medium", "High", "Critical")
        print(f"    - Safe in-memory PE parse (notepad.exe): Sections={len(pe_report['sections'])} RiskScore={pe_report['static_risk_score']}: PASSED")

    # Non-PE binary handling (Low entropy script)
    non_pe_report = parse_pe_artifact(b"#!/bin/bash\necho 'clean script'\n", filename="script.sh")
    assert non_pe_report["is_pe"] is False
    assert non_pe_report["pe_error"] is not None
    assert non_pe_report["overall_entropy"] < 7.2
    assert non_pe_report["is_packed_or_encrypted"] is False
    assert non_pe_report["static_risk_score"] < 20.0
    print("    - Non-PE low-entropy binary gracefully triaged without crash: PASSED")

    # Non-PE binary handling (High entropy >= 7.2 shellcode / packed payload)
    high_ent_payload = os.urandom(2048)
    high_ent_report = parse_pe_artifact(high_ent_payload, filename="payload.bin")
    assert high_ent_report["is_pe"] is False
    assert high_ent_report["overall_entropy"] >= 7.2
    assert high_ent_report["is_packed_or_encrypted"] is True
    assert any("PACKED / ENCRYPTED ARTIFACT" in p for p in high_ent_report["packing_indicators"])
    assert high_ent_report["static_risk_score"] >= 75.0, f"Expected static_risk_score >= 75.0, got {high_ent_report['static_risk_score']}"
    assert high_ent_report["verdict"] in ("High", "Critical")
    assert any(t["technique_id"] == "T1027.002" for t in high_ent_report["mitre_techniques"])
    print(f"    - High-entropy non-PE binary (Entropy={high_ent_report['overall_entropy']}) flagged as PACKED / ENCRYPTED (Score={high_ent_report['static_risk_score']}, Verdict={high_ent_report['verdict']}): PASSED")

    # -------------------------------------------------------------------------
    # 4. YARA Runner Verification
    # -------------------------------------------------------------------------
    print("\n[+] 4. Testing YARA Execution Engine (yara_runner.py):")

    # Baseline scan with mock packed header
    mock_upx = b"MZ\x90\x00\x03\x00\x00\x00UPX0\x00\x00\x00\x00UPX1\x00\x00\x00\x00UPX!"
    base_matches = scan_with_baseline(mock_upx)
    matched_rules = [m["rule_name"] for m in base_matches]
    assert "UPX_Packer_Signature" in matched_rules, f"Expected UPX rule match: {matched_rules}"
    assert len(base_matches[0]["strings"]) >= 2
    print(f"    - Baseline YARA scan matched [{matched_rules[0]}] with string offsets: PASSED")

    # Custom rule evaluation: valid matching rule
    custom_rule = """
    rule Custom_Shellcode_Stub {
        meta:
            author = "SOC Analyst"
        strings:
            $stub = "EVIL_PAYLOAD_HERE" ascii
        condition:
            $stub
    }
    """
    valid_res = scan_with_custom_rule(b"test buffer containing EVIL_PAYLOAD_HERE and stuff", custom_rule)
    assert valid_res["success"] is True
    assert valid_res["match_count"] == 1
    assert valid_res["matches"][0]["rule_name"] == "Custom_Shellcode_Stub"
    assert valid_res["matches"][0]["strings"][0]["offset"] == b"test buffer containing EVIL_PAYLOAD_HERE and stuff".find(b"EVIL_PAYLOAD_HERE")
    print("    - Custom YARA rule compiled and executed successfully (match found): PASSED")

    # Custom rule evaluation: syntax error isolation
    broken_rule = "rule Broken { condition: ??? }"
    broken_res = scan_with_custom_rule(b"some data", broken_rule)
    assert broken_res["success"] is False
    assert broken_res["error"] is not None
    assert "Syntax Error" in broken_res["error"] or "Compilation Error" in broken_res["error"]
    print("    - Custom YARA syntax error safely caught and isolated: PASSED")

    # -------------------------------------------------------------------------
    # 5. Integrated Endpoints Verification
    # -------------------------------------------------------------------------
    print("\n[+] 5. Testing Integrated API Endpoints (POST /api/analyze & /api/artifact/*):")

    # Setup User & Bearer Token
    USERS_DB.clear()
    reg = client.post("/api/auth/register", json={"username": "lead_hunter", "password": "Password789!"})
    assert reg.status_code == 201
    tok = client.post("/api/auth/login", json={"username": "lead_hunter", "password": "Password789!"}).json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {tok}"}

    # A. POST /api/analyze returns mitre_techniques & transparent score_breakdown
    an_res = client.post("/api/analyze", json={"ioc": "1.1.1.1"}, headers=auth_headers)
    assert an_res.status_code == 200, an_res.text
    an_data = an_res.json()
    assert "mitre_techniques" in an_data
    assert isinstance(an_data["mitre_techniques"], list)
    assert len(an_data["mitre_techniques"]) > 0
    assert "vendor_consensus" in an_data["score_breakdown"]
    assert "threat_taxonomy" in an_data["score_breakdown"]
    assert "infrastructure_telemetry" in an_data["score_breakdown"]
    assert "structural_heuristics" in an_data["score_breakdown"]
    # Legacy aliases
    assert "cross_vendor_consensus" in an_data["score_breakdown"]
    assert "reputation_confidence" in an_data["score_breakdown"]
    assert "external_engines" in an_data["score_breakdown"]
    assert "threat_category" in an_data["score_breakdown"]
    assert "confidence_prevalence" in an_data["score_breakdown"]
    assert "attribute_heuristics" in an_data["score_breakdown"]
    print(f"    - POST /api/analyze integrated: mitre_techniques={len(an_data['mitre_techniques'])}, 4 refactored factor cards present: PASSED")

    # B. POST /api/artifact/analyze with file upload
    test_binary = b"MZ" + b"\x90" * 200 + b"VirtualAllocEx\x00WriteProcessMemory\x00" + b"http://malware-drop.xyz/test.exe"
    files = {"file": ("malware_sample.exe", io.BytesIO(test_binary), "application/octet-stream")}
    art_res = client.post("/api/artifact/analyze", files=files, headers=auth_headers)
    assert art_res.status_code == 200, art_res.text
    art_data = art_res.json()
    assert art_data["filename"] == "malware_sample.exe"
    assert "hashes" in art_data
    assert "overall_entropy" in art_data
    assert "extracted_iocs" in art_data
    assert "yara_matches" in art_data
    assert "mitre_techniques" in art_data
    assert 0.0 <= art_data["static_risk_score"] <= 100.0
    print(f"    - POST /api/artifact/analyze returned complete static analysis report: PASSED")

    # C. POST /api/artifact/yara-test
    yara_files = {"file": ("sample.exe", io.BytesIO(test_binary), "application/octet-stream")}
    yara_data = {"rule": 'rule TestRule { strings: $a = "VirtualAllocEx" condition: $a }'}
    yt_res = client.post("/api/artifact/yara-test", files=yara_files, data=yara_data, headers=auth_headers)
    assert yt_res.status_code == 200, yt_res.text
    yt_json = yt_res.json()
    assert yt_json["success"] is True
    assert yt_json["match_count"] >= 1
    assert yt_json["matches"][0]["rule_name"] == "TestRule"
    print("    - POST /api/artifact/yara-test executed custom rule against uploaded file: PASSED")

    print("\n" + "=" * 65)
    print("[SUCCESS] ALL STAGE 4 AND STAGE 5 TESTS PASSED PERFECTLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_stage4_stage5_tests()
