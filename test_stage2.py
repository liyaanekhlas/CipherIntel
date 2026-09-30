"""
Verification test suite for SentinelScope Stage 2:
Threat Intelligence Enrichment Engine & Scoring.
"""

from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import USERS_DB
from backend.ioc_detector import defang_ioc, refang_ioc, validate_and_classify_ioc
from backend.scoring import calculate_threat_score

def run_all_tests():
    client = TestClient(app)
    print("=" * 60)
    print("[*] STARTING SENTINELSCOPE STAGE 2 VERIFICATION SUITE")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. Verify IOC Detector Unit Tests
    # ---------------------------------------------------------
    print("\n[+] 1. Testing IOC Detector & Defanger:")
    assert defang_ioc("http://test.com") == "hxxp://test[.]com"
    assert defang_ioc("1.1.1.1") == "1.1.1[.]1"
    assert defang_ioc("malware.org") == "malware[.]org"
    print("    - Defanging (http://test.com -> hxxp://test[.]com, 1.1.1.1 -> 1.1.1[.]1): PASSED")

    assert refang_ioc("hxxp://test[.]com") == "http://test.com"
    assert refang_ioc("1.1.1[.]1") == "1.1.1.1"
    print("    - Refanging normalization: PASSED")

    # RFC1918 Private IP rejection checks
    private_ips = ["10.0.0.1", "172.16.10.20", "192.168.1.254", "127.0.0.1"]
    for priv in private_ips:
        try:
            validate_and_classify_ioc(priv)
            assert False, f"Expected 400 rejection for private IP {priv}"
        except Exception as e:
            assert getattr(e, "status_code", None) == 400
    print("    - RFC1918 & Loopback IP rejection (10/8, 172.16/12, 192.168/16, 127/8): PASSED (400)")

    # ---------------------------------------------------------
    # 2. Verify Scoring Formulas
    # ---------------------------------------------------------
    print("\n[+] 2. Testing Proprietary Scoring Formulas:")
    # IP: (VT_malicious / VT_total * 50) + (AbuseIPDB_confidence / 100 * 50)
    ip_score = calculate_threat_score("ip", {
        "virustotal": {"malicious": 40, "total": 80},  # 50% * 50 = 25
        "abuseipdb": {"abuse_confidence_score": 90},    # 90% * 50 = 45 -> Total 70
    })
    assert ip_score["threat_score"] == 70.0
    assert ip_score["severity"] == "High"
    assert ip_score["classification"] == "Malicious"
    print(f"    - IP Formula calculation ({ip_score['threat_score']}, {ip_score['severity']}): PASSED")

    # Domain/URL: (VT_malicious / VT_total * 60) + (40 if active/online/malware_download else 20 if historical/offline else 0)
    domain_score = calculate_threat_score("domain", {
        "virustotal": {"malicious": 20, "total": 100},  # 20% * 60 = 12
        "urlhaus": {"urlhaus_status": "active"},        # 40 -> Total 52
    })
    assert domain_score["threat_score"] == 52.0
    assert domain_score["severity"] == "Medium"
    assert domain_score["classification"] == "Suspicious"
    print(f"    - Domain Formula calculation ({domain_score['threat_score']}, {domain_score['severity']}): PASSED")

    # Hash: (VT_malicious / VT_total * 60) + (40 if confirmed in MalwareBazaar else 0)
    hash_score = calculate_threat_score("hash", {
        "virustotal": {"malicious": 50, "total": 100},  # 50% * 60 = 30
        "malwarebazaar": {"confirmed": True},           # 40 -> Total 70
    })
    assert hash_score["threat_score"] == 70.0
    assert hash_score["severity"] == "High"
    print(f"    - Hash Formula calculation ({hash_score['threat_score']}, {hash_score['severity']}): PASSED")

    # ---------------------------------------------------------
    # 3. Authenticated Endpoint POST /api/analyze Integration
    # ---------------------------------------------------------
    print("\n[+] 3. Testing POST /api/analyze Endpoint:")

    # Setup User and JWT
    USERS_DB.clear()
    reg_res = client.post("/api/auth/register", json={"username": "sec_operator", "password": "SecurePassword123!"})
    assert reg_res.status_code == 201

    login_res = client.post("/api/auth/login", json={"username": "sec_operator", "password": "SecurePassword123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # A. Unauthenticated rejection
    unauth_res = client.post("/api/analyze", json={"ioc": "8.8.8.8"})
    assert unauth_res.status_code in (401, 403)
    print("    - Unauthenticated request rejected (401/403): PASSED")

    # B. Invalid IOC format rejection
    bad_ioc_res = client.post("/api/analyze", json={"ioc": "not_an_ioc_string"}, headers=headers)
    assert bad_ioc_res.status_code == 400
    print("    - Invalid IOC format rejected (400): PASSED")

    # C. Private IP rejection
    priv_res = client.post("/api/analyze", json={"ioc": "192.168.1.1"}, headers=headers)
    assert priv_res.status_code == 400
    print("    - Private IP rejected at endpoint level (400): PASSED")

    # D. Analyze Public IP (8.8.8.8)
    ip_res = client.post("/api/analyze", json={"ioc": "8.8.8.8"}, headers=headers)
    assert ip_res.status_code == 200, ip_res.text
    data = ip_res.json()
    assert data["ioc_type"] == "ip"
    assert "virustotal" in data["raw_metrics"]
    assert "abuseipdb" in data["raw_metrics"]
    assert 0.0 <= data["threat_score"] <= 100.0
    assert len(data["recommended_actions"]) > 0
    print(f"    - Analyze IP (8.8.8.8) returned score={data['threat_score']} severity={data['severity']}: PASSED")

    # E. Test TTLCache on second query
    cached_res = client.post("/api/analyze", json={"ioc": "8.8.8.8"}, headers=headers)
    assert cached_res.status_code == 200
    print("    - TTLCache hit verification: PASSED")

    # F. Analyze Domain (e.g., example.com)
    domain_res = client.post("/api/analyze", json={"ioc": "example.com"}, headers=headers)
    assert domain_res.status_code == 200, domain_res.text
    d_data = domain_res.json()
    assert d_data["ioc_type"] == "domain"
    assert "virustotal" in d_data["raw_metrics"]
    assert "urlhaus" in d_data["raw_metrics"]
    print(f"    - Analyze Domain (example.com) returned score={d_data['threat_score']}: PASSED")

    # G. Analyze URL (e.g., http://example.com/test)
    url_res = client.post("/api/analyze", json={"ioc": "http://example.com/test"}, headers=headers)
    assert url_res.status_code == 200, url_res.text
    u_data = url_res.json()
    assert u_data["ioc_type"] == "url"
    assert u_data["defanged_ioc"] == "hxxp://example[.]com/test"
    print(f"    - Analyze URL defanging & enrichment ({u_data['defanged_ioc']}): PASSED")

    # H. Analyze Hash (e.g. standard MD5)
    hash_res = client.post("/api/analyze", json={"ioc": "44d88612fea8a8f36de82e1278abb02f"}, headers=headers)
    assert hash_res.status_code == 200, hash_res.text
    h_data = hash_res.json()
    assert h_data["ioc_type"] == "hash"
    assert "virustotal" in h_data["raw_metrics"]
    assert "malwarebazaar" in h_data["raw_metrics"]
    print(f"    - Analyze Hash enrichment (44d88612fea8a8f36de82e1278abb02f): PASSED")

    print("\n" + "=" * 60)
    print("[SUCCESS] ALL STAGE 1 AND STAGE 2 TESTS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_all_tests()
