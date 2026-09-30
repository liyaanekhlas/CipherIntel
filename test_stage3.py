"""
Verification test suite for SentinelScope Stage 3:
Rolling Recent Searches History (Strictly 2 items).
"""

from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import USERS_DB
from backend.history import SEARCH_HISTORY

def run_stage3_tests():
    client = TestClient(app)
    print("=" * 60)
    print("[*] STARTING SENTINELSCOPE STAGE 3 VERIFICATION SUITE")
    print("=" * 60)

    # Clean in-memory storage for clean test
    USERS_DB.clear()
    SEARCH_HISTORY.clear()

    # 1. Register and Login User A
    reg_a = client.post("/api/auth/register", json={"username": "analyst_a", "password": "PasswordA123!"})
    assert reg_a.status_code == 201
    tok_a = client.post("/api/auth/login", json={"username": "analyst_a", "password": "PasswordA123!"}).json()["access_token"]
    headers_a = {"Authorization": f"Bearer {tok_a}"}

    # 2. Register and Login User B (for user isolation test)
    reg_b = client.post("/api/auth/register", json={"username": "analyst_b", "password": "PasswordB123!"})
    assert reg_b.status_code == 201
    tok_b = client.post("/api/auth/login", json={"username": "analyst_b", "password": "PasswordB123!"}).json()["access_token"]
    headers_b = {"Authorization": f"Bearer {tok_b}"}

    # 3. Test unauthenticated GET /api/history
    unauth = client.get("/api/history")
    assert unauth.status_code in (401, 403), f"Expected 401/403 for unauth history: {unauth.status_code}"
    print("[+] 1. Unauthenticated GET /api/history rejected (401/403): PASSED")

    # 4. Test initial empty history for User A
    hist_a0 = client.get("/api/history", headers=headers_a)
    assert hist_a0.status_code == 200
    assert hist_a0.json() == []
    print("[+] 2. Initial empty history for new user returns []: PASSED")

    # 5. Query 1st IOC for User A: 8.8.8.8
    res1 = client.post("/api/analyze", json={"ioc": "8.8.8.8"}, headers=headers_a)
    assert res1.status_code == 200

    hist_a1 = client.get("/api/history", headers=headers_a).json()
    assert len(hist_a1) == 1
    assert hist_a1[0]["ioc"] == "8.8.8.8"
    assert hist_a1[0]["ioc_type"] == "ip"
    assert "searched_at" in hist_a1[0]
    print(f"[+] 3. 1st query recorded in history (length={len(hist_a1)}): PASSED")

    # 6. Query 2nd IOC for User A: example.com
    res2 = client.post("/api/analyze", json={"ioc": "example.com"}, headers=headers_a)
    assert res2.status_code == 200

    hist_a2 = client.get("/api/history", headers=headers_a).json()
    assert len(hist_a2) == 2
    # Verify newest query is at index 0
    assert hist_a2[0]["ioc"] == "example.com"
    assert hist_a2[1]["ioc"] == "8.8.8.8"
    print(f"[+] 4. 2nd query prepended to history (length={len(hist_a2)}, newest at index 0): PASSED")

    # 7. Query 3rd IOC for User A: http://test.com
    res3 = client.post("/api/analyze", json={"ioc": "http://test.com"}, headers=headers_a)
    assert res3.status_code == 200

    hist_a3 = client.get("/api/history", headers=headers_a).json()
    # Strictly capped at 2 items!
    assert len(hist_a3) == 2, f"History length should be strictly 2, got {len(hist_a3)}"
    assert hist_a3[0]["ioc"] == "http://test.com"
    assert hist_a3[0]["defanged_ioc"] == "hxxp://test[.]com"
    assert hist_a3[1]["ioc"] == "example.com"
    # Oldest (8.8.8.8) was dropped
    assert all(item["ioc"] != "8.8.8.8" for item in hist_a3)
    print(f"[+] 5. 3rd query capped history strictly to 2 most recent items: PASSED")

    # 8. User isolation check: User B history must still be empty
    hist_b0 = client.get("/api/history", headers=headers_b).json()
    assert hist_b0 == [], f"User B history should be empty, got {hist_b0}"

    # Query 1 IOC for User B: 1.1.1.1
    res_b = client.post("/api/analyze", json={"ioc": "1.1.1.1"}, headers=headers_b)
    assert res_b.status_code == 200

    hist_b1 = client.get("/api/history", headers=headers_b).json()
    assert len(hist_b1) == 1
    assert hist_b1[0]["ioc"] == "1.1.1.1"

    # User A history must still have its 2 items unaffected
    hist_a_final = client.get("/api/history", headers=headers_a).json()
    assert len(hist_a_final) == 2
    assert hist_a_final[0]["ioc"] == "http://test.com"
    print("[+] 6. Per-user in-memory search history isolation: PASSED")

    print("\n" + "=" * 60)
    print("[SUCCESS] ALL STAGE 3 TESTS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_stage3_tests()
