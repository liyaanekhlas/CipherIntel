"""
Verification tests for SentinelScope Stage 1 Authentication.
Run directly with: python test_auth.py
"""

from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import USERS_DB

def run_tests():
    client = TestClient(app)
    print("[*] Running SentinelScope Auth Verification Suite...")

    # Clear USERS_DB for clean test run
    USERS_DB.clear()

    # 1. Health check
    r = client.get("/")
    assert r.status_code == 200, f"Root endpoint failed: {r.status_code}"
    print("  [+] Health check endpoint GET /: OK")

    # 2. Register valid user
    payload = {"username": "sentinel_admin", "password": "SuperSecretPassword123!"}
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 201, f"Registration failed: {r.status_code} {r.text}"
    assert r.json().get("username") == "sentinel_admin"
    assert "sentinel_admin" in USERS_DB
    assert USERS_DB["sentinel_admin"]["hashed_password"] != "SuperSecretPassword123!"
    print("  [+] Registration POST /api/auth/register: OK (In-memory hashed password stored)")

    # 3. Prevent duplicate registration
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 400, f"Duplicate registration check failed: {r.status_code}"
    print("  [+] Duplicate registration rejection: OK (Returned 400 Bad Request)")

    # 4. Reject invalid login credentials
    bad_login = {"username": "sentinel_admin", "password": "WrongPassword!"}
    r = client.post("/api/auth/login", json=bad_login)
    assert r.status_code == 401, f"Invalid login check failed: {r.status_code}"
    print("  [+] Invalid credentials rejection: OK (Returned 401 Unauthorized)")

    # 5. Successful login & JWT token generation
    r = client.post("/api/auth/login", json=payload)
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    data = r.json()
    token = data.get("access_token")
    assert token is not None and data.get("token_type") == "bearer"
    print("  [+] Login POST /api/auth/login: OK (Generated Bearer JWT token)")

    # 6. Reject unauthenticated access to /api/auth/me
    r = client.get("/api/auth/me")
    assert r.status_code in (401, 403), f"Protected endpoint access failed: {r.status_code}"
    print("  [+] Protected endpoint rejection without token: OK (Returned 401/403)")

    # 7. Authenticated access to /api/auth/me
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/auth/me", headers=headers)
    assert r.status_code == 200, f"Failed accessing protected me: {r.status_code} {r.text}"
    assert r.json().get("username") == "sentinel_admin"
    print("  [+] Protected profile GET /api/auth/me: OK (Validated user 'sentinel_admin')")

    print("\n[SUCCESS] All Stage 1 tests passed successfully!")

if __name__ == "__main__":
    run_tests()
