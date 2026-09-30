"""
CipherIntel - Threat Intelligence & IOC Enrichment Platform
Stage 1: In-Memory User Registration, Login, and JWT Token Verification.
Stage 2: Threat Intelligence Dual-Source Enrichment Engine & Scoring.
Stage 3: Rolling Recent Searches History (strictly 2 most recent searches).
Stage 4: Contextual Multi-Factor Risk Engine & MITRE ATT&CK Mapping.
Stage 5: Binary & Static Artifact Analysis Module (PE, Entropy, IAT, YARA).
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.auth import (
    USERS_DB,
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)
from backend.ioc_detector import validate_and_classify_ioc
from backend.enrichment import enrich_ioc
from backend.scoring import calculate_threat_score
from backend.history import SEARCH_HISTORY
from backend.mitre_mapper import map_ioc_to_mitre
from backend.risk_engine import calculate_risk_score
from backend.static_analyzer import parse_pe_artifact
from backend.yara_runner import scan_with_baseline, scan_with_custom_rule

# FastAPI Application Instance
app = FastAPI(
    title="CipherIntel API",
    description="CipherIntel Threat Intelligence & Analysis Platform",
    version="3.5.0",
)

# CORS middleware configured for local frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "*",  # Local development fallback
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend directory for direct dashboard access
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/dashboard", StaticFiles(directory=frontend_dir, html=True), name="frontend")


# Pydantic Schemas - Authentication
class AuthRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="User username")
    password: str = Field(..., min_length=6, max_length=128, description="User password")


class RegisterResponse(BaseModel):
    message: str
    username: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserProfileResponse(BaseModel):
    username: str
    created_at: Optional[str] = None


# Pydantic Schemas - Threat Intelligence
class AnalyzeRequest(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=1000, description="Indicator to analyze (IP, Domain, URL, or Hash)")


class AnalyzeResponse(BaseModel):
    original_ioc: str
    defanged_ioc: str
    ioc_type: str
    threat_score: float
    severity: str
    classification: str
    score_breakdown: Dict[str, Any]
    raw_metrics: Dict[str, Any]
    recommended_actions: List[str]
    mitre_techniques: List[Dict[str, Any]] = []
    verdict: Optional[str] = None


# Pydantic Schemas - Search History
class SearchHistoryItem(BaseModel):
    ioc: str
    defanged_ioc: str
    ioc_type: str
    threat_score: float
    severity: str
    searched_at: str


@app.get("/", tags=["Health"])
async def health_check():
    """Health check endpoint confirming CipherIntel service is operational."""
    return {
        "service": "CipherIntel Threat Intelligence Platform",
        "status": "operational",
        "version": "3.5.0",
        "modules": [
            "IOC Dual Enrichment",
            "Contextual Risk Scoring Engine",
            "MITRE ATT&CK Matrix",
            "Static Binary & PE Analysis",
            "YARA Signature Studio",
        ],
    }


@app.post(
    "/api/auth/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
async def register(user_data: AuthRequest):
    """
    Registers a new user in the in-memory USERS_DB dictionary.
    Rejects duplicate usernames and securely hashes the password with bcrypt.
    """
    username = user_data.username.strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username cannot be empty",
        )

    if username in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    hashed_pw = hash_password(user_data.password)
    created_timestamp = datetime.now(timezone.utc).isoformat()
    USERS_DB[username] = {
        "hashed_password": hashed_pw,
        "created_at": created_timestamp,
    }

    return RegisterResponse(
        message="User registered successfully",
        username=username,
    )


@app.post(
    "/api/auth/login",
    response_model=TokenResponse,
    tags=["Authentication"],
)
async def login(credentials: AuthRequest):
    """
    Validates user credentials against in-memory USERS_DB and returns a signed JWT access token.
    """
    username = credentials.username.strip()
    user_record = USERS_DB.get(username)

    if not user_record or not verify_password(credentials.password, user_record["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": username})
    return TokenResponse(access_token=access_token, token_type="bearer")


@app.get(
    "/api/auth/me",
    response_model=UserProfileResponse,
    tags=["Authentication"],
)
async def get_me(current_user: str = Depends(get_current_user)):
    """
    Protected endpoint that validates the Bearer token and returns the current authenticated user's profile.
    """
    user_record = USERS_DB.get(current_user, {})
    return UserProfileResponse(
        username=current_user,
        created_at=user_record.get("created_at"),
    )


@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
    tags=["Threat Intelligence"],
)
async def analyze_indicator(
    request: AnalyzeRequest,
    current_user: str = Depends(get_current_user),
):
    """
    Protected threat intelligence analysis endpoint.
    1. Validates and classifies indicator ('ip', 'domain', 'url', 'hash').
    2. Rejects private/RFC1918 IPs with HTTP 400.
    3. Concurrently queries dual threat intelligence sources via asyncio.gather.
    4. Evaluates multi-factor contextual risk scoring and proprietary formulas.
    5. Maps telemetry to MITRE ATT&CK Enterprise tactics and techniques.
    6. Prepends search record to user's history and strictly retains up to 2 recent items.
    """
    raw_input = request.ioc.strip()
    ioc_type, refanged_ioc, defanged_ioc = validate_and_classify_ioc(raw_input)

    if ioc_type == "invalid":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid indicator format. Must be a valid IPv4 address, domain name, "
                "URL (http/https), or file hash (MD5 or SHA256)."
            ),
        )

    # Concurrently enrich IOC using dual APIs
    raw_metrics = await enrich_ioc(ioc_type, refanged_ioc)

    # Compute baseline threat score & SOC checklist
    score_results = calculate_threat_score(ioc_type, raw_metrics)

    # Compute multi-factor contextual risk score via SOC Corroboration Engine
    risk_results = calculate_risk_score(ioc_type, refanged_ioc, raw_metrics)

    # Clean override enforcement
    final_threat_score = score_results["threat_score"]
    final_severity = score_results["severity"]
    final_classification = score_results["classification"]
    if risk_results.get("is_clean_override"):
        final_threat_score = 0.0
        final_severity = "Low"
        final_classification = "Clean"

    # Map IOC telemetry to MITRE ATT&CK Enterprise techniques
    mitre_techs = map_ioc_to_mitre(
        ioc_type=ioc_type,
        raw_metrics=raw_metrics,
        threat_score=final_threat_score,
        severity=final_severity,
    )

    # Combine transparent breakdown for full UI visual meter & legacy compatibility
    combined_breakdown = {
        # Refactored 4-Card Engineered Intelligence Factors (35%, 30%, 25%, 10%)
        "vendor_consensus": risk_results["breakdown"]["vendor_consensus_score"],
        "threat_taxonomy": risk_results["breakdown"]["threat_taxonomy_score"],
        "infrastructure_telemetry": risk_results["breakdown"]["infrastructure_telemetry_score"],
        "structural_heuristics": risk_results["breakdown"]["structural_heuristics_score"],
        # Backward compatibility factor keys
        "cross_vendor_consensus": risk_results["breakdown"]["vendor_consensus_score"],
        "reputation_confidence": risk_results["breakdown"]["infrastructure_telemetry_score"],
        "external_engines": risk_results["breakdown"]["vendor_consensus_score"],
        "threat_category": risk_results["breakdown"]["threat_taxonomy_score"],
        "confidence_prevalence": risk_results["breakdown"]["infrastructure_telemetry_score"],
        "attribute_heuristics": risk_results["breakdown"]["structural_heuristics_score"],
        "factors": risk_results["breakdown"],
        # Legacy components
        "virustotal_component": score_results["score_breakdown"].get("virustotal_component", 0.0),
        "abuseipdb_component": score_results["score_breakdown"].get("abuseipdb_component", 0.0),
        "urlhaus_component": score_results["score_breakdown"].get("urlhaus_component", 0.0),
        "malwarebazaar_component": score_results["score_breakdown"].get("malwarebazaar_component", 0.0),
        "vendor2_component": round(
            risk_results["breakdown"]["threat_taxonomy_score"] + risk_results["breakdown"]["infrastructure_telemetry_score"], 1
        ),
    }

    # Record search in rolling history (strictly keep up to 2 most recent)
    search_record = {
        "ioc": raw_input,
        "defanged_ioc": defanged_ioc,
        "ioc_type": ioc_type,
        "threat_score": final_threat_score,
        "severity": final_severity,
        "searched_at": datetime.now(timezone.utc).isoformat(),
    }
    if current_user not in SEARCH_HISTORY:
        SEARCH_HISTORY[current_user] = []
    SEARCH_HISTORY[current_user].insert(0, search_record)
    SEARCH_HISTORY[current_user] = SEARCH_HISTORY[current_user][:2]

    return AnalyzeResponse(
        original_ioc=raw_input,
        defanged_ioc=defanged_ioc,
        ioc_type=ioc_type,
        threat_score=final_threat_score,
        severity=final_severity,
        classification=final_classification,
        score_breakdown=combined_breakdown,
        raw_metrics=raw_metrics,
        recommended_actions=score_results["recommended_actions"],
        mitre_techniques=mitre_techs,
        verdict=risk_results.get("verdict"),
    )


@app.get(
    "/api/history",
    response_model=List[SearchHistoryItem],
    tags=["History"],
)
async def get_history(current_user: str = Depends(get_current_user)):
    """
    Protected endpoint that returns strictly the list of up to 2 most recent searches
    for the authenticated user.
    """
    user_history = SEARCH_HISTORY.get(current_user, [])
    return user_history[:2]


# ==============================================================================
# Task 2: Binary & Static Artifact Analysis Module Endpoints
# ==============================================================================

@app.post(
    "/api/artifact/analyze",
    tags=["Static Artifact Analysis"],
)
async def analyze_artifact(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user),
):
    """
    Safely parses an untrusted uploaded executable/binary in-memory:
    - Extracts PE headers, sections, timestamp, machine architecture
    - Computes Shannon entropy per section (flagging > 7.0 as packed/encrypted)
    - Checks raw vs virtual size discrepancies
    - Inspects IAT for high-risk evasion, injection, and system access APIs
    - Matches against baseline YARA ruleset
    - Extracts printable strings (ASCII/UTF-16) and public IOCs
    - Calculates static risk score and maps to MITRE ATT&CK techniques
    """
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # Perform safe in-memory static analysis
    report = parse_pe_artifact(file_bytes, filename=file.filename or "artifact.bin")

    # Perform baseline YARA scan
    yara_matches = scan_with_baseline(file_bytes)
    report["yara_matches"] = yara_matches

    # If YARA matched specific rules, enrich MITRE mapping if not already included
    for match in yara_matches:
        rule_meta = match.get("meta", {})
        technique_id = rule_meta.get("mitre_technique")
        if technique_id and not any(t["technique_id"] == technique_id for t in report["mitre_techniques"]):
            report["mitre_techniques"].append({
                "technique_id": technique_id,
                "technique_name": match["rule_name"].replace("_", " "),
                "tactic": rule_meta.get("threat_level", "Defense Evasion"),
                "reason": f"Baseline YARA rule [{match['rule_name']}] matched: {rule_meta.get('description', '')}",
            })

    return report


@app.post(
    "/api/artifact/yara-test",
    tags=["Static Artifact Analysis"],
)
async def test_yara_rule(
    file: UploadFile = File(...),
    rule: str = Form(...),
    current_user: str = Depends(get_current_user),
):
    """
    Compiles and matches a user-provided YARA rule string against the uploaded artifact.
    Safely isolates syntax errors and enforces evaluation timeout.
    """
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    result = scan_with_custom_rule(file_bytes, rule)
    return result
