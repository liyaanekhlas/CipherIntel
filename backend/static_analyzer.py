"""
SentinelScope Binary & Static Artifact Analysis Module.

Provides safe in-memory inspection of untrusted files:
- PE header parsing and compilation timestamp extraction via pefile
- Shannon entropy calculation per section (flagging entropy > 7.0 as packed/encrypted)
- Virtual vs. raw size discrepancy calculation
- Import Address Table (IAT) inspection for high-risk injection, evasion, and system access APIs
- ASCII and UTF-16 string and public IOC extraction (IPv4, Domains, URLs)
- Static risk scoring and MITRE ATT&CK technique mapping
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import pefile

from backend.mitre_mapper import map_api_to_mitre, get_technique_details

# Categorized High-Risk Windows API Signatures
HIGH_RISK_APIS = {
    "memory_injection": {
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "VirtualProtect", "VirtualProtectEx",
        "QueueUserAPC", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"
    },
    "process_access": {
        "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "OpenProcess", "CreateProcessA", "CreateProcessW"
    },
    "evasion_hooking": {
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
    }
}

ALL_FLAGGED_APIS = (
    HIGH_RISK_APIS["memory_injection"]
    | HIGH_RISK_APIS["process_access"]
    | HIGH_RISK_APIS["evasion_hooking"]
)

# Known Packer Section Names
KNOWN_PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".fsg", ".themida", ".vmp", ".petite", ".nsp"}

# Regex for IPv4, Domain, and URL extraction from strings
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"'<>]*)?",
    re.IGNORECASE
)
DOMAIN_REGEX = re.compile(
    r"\b(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)

# Common non-domain extensions to ignore when scanning strings
IGNORED_DOMAIN_EXTENSIONS = {
    "exe", "dll", "pdb", "txt", "cpp", "c", "h", "hpp", "obj",
    "png", "jpg", "gif", "ico", "xml", "manifest", "wav", "mp3",
    "res", "def", "rc", "inf", "cat", "dat", "bin"
}


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon Entropy: H = -sum(p_i * log2(p_i))
    Scale: 0.0 (completely uniform/null) to 8.0 (completely random / compressed / encrypted).
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def extract_strings_and_iocs(file_bytes: bytes, min_len: int = 6) -> Dict[str, Any]:
    """
    Extracts printable ASCII and UTF-16 LE strings (>= min_len characters).
    Runs regex to locate public IPv4 addresses, domains, and URLs.
    """
    # 1. ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
    ascii_matches = [m.decode("ascii", errors="ignore") for m in ascii_pattern.findall(file_bytes)]

    # 2. UTF-16 LE strings
    utf16_pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}")
    utf16_matches = []
    for raw in utf16_pattern.findall(file_bytes):
        try:
            utf16_matches.append(raw.decode("utf-16le", errors="ignore"))
        except Exception:
            pass

    combined_strings = list(dict.fromkeys(ascii_matches + utf16_matches))

    # 3. Extract IOCs
    extracted_ips: Set[str] = set()
    extracted_urls: Set[str] = set()
    extracted_domains: Set[str] = set()

    # Search in all concatenated strings for comprehensive extraction
    corpus = "\n".join(combined_strings)

    # A. URLs
    for url in URL_REGEX.findall(corpus):
        clean_url = url.strip(".,;:)'\"")
        if clean_url:
            extracted_urls.add(clean_url)

    # B. IPv4s (ignore common assembly/manifest version numbers)
    for m in IPV4_REGEX.finditer(corpus):
        ip_str = m.group(0)

        # Skip candidate IPs ending in .0.0.0 (e.g. 1.0.0.0, 6.0.0.0, 10.0.0.0)
        if ip_str.endswith(".0.0.0"):
            continue

        # Skip candidate IPs preceded by version= (e.g. version="1.0.0.0", version=10.0.19041.1, assemblyVersion="...")
        prefix = corpus[max(0, m.start() - 35):m.start()]
        if re.search(r"(?:version|ver|assemblyVersion|fileVersion|productVersion)\s*[:=]\s*['\"]?$", prefix, re.IGNORECASE):
            continue

        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            # Filter out loopback, unspecified (0.0.0.0), broadcast, and link-local
            if not (ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local):
                # Public or notable internal
                extracted_ips.add(str(ip_obj))
        except Exception:
            pass

    # C. Domains
    for domain_match in DOMAIN_REGEX.findall(corpus):
        clean_domain = domain_match.lower().strip(".,;:)'\"")
        parts = clean_domain.split(".")
        tld = parts[-1]
        if tld not in IGNORED_DOMAIN_EXTENSIONS and len(tld) >= 2:
            # Exclude false positives from common Windows version tags
            if not re.match(r"^\d+\.\d+", clean_domain):
                extracted_domains.add(clean_domain)

    # Deduplicate against URLs
    for url in extracted_urls:
        for dom in list(extracted_domains):
            if dom in url:
                pass  # Keep in domains list for pivoting

    return {
        "total_strings_found": len(combined_strings),
        "sample_strings": combined_strings[:80],  # Return representative preview
        "extracted_iocs": {
            "ips": sorted(list(extracted_ips))[:50],
            "domains": sorted(list(extracted_domains))[:50],
            "urls": sorted(list(extracted_urls))[:50],
        }
    }


def parse_pe_artifact(file_bytes: bytes, filename: str = "sample.bin") -> Dict[str, Any]:
    """
    Safely parses an untrusted binary in-memory:
    - Parses PE headers using pefile with fast_load=True
    - Calculates section Shannon entropy and flags entropy > 7.0
    - Measures virtual vs raw size discrepancies
    - Inspects IAT for high-risk evasion and injection APIs
    - Extracts strings and public IOCs
    - Computes static risk score and associates MITRE techniques
    """
    file_size = len(file_bytes)
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha1_hash = hashlib.sha1(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    overall_entropy = calculate_shannon_entropy(file_bytes)

    # Extract strings and IOCs
    string_analysis = extract_strings_and_iocs(file_bytes)

    is_pe = True
    pe_error: Optional[str] = None
    headers_info: Dict[str, Any] = {}
    sections_info: List[Dict[str, Any]] = []
    imported_dlls: Dict[str, List[str]] = {}
    flagged_apis: List[Dict[str, Any]] = []
    packing_indicators: List[str] = []

    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        # Parse imports directory specifically
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass

        # 1. Header Information
        timestamp_int = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.fromtimestamp(timestamp_int, tz=timezone.utc).isoformat()
        except Exception:
            compile_time = f"Raw timestamp: {timestamp_int}"

        machine_type = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86" if pe.FILE_HEADER.Machine == 0x14C else hex(pe.FILE_HEADER.Machine)
        subsystem_id = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
        subsystem_map = {1: "Native", 2: "Windows GUI", 3: "Windows CUI (Console)", 7: "POSIX CUI"}
        subsystem_str = subsystem_map.get(subsystem_id, f"Subsystem {subsystem_id}")

        headers_info = {
            "machine": machine_type,
            "compilation_timestamp": compile_time,
            "raw_timestamp": timestamp_int,
            "entry_point": hex(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)),
            "image_base": hex(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "subsystem": subsystem_str,
        }

        # 2. Section Analysis & Entropy Calculation
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00").strip()
            if not sec_name:
                sec_name = "[unnamed]"

            raw_size = section.SizeOfRawData
            virt_size = section.Misc_VirtualSize
            sec_data = section.get_data()
            sec_entropy = calculate_shannon_entropy(sec_data)
            is_high_entropy = sec_entropy > 7.0

            # Virtual vs Raw Size Discrepancy
            discrepancy = abs(virt_size - raw_size)
            discrepancy_ratio = round((virt_size / raw_size), 2) if raw_size > 0 else (virt_size if virt_size > 0 else 0)

            # Check for packing heuristics per section
            sec_name_lower = sec_name.lower()
            if sec_name_lower in KNOWN_PACKER_SECTIONS or "upx" in sec_name_lower:
                packing_indicators.append(f"Packer section signature identified: {sec_name}")
            if raw_size == 0 and virt_size > 4096:
                packing_indicators.append(f"Uninitialized executable section with zero raw bytes: {sec_name}")
            if is_high_entropy:
                packing_indicators.append(f"Section {sec_name} exhibits high entropy ({sec_entropy} > 7.0), indicating packing/encryption")

            sections_info.append({
                "name": sec_name,
                "virtual_size": virt_size,
                "raw_size": raw_size,
                "size_discrepancy": discrepancy,
                "discrepancy_ratio": discrepancy_ratio,
                "entropy": sec_entropy,
                "is_high_entropy": is_high_entropy,
                "characteristics": hex(section.Characteristics),
            })

        # 3. Import Address Table (IAT) Inspection
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "Unknown.dll"
                dll_apis: List[str] = []

                for imp in entry.imports:
                    api_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
                    dll_apis.append(api_name)

                    # Check against high-risk API list
                    if api_name in ALL_FLAGGED_APIS:
                        # Determine category
                        category = "Generic Suspicious"
                        for cat_name, api_set in HIGH_RISK_APIS.items():
                            if api_name in api_set:
                                category = cat_name.replace("_", " ").title()
                                break

                        mitre_obj = map_api_to_mitre(api_name)
                        flagged_apis.append({
                            "api_name": api_name,
                            "dll": dll_name,
                            "category": category,
                            "mitre_technique": mitre_obj,
                        })

                imported_dlls[dll_name] = dll_apis

    except pefile.PEFormatError as pe_err:
        is_pe = False
        pe_error = f"Not a valid PE binary header ({str(pe_err)})"
    except Exception as exc:
        is_pe = False
        pe_error = f"PE Parsing Exception: {str(exc)}"

    # 4. Overall Entropy & Packaging Evaluation for All Binaries (PE & Non-PE)
    # Check overall file entropy: If overall_entropy >= 7.2, flag as PACKED / ENCRYPTED ARTIFACT,
    # raise the static risk score to High/Critical (75+ points).
    is_packed_or_encrypted = overall_entropy >= 7.2
    if is_packed_or_encrypted:
        packing_indicators.insert(
            0,
            f"PACKED / ENCRYPTED ARTIFACT: Overall file entropy is extremely high ({overall_entropy:.2f} >= 7.2 / 8.0), indicating strong compression, encryption, or packed shellcode.",
        )

    # 5. Static Risk Score Calculation & MITRE Technique Mapping
    # High entropy sections: +30
    # Suspicious APIs: +20 each, capped at 50
    # Packing indicators: +20
    static_score = 0.0
    has_high_entropy = any(sec["is_high_entropy"] for sec in sections_info) or (overall_entropy > 7.0)

    if has_high_entropy:
        static_score += 30.0

    api_points = min(50.0, len(flagged_apis) * 20.0)
    static_score += api_points

    if len(packing_indicators) > 0:
        static_score += 20.0

    # Overall entropy >= 7.2 guarantees a High/Critical static risk score (75+ points)
    if is_packed_or_encrypted:
        static_score = max(static_score, 75.0)

    clamped_static_score = max(0.0, min(100.0, round(static_score, 1)))

    if clamped_static_score < 20.0:
        verdict = "Low"
    elif clamped_static_score < 60.0:
        verdict = "Medium"
    elif clamped_static_score < 85.0:
        verdict = "High"
    else:
        verdict = "Critical"

    # Compile unified MITRE techniques list
    mapped_mitre: List[Dict[str, Any]] = []
    seen_techniques: Set[str] = set()

    for item in flagged_apis:
        m = item.get("mitre_technique")
        if m and m["technique_id"] not in seen_techniques:
            seen_techniques.add(m["technique_id"])
            mapped_mitre.append(m)

    if has_high_entropy or len(packing_indicators) > 0 or is_packed_or_encrypted:
        if "T1027.002" not in seen_techniques:
            seen_techniques.add("T1027.002")
            pack_tech = get_technique_details("T1027.002")
            if pack_tech:
                mapped_mitre.append({
                    "technique_id": pack_tech["technique_id"],
                    "technique_name": pack_tech["technique_name"],
                    "tactic": pack_tech["tactic"],
                    "reason": f"Artifact exhibits high entropy ({overall_entropy:.2f} / 8.0) or packing indicators indicative of encryption, compression, or packed shellcode.",
                })

    return {
        "filename": filename,
        "file_size": file_size,
        "hashes": {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
        },
        "is_pe": is_pe,
        "pe_error": pe_error,
        "headers": headers_info,
        "sections": sections_info,
        "overall_entropy": overall_entropy,
        "has_high_entropy": has_high_entropy,
        "is_packed_or_encrypted": is_packed_or_encrypted,
        "is_packed": is_packed_or_encrypted or len(packing_indicators) > 0,
        "packing_indicators": list(dict.fromkeys(packing_indicators)),
        "flagged_apis": flagged_apis,
        "total_flagged_apis": len(flagged_apis),
        "imported_dlls_count": len(imported_dlls),
        "imported_dlls_summary": {dll: len(apis) for dll, apis in imported_dlls.items()},
        "extracted_iocs": string_analysis["extracted_iocs"],
        "total_strings_extracted": string_analysis["total_strings_found"],
        "sample_strings": string_analysis["sample_strings"][:40],
        "static_risk_score": clamped_static_score,
        "verdict": verdict,
        "mitre_techniques": mapped_mitre,
    }
