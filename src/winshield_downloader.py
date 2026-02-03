"""
WinShield Downloader

Downloads a single missing Windows update package from the Microsoft Update Catalog
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup


# ============================================================
# PATHS
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))   
ROOT_DIR = os.path.dirname(SCRIPT_DIR)                    

RESULTS_DIR = os.path.join(ROOT_DIR, "results")
DOWNLOADS_DIR = os.path.join(ROOT_DIR, "downloads")

SCAN_RESULT_PATH = os.path.join(RESULTS_DIR, "winshield_scan_result.json")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)


# ============================================================
# MICROSOFT UPDATE CATALOG ENDPOINTS
# ============================================================

CATALOG_BASE = "https://www.catalog.update.microsoft.com"
SEARCH_URL = f"{CATALOG_BASE}/Search.aspx"
DOWNLOAD_DIALOG_URL = f"{CATALOG_BASE}/DownloadDialog.aspx"

DEFAULT_TIMEOUT = 30


# ============================================================
# MODELS
# ============================================================

# Data class for missing item
@dataclass(frozen=True)
class MissingKbItem:
    kb_id: str
    update_type: str

# Data class for catalog search candidate
@dataclass(frozen=True)
class CatalogCandidate:
    update_id: str
    title: str
    products: str
    classification: str
    last_updated: str
    version: str
    size: str

# Data class for baseline constraints
@dataclass(frozen=True)
class BaselineConstraints:
    windows_gen: str          
    display_version: str     
    build_major: str          
    catalog_arch: str         


# ============================================================
# IO HELPERS
# ============================================================

def load_scan_result(path: str) -> dict:
# Loads the scanner JSON result from disk

    if not os.path.isfile(path):
        raise RuntimeError(
            f"Scan result not found: {path}\n"
            "Run winshield_scanner.py first."
        )
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def safe_input(prompt: str) -> str:
# Reads operator input safely

    try:
        return input(prompt)
    except EOFError:
        return ""


# ============================================================
# BASELINE CONSTRAINT BUILDING
# ============================================================

def build_constraints(baseline: dict) -> BaselineConstraints:
# Converts baseline metadata into matching constraints used for candidate scoring

    os_name = str(baseline.get("OsName") or "")
    display_version = str(baseline.get("DisplayVersion") or "")
    arch = str(baseline.get("Architecture") or "")
    build = str(baseline.get("Build") or "")

    build_major = build.split(".", 1)[0] if build else ""

    os_lower = os_name.lower()
    if "windows 11" in os_lower:
        windows_gen = "windows 11"
    elif "windows 10" in os_lower:
        windows_gen = "windows 10"
    else:
        windows_gen = ""

    arch_lower = arch.lower()
    if arch_lower in ("x64", "amd64"):
        catalog_arch = "x64"
    elif "arm64" in arch_lower:
        catalog_arch = "arm64"
    elif arch_lower in ("x86", "32-bit"):
        catalog_arch = "x86"
    else:
        catalog_arch = "x64"

    return BaselineConstraints(
        windows_gen=windows_gen,
        display_version=display_version.strip(),
        build_major=build_major.strip(),
        catalog_arch=catalog_arch,
    )


# ============================================================
# HTTP HELPERS
# ============================================================

def build_session() -> requests.Session:
# Builds a session with stable headers

    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "winshield_downloader.py",
            "Accept-Language": "en-GB,en;q=0.9",
        }
    )
    return s


def fetch_text(session: requests.Session, url: str, params: dict | None = None) -> str:
# Fetches HTML content and raises on HTTP errors

    r = session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()
    return r.text


# ============================================================
# SCAN RESULT PARSING
# ============================================================

def build_missing_list(scan_result: dict) -> List[MissingKbItem]:
# Builds a display list of missing KBs with UpdateType labels

    missing_kbs: List[str] = scan_result.get("MissingKbs") or []
    kb_entries: List[dict] = scan_result.get("KbEntries") or []

    kb_index: Dict[str, dict] = {
        str(entry.get("KB")).upper(): entry
        for entry in kb_entries
        if entry.get("KB")
    }

    out: List[MissingKbItem] = []
    for kb in missing_kbs:
        kb_str = str(kb).strip().upper()
        if not kb_str:
            continue
        update_type = str(kb_index.get(kb_str, {}).get("UpdateType") or "Unknown")
        out.append(MissingKbItem(kb_id=kb_str, update_type=update_type))

    return out


# ============================================================
# CATALOG SEARCH PARSING
# ============================================================

def parse_search_candidates(html: str) -> List[CatalogCandidate]:
# Parses the Catalog results table into structured candidates

    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table", id="ctl00_catalogBody_updateMatches")
    if not table:
        return []

    candidates: List[CatalogCandidate] = []

    for tr in table.find_all("tr"):
        tr_id = (tr.get("id") or "").strip()
        if "_R" not in tr_id:
            continue

        update_id = tr_id.split("_R", 1)[0].strip()
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", update_id):
            continue

        tds = tr.find_all("td")
        if len(tds) < 8:
            continue

        candidates.append(
            CatalogCandidate(
                update_id=update_id,
                title=tds[1].get_text(" ", strip=True),
                products=tds[2].get_text(" ", strip=True),
                classification=tds[3].get_text(" ", strip=True),
                last_updated=tds[4].get_text(" ", strip=True),
                version=tds[5].get_text(" ", strip=True),
                size=tds[6].get_text(" ", strip=True),
            )
        )

    return candidates


# ============================================================
# CANDIDATE SCORING AND SELECTION
# ============================================================

def score_candidate(candidate: CatalogCandidate, kb_id: str, c: BaselineConstraints) -> int:
# Candidate scoring function based on baseline constraints
    
    t = candidate.title.lower()
    score = 0

    # KB token must be present
    if kb_id.lower() not in t:
        return -10_000
    score += 50

    # Windows generation match 
    if c.windows_gen:
        if c.windows_gen in t:
            score += 40
        if c.windows_gen == "windows 10" and "windows 11" in t:
            return -10_000
        if c.windows_gen == "windows 11" and "windows 10" in t:
            return -10_000

    # Client baseline should not pull Server packages
    if c.windows_gen.startswith("windows ") and "server" in t:
        return -10_000

    # Architecture is treated as required
    if c.catalog_arch == "x64":
        if "arm64-based" in t or "x86-based" in t or "32-bit" in t:
            return -10_000
        if "x64-based" in t:
            score += 25

    elif c.catalog_arch == "arm64":
        if "x64-based" in t or "x86-based" in t or "32-bit" in t:
            return -10_000
        if "arm64-based" in t:
            score += 25

    elif c.catalog_arch == "x86":
        if "x64-based" in t or "arm64-based" in t:
            return -10_000
        if "x86-based" in t or "32-bit" in t:
            score += 25

    # DisplayVersion is optional
    dv = c.display_version.lower().strip()
    if dv:
        if dv in t:
            score += 25
        # Penalise if the title explicitly contains another token
        if re.search(r"\b\d{2}h[12]\b", t) and dv not in t:
            score -= 15

    # Build major is optional
    if c.build_major:
        m = re.search(r"\(\s*(\d{5})\.", t)
        if m:
            score += 10 if m.group(1) == c.build_major else -5

    return score


def choose_best_candidate(candidates: List[CatalogCandidate], kb_id: str, constraints: BaselineConstraints) -> Tuple[Optional[CatalogCandidate], Optional[str]]:
# Selects the best candidate and enforces a minimum confidence threshold

    scored: List[Tuple[int, CatalogCandidate]] = []
    for cand in candidates:
        s = score_candidate(cand, kb_id, constraints)
        if s >= 0:
            scored.append((s, cand))

    if not scored:
        return None, "No candidate matched baseline constraints."

    scored.sort(key=lambda x: x[0], reverse=True)
    best_score, best = scored[0]

    # Guardrail to avoid mismatch
    if best_score < 90:
        return None, f"Ambiguous match (best score {best_score} below threshold)."

    return best, None


# ============================================================
# DOWNLOAD DIALOG RESOLUTION
# ============================================================

def build_dialog_params(update_id: str) -> dict:
# The DownloadDialog endpoint expects a JSON array in the updateIDs query param

    payload = f'[{{"size":0,"languages":"all","uidInfo":"{update_id}","updateID":"{update_id}"}}]'
    return {"updateIDs": payload}


def extract_download_urls(dialog_html: str) -> List[str]:
# Extracts direct .msu or .cab URLs from the DownloadDialog HTML

    urls: List[str] = []

    urls.extend(
        re.findall(
            r'href="(https?://[^"]+\.(?:msu|cab)(?:\?[^"]*)?)"',
            dialog_html,
            flags=re.IGNORECASE,
        )
    )

    urls.extend(
        re.findall(
            r"\.url\s*=\s*'(?P<url>https?://[^']+\.(?:msu|cab)(?:\?[^']*)?)'",
            dialog_html,
            flags=re.IGNORECASE,
        )
    )

    out: List[str] = []
    seen: set[str] = set()

    for u in urls:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)

    return out


def download_file(session: requests.Session, url: str, out_dir: str) -> str:
# Downloads the resolved package into downloads directory

    os.makedirs(out_dir, exist_ok=True)

    filename = url.split("/")[-1].split("?", 1)[0]
    out_path = os.path.join(out_dir, filename)

    with session.get(url, stream=True, timeout=DEFAULT_TIMEOUT) as r:
        r.raise_for_status()
        with open(out_path, "wb") as h:
            for chunk in r.iter_content(chunk_size=1024 * 256):
                if chunk:
                    h.write(chunk)

    return out_path


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    print("[*] Running winshield_downloader.py...")

    scan_result = load_scan_result(SCAN_RESULT_PATH)

    baseline = scan_result.get("Baseline") or {}
    constraints = build_constraints(baseline)

    missing_items = build_missing_list(scan_result)
    if not missing_items:
        print("[-] Nothing to download.")

    print("=== Missing KBs ===")
    for idx, item in enumerate(missing_items, start=1):
        print(f"{idx}) {item.kb_id} [{item.update_type}]")
    print()

    raw = safe_input("Select ONE KB: ").strip()
    if not raw.isdigit():
        print("[!] Selection must be a number.")
        return 1

    choice = int(raw)
    if choice < 1 or choice > len(missing_items):
        print("[!] Selection out of range.")
        return 1

    kb_id = missing_items[choice - 1].kb_id
    if not re.fullmatch(r"KB\d{6,8}", kb_id):
        print(f"[!] Invalid KB token: {kb_id}")
        return 1

    session = build_session()

    print(f"[*] Searching Microsoft Update Catalog for {kb_id} ...")
    search_html = fetch_text(session, SEARCH_URL, params={"q": kb_id})

    candidates = parse_search_candidates(search_html)
    if not candidates:
        print("[-] No candidates found.")
        return 1

    best, reason = choose_best_candidate(candidates, kb_id, constraints)
    if not best:
        print(f"[-] {reason}")
        print("    Candidates:")
        for idx, cand in enumerate(candidates, start=1):
            print(f"  {idx}) {cand.title} (UpdateID: {cand.update_id})")
        return 1

    print(f"[+] Selected: {best.title}")
    print(f"[*] Resolving download URL (UpdateID: {best.update_id}) ...")

    dialog_html = fetch_text(session, DOWNLOAD_DIALOG_URL, params=build_dialog_params(best.update_id))
    urls = extract_download_urls(dialog_html)
    if not urls:
        print("[-] No .msu or .cab URL found in download dialog HTML.")
        return 1

    chosen_url = urls[0]
    print(f"[+] URL: {chosen_url}")
    print(f"[*] Downloading into: {DOWNLOADS_DIR}...")

    out_path = download_file(session, chosen_url, DOWNLOADS_DIR)
    print(f"[+] Downloaded: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
