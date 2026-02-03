"""
WinShield Scanner

Scans the local system for installed Windows updates and correlates them with the Microsoft Update Catalog.
"""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from typing import Dict, List, Set, Tuple


# ============================================================
# SCRIPT NAMES
# ============================================================

BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"


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
# POWERSHELL EXECUTION
# ============================================================

def run_powershell_script(script_name: str, extra_args: List[str] | None = None) -> dict:
# Run a PowerShell script and return its JSON output as a dict

    # If no extra_args provided, use empty list
    if extra_args is None:
        extra_args = []

    # Build full path to the .ps1 script
    script_path = os.path.join(SCRIPT_DIR, script_name)

    # Assemble PowerShell command
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", script_path,
        *extra_args,
    ]

    # Execute command and capture output
    result = subprocess.run(cmd, capture_output=True, text=True)


    # Abort if script failed
    if result.returncode != 0:
        raise RuntimeError(f"{script_name} failed")

    # Read and validate stdout
    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"{script_name} returned no output")

    # Parse JSON output
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc



# ============================================================
# MONTHID RANGE
# ============================================================

def build_month_ids_from_lcu(baseline: dict, max_months: int = 48) -> List[str]:
# Build a list of MonthIds from installed LcuMonthId up to MsrcLatestMonthId
    
    # Require admin baseline
    if not baseline.get("IsAdmin"):
        raise RuntimeError("Baseline collected without administrative privileges. LCU detection requires elevation.")

    # Starting month comes from installed LCU
    lcu_month_id = baseline.get("LcuMonthId")
    if not lcu_month_id:
        raise RuntimeError("Baseline did not provide LcuMonthId.")

    # Ending month is latest MSRC month or current month as fallback
    msrc_latest_month_id = baseline.get("MsrcLatestMonthId")
    if msrc_latest_month_id:
        end = datetime.strptime(msrc_latest_month_id, "%Y-%b").replace(day=1, tzinfo=UTC)
    else:
        end = datetime.now(UTC).replace(day=1)

    # Convert LCU month to datetime
    start = datetime.strptime(lcu_month_id, "%Y-%b").replace(day=1, tzinfo=UTC)

    # Ensure that start is not after end
    if start > end:
        start = end

    # Container for MonthIds
    month_ids: List[str] = []

    # Allow incrementing month and year
    year = start.year
    month = start.month

    # Iterate monthly from start to end
    while True:
        current = datetime(year, month, 1, tzinfo=UTC)
        if current > end:
            break
    
        # Add MonthId in MSRC format
        month_ids.append(current.strftime("%Y-%b"))

        # Stop at end month or safety cap
        if current == end or len(month_ids) >= max_months:
            break

        # Advance to next calendar month
        month += 1
        if month == 13:
            month = 1
            year += 1

    # Return a list of MonthIds
    return month_ids


def chunk_list(items: List[str], chunk_size: int) -> List[List[str]]:
    # Slice list into fixed-size chunks

    # Reduce adapter load
    return [
        items[i:i + chunk_size]
        for i in range(0, len(items), chunk_size)
    ]


# ============================================================
# KB ENTRY MERGE
# ============================================================

def merge_kb_entries(existing: Dict[str, dict], incoming: List[dict]) -> None:
# In-place merge adapter KB entries into an indexed structure
    
    # Iterate over each KB entry returned by the adapter
    for entry in incoming:
        # Extract the KB identifier
        kb_id = entry.get("KB")
        # Skip entries without a valid KB ID
        if not kb_id:
            continue

        # Initialise entry in existing map if not present
        if kb_id not in existing:
            existing[kb_id] = {
                "KB": kb_id,
                "Months": [],
                "Cves": [],
                "Supersedes": []
            }

        # Avoid duplicates when merging Months
        for month_id in (entry.get("Months") or []):
            if month_id and month_id not in existing[kb_id]["Months"]:
                existing[kb_id]["Months"].append(month_id)

        # Avoid duplicates when merging CVEs
        for cve in (entry.get("Cves") or []):
            if cve and cve not in existing[kb_id]["Cves"]:
                existing[kb_id]["Cves"].append(cve)

        # Avoid duplicates when merging Supersedes
        for superseded in (entry.get("Supersedes") or []):
            if superseded and superseded not in existing[kb_id]["Supersedes"]:
                existing[kb_id]["Supersedes"].append(superseded)


# ============================================================
# SUPERSEDENCE EXPANSION
# ============================================================

def compute_supersedence(kb_entries: List[dict], installed_kbs: Set[str]) -> Tuple[Set[str], Dict[str, List[str]]]:
# Turns older KBs as logically present
    
    # Newer KB maps to set of older KBs it supersedes
    supersedes_map: Dict[str, Set[str]] = {}

    # Populate supersedence container
    for entry in kb_entries:
        kb_id = entry.get("KB")
        if not kb_id:
            continue
        for old in (entry.get("Supersedes") or []):
            supersedes_map.setdefault(kb_id, set()).add(old)

    logical_present: Set[str] = set(installed_kbs)
    superseded_by: Dict[str, Set[str]] = {}

    # Expand supersedence from each installed KB
    for root_installed in installed_kbs:
        stack = [root_installed]
        seen = {root_installed}

        # Depth-first traversal of supersedence graph
        while stack:
            current = stack.pop()

            # For each older KB superseded by current
            for old in supersedes_map.get(current, set()): # Get older KBs
                logical_present.add(old) # Mark as logically present
                superseded_by.setdefault(old, set()).add(root_installed) #  Record superseding KB

                if old not in seen: # Avoid cycles
                    seen.add(old) # Track seen
                    stack.append(old) # Continue traversal

    # Convert superseded sets to sorted lists for output
    return logical_present, {k: sorted(v) for k, v in superseded_by.items()}


# ============================================================
# REPORTING
# ============================================================

def print_kb_table(kb_entries: List[dict], installed_kbs: Set[str], logical_present_kbs: Set[str], superseded_by: Dict[str, List[str]]) -> None:
# Print a formatted table of KB correlation results

    # Build KB dictionary 
    kb_index = {}

    # Map KB entries by KB ID for easy lookup
    for entry in kb_entries:
        if entry.get("KB"):
            kb_index[entry["KB"]] = entry

    col_kb_width = 11
    col_type_width = 12
    col_status_width = 40
    col_months_width = 20

    print("=== Correlation ===")
    print(
        f"{'KB':<{col_kb_width}} "
        f"{'Type':<{col_type_width}} "
        f"{'Status':<{col_status_width}} "
        f"{'Months':<{col_months_width}} "
        f"CVEs"
    )
    print("-" * 110)

    for kb_id in sorted(kb_index.keys()):
        entry = kb_index[kb_id]

        months = list(entry.get("Months") or [])
        cves = list(entry.get("Cves") or [])
        update_type = entry.get("UpdateType", "")

        # Physical install always wins.
        if kb_id in installed_kbs:
            status = "Installed"
        elif kb_id in logical_present_kbs:
            by = superseded_by.get(kb_id, [])
            status = f"Superseded ({', '.join(by)})" if by else "Superseded"
        else:
            status = "Missing"

        # Ensure at least one printed line even when months/cves are empty.
        if not months:
            months = [""]
        if not cves:
            cves = [""]

        height = max(len(months), len(cves))

        for i in range(height):
            kb_cell = kb_id if i == 0 else ""
            type_cell = update_type if i == 0 else ""
            status_cell = status if i == 0 else ""
            month_cell = months[i] if i < len(months) else ""
            cve_cell = cves[i] if i < len(cves) else ""

            print(
                f"{kb_cell:<{col_kb_width}} "
                f"{type_cell:<{col_type_width}} "
                f"{status_cell:<{col_status_width}} "
                f"{month_cell:<{col_months_width}} "
                f"{cve_cell}"
            )

        print("-" * 110)


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    # ---------------------------
    # BASELINE
    # ---------------------------

    print("[*] Running winshield_baseline.ps1...")
    baseline = run_powershell_script(BASELINE_SCRIPT)

    product_name_hint = baseline.get("ProductNameHint")
    if not product_name_hint:
        print("[!] Baseline did not provide ProductNameHint.")
        sys.exit(1)

    print(f"[+] OsName: {baseline.get('OsName')} {baseline.get('DisplayVersion')} ({baseline.get('Build')})")
    print(f"[+] ProductNameHint: {product_name_hint}")
    print(f"[+] LcuMonthId: {baseline.get('LcuMonthId')}")
    print(f"[+] MsrcLatestMonthId: {baseline.get('MsrcLatestMonthId')}")
    print()

    # ---------------------------
    # INVENTORY
    # ---------------------------

    print("[*] Running winshield_inventory.ps1...")
    inventory = run_powershell_script(INVENTORY_SCRIPT)

    installed_kbs: Set[str] = set(inventory.get("AllInstalledKbs") or [])
    print(f"[+] AllInstalledKbs: {len(installed_kbs)}")
    print()

    # ---------------------------
    # MONTH RANGE
    # ---------------------------

    print("[*] Building MonthId range...")
    month_ids = build_month_ids_from_lcu(baseline)

    print(f"[+] MonthIds ({len(month_ids)}): {', '.join(month_ids)}")
    print()

    # ---------------------------
    # ADAPTER QUERIES
    # ---------------------------

    chunk_size = 3
    month_chunks = chunk_list(month_ids, chunk_size)

    merged_kb_map: Dict[str, dict] = {}
    months_with_entries: List[str] = []

    print(f"[*] Running winshield_adapter.ps1")
    print(f"[+] Querying {len(month_chunks)} chunk(s) of up to {chunk_size} month(s)...")

    for idx, chunk in enumerate(month_chunks, start=1):
        months_arg = ",".join(chunk)
        print(f"    -> Chunk {idx}/{len(month_chunks)}: {months_arg}")

        msrc_data = run_powershell_script(
            ADAPTER_SCRIPT,
            extra_args=["-MonthIds", months_arg, "-ProductNameHint", product_name_hint],
        )

        adapter_entries = msrc_data.get("KbEntries") or []
        if not adapter_entries:
            print("       (-) No KBs for this chunk.")
            continue

        months_with_entries.extend(chunk)
        merge_kb_entries(merged_kb_map, adapter_entries)

        print(f"       (+) Merged KBs so far: {len(merged_kb_map)}")

    if not merged_kb_map:
        print("[-] No KBs for this product across months range.")
        sys.exit(0)

    kb_entries: List[dict] = list(merged_kb_map.values())

    # ---------------------------
    # NORMALISATION AND CLASSIFICATION
    # ---------------------------

    for e in kb_entries:
        e["Months"] = sorted(set(e.get("Months") or []))
        e["Cves"] = sorted(set(e.get("Cves") or []))
        e["Supersedes"] = sorted(set(e.get("Supersedes") or []))

    for e in kb_entries:
        e["UpdateType"] = "Superseding" if e.get("Supersedes") else "Standalone"

    expected_kbs: Set[str] = {e["KB"] for e in kb_entries if e.get("KB")}

    # ---------------------------
    # SUPERSEDENCE EXPANSION
    # ---------------------------

    logical_present_kbs, superseded_by = compute_supersedence(kb_entries, installed_kbs)

    present_sorted = sorted(expected_kbs & logical_present_kbs)
    missing_sorted = sorted(expected_kbs - logical_present_kbs)

    # ---------------------------
    # SUMMARY
    # ---------------------------

    kb_index = {e["KB"]: e for e in kb_entries if e.get("KB")}
    missing_superseding = sum(1 for kb in missing_sorted if kb_index.get(kb, {}).get("UpdateType") == "Superseding")
    missing_standalone = len(missing_sorted) - missing_superseding

    print()
    print("=== Summary ===")
    print(f"Expected KBs: {len(expected_kbs)}")
    print(f"Logical KBs:  {len(present_sorted)}")
    print(f"Missing KBs:  {len(missing_sorted)}")
    print(f"Breakdown: {missing_superseding} Superseding | {missing_standalone} Standalone")
    print()

    # ---------------------------
    # TABLE AND MISSING LIST
    # ---------------------------

    print_kb_table(
        kb_entries=kb_entries,
        installed_kbs=installed_kbs,
        logical_present_kbs=logical_present_kbs,
        superseded_by=superseded_by,
    )

    print()
    print("=== Missing ===")
    if not missing_sorted:
        print("None")
    else:
        for kb in missing_sorted:
            entry = kb_index.get(kb, {})
            print(
                f"- {kb} [{entry.get('UpdateType', '?')}] "
                f"| Months: {', '.join(entry.get('Months') or [])}, CVEs: {len(entry.get('Cves') or [])}"
            )

    # ---------------------------
    # WRITE RESULT JSON
    # ---------------------------

    scan_result = {
        "Baseline": baseline,
        "InstalledKbs": sorted(installed_kbs),
        "MonthsRequested": month_ids,
        "MonthsWithEntries": sorted(set(months_with_entries)),
        "KbEntries": sorted(kb_entries, key=lambda x: x.get("KB", "")),
        "MissingKbs": missing_sorted,
        "MissingBreakdown": {"Superseding": missing_superseding, "Standalone": missing_standalone},
    }

    with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as handle:
        json.dump(scan_result, handle, indent=2)

    print()
    print(f"[+] Saved scan result to {SCAN_RESULT_PATH}")


if __name__ == "__main__":
    raise SystemExit(main())
