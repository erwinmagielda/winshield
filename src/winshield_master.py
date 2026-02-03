"""
WinShield Master

"""

import os
import subprocess
import sys
from typing import Dict, Tuple


# ============================================================
# PATHS
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  
ROOT_DIR = os.path.dirname(SCRIPT_DIR)                  

PYTHON_EXE = sys.executable


# ============================================================
# STAGE MAP
# ============================================================

STAGES: Dict[str, Tuple[str, str]] = {
    "1": ("winshield_scanner.py", os.path.join(SCRIPT_DIR, "winshield_scanner.py")),
    "2": ("winshield_downloader.py", os.path.join(SCRIPT_DIR, "winshield_downloader.py")),
    "3": ("winshield_installer.py", os.path.join(SCRIPT_DIR, "winshield_installer.py")),
}


# ============================================================
# PROCESS RUNNER
# ============================================================

def run_stage(name: str, path: str) -> int:

    if not os.path.isfile(path):
        print(f"[X] Stage script not found: {path}")
        return 1

    print()
    print(f"[*] Running: {name}")
    print("=" * 60)

    try:
        completed = subprocess.run(
            [PYTHON_EXE, path],
            cwd=ROOT_DIR,
            check=False,
        )
        rc = int(completed.returncode or 0)
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        rc = 130
    except Exception as exc:
        print(f"[X] Failed to launch stage: {exc}")
        rc = 1

    print("=" * 60)
    if rc == 0:
        print(f"[+] Finished: {name}")
    else:
        print(f"[!] Finished: {name} (exit code: {rc})")
    print()

    return rc


# ============================================================
# UI
# ============================================================

def print_menu() -> None:
    """
    Prints the operator menu.
    """
    print("=" * 43)
    print("                 WinShield")
    print("=" * 43)
    print("1) Scan System")
    print("2) Download KB")
    print("3) Install KB")
    print("4) Exit")
    print()


def read_choice() -> str:
    
    while True:
        try:
            choice = input("Select an option: ").strip()
        except KeyboardInterrupt:
            print("\n[!] Cancelled by user.")
            return "4"
        except EOFError:
            return "4"

        if choice == "":
            continue

        return choice


# ============================================================
# MAIN LOOP
# ============================================================

def main() -> int:

    while True:
        print_menu()
        choice = read_choice()

        if choice == "4":
            print("Exiting WinShield...")
            return 0

        if choice in STAGES:
            name, path = STAGES[choice]
            run_stage(name, path)
            continue

        print("[!] Invalid selection.")
        print()


if __name__ == "__main__":
    raise SystemExit(main())
