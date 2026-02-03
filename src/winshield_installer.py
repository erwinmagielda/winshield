"""
WinShield Installer

Lists .msu/.cab in /downloads, lets operator select one, installs it.
"""

import ctypes
import os
import re
import subprocess
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
DOWNLOADS_DIR = os.path.join(ROOT_DIR, "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_packages(downloads_dir: str) -> list[str]:
    packages: list[str] = []
    for name in os.listdir(downloads_dir):
        path = os.path.join(downloads_dir, name)
        if not os.path.isfile(path):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in (".msu", ".cab"):
            packages.append(path)

    packages.sort(key=lambda p: os.path.basename(p).lower())
    return packages


def extract_kb_label(filename: str) -> str:
    m = re.search(r"(KB\d{4,8})", filename, flags=re.IGNORECASE)
    return m.group(1).upper() if m else filename


def run(argv: list[str]) -> int:
    p = subprocess.run(argv, text=True)
    return int(p.returncode or 0)


def main() -> int:
    print("[*] Running winshield_installer.py...")

    if not is_admin():
        print("[!] Run as Administrator.")
        return 1

    packages = find_packages(DOWNLOADS_DIR)
    if not packages:
        print("[+] No .msu or .cab packages found.")
        return 0

    for i, path in enumerate(packages, start=1):
        print(f"{i}) {os.path.basename(path)}")

    raw = input("Select package #: ").strip()
    if not raw.isdigit():
        print("[X] Invalid selection.")
        return 1

    idx = int(raw)
    if idx < 1 or idx > len(packages):
        print("[!] Invalid selection.")
        return 1

    chosen = packages[idx - 1]
    name = os.path.basename(chosen)
    kb_label = extract_kb_label(name)

    ext = os.path.splitext(chosen)[1].lower()

    print(f"[*] Installing {kb_label}...")

    if ext == ".msu":
        code = run(["wusa.exe", chosen, "/quiet", "/norestart"])
    else:
        code = run(["dism.exe", "/online", "/add-package", f"/packagepath:{chosen}", "/quiet", "/norestart"])

    print(f"[+] ExitCode: {code}")
    return 0 if code in (0, 3010) else 1


if __name__ == "__main__":
    sys.exit(main())
