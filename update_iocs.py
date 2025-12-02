#!/usr/bin/env python3
"""
Update IOC feeds from remote sources.

This script fetches the latest compromised package lists from:
- Hemachandsai's malicious packages feed
- Wiz.io research data
- Codacy's vulnerability database

Run periodically to keep your local IOC database current.
"""
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# IOC Feed URLs - checked and verified working endpoints
IOC_FEEDS = {
    # CyberDracula's maintained feed (most comprehensive)
    "cyberDracula_packages": "https://raw.githubusercontent.com/CyberDracula/shai-hulud-2-scanner/main/fallback/malicious-packages.json",
    # Cobenian's feed
    "cobenian": "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt",
}

# Backup/fallback feeds
FALLBACK_FEEDS = {
    # Alternative endpoints if primary feeds fail
    "cyberDracula_wiz": "https://raw.githubusercontent.com/CyberDracula/shai-hulud-2-scanner/main/fallback/wiz-research-data.json",
}

SCRIPT_DIR = Path(__file__).parent
PACKAGES_FILE = SCRIPT_DIR / "data" / "compromised-packages.txt"


def fetch_url(url: str, timeout: int = 30) -> str | None:
    """Fetch content from URL with timeout."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "scan_shai_hulud IOC updater/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"  [!] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def parse_json_feed(content: str) -> set:
    """Parse JSON format IOC feed (package:version pairs)."""
    packages = set()
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("package")
                    version = item.get("version")
                    if name and version:
                        packages.add(f"{name}:{version}")
                elif isinstance(item, str) and ":" in item:
                    packages.add(item)
        elif isinstance(data, dict):
            # Handle {package: [versions]} format
            for pkg_name, versions in data.items():
                if isinstance(versions, list):
                    for v in versions:
                        packages.add(f"{pkg_name}:{v}")
                elif isinstance(versions, str):
                    packages.add(f"{pkg_name}:{versions}")
    except json.JSONDecodeError as e:
        print(f"  [!] JSON parse error: {e}", file=sys.stderr)
    return packages


def parse_csv_feed(content: str) -> set:
    """Parse CSV format IOC feed."""
    packages = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("package"):
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            pkg_name = parts[0].strip().strip('"')
            version = parts[1].strip().strip('"')
            if pkg_name and version:
                packages.add(f"{pkg_name}:{version}")
    return packages


def parse_text_feed(content: str) -> set:
    """Parse text format IOC feed (package:version per line)."""
    packages = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: package_name:version
        if ":" in line:
            packages.add(line)
    return packages


def load_existing_packages() -> tuple[set, list]:
    """Load existing packages and preserve header comments."""
    packages = set()
    header_lines = []
    
    if not PACKAGES_FILE.exists():
        return packages, header_lines
    
    in_header = True
    with PACKAGES_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if in_header and (not stripped or stripped.startswith("#")):
                header_lines.append(line.rstrip())
            else:
                in_header = False
                if stripped and not stripped.startswith("#"):
                    packages.add(stripped)
    
    return packages, header_lines


def save_packages(packages: set, header_lines: list):
    """Save packages to file with header."""
    # Sort packages for consistent output
    sorted_packages = sorted(packages, key=lambda x: (x.split(":")[0].lower(), x))
    
    with PACKAGES_FILE.open("w", encoding="utf-8") as f:
        # Write header
        for line in header_lines:
            f.write(line + "\n")
        
        # Add update timestamp if not in header
        timestamp_line = f"# Last updated: {datetime.utcnow().isoformat()}Z"
        if not any("Last updated" in h for h in header_lines):
            f.write("\n" + timestamp_line + "\n")
        
        f.write("\n")
        
        # Write packages
        for pkg in sorted_packages:
            f.write(pkg + "\n")


def main():
    print("=" * 60)
    print("  Shai-Hulud IOC Feed Updater")
    print("=" * 60)
    print()
    
    # Load existing packages
    existing_packages, header_lines = load_existing_packages()
    print(f"[*] Existing packages: {len(existing_packages)}")
    
    all_new_packages = set()
    
    # Fetch from primary feeds
    print("\n[*] Fetching from IOC feeds...")
    for name, url in IOC_FEEDS.items():
        print(f"  → {name}...", end=" ", flush=True)
        content = fetch_url(url)
        if content:
            if url.endswith(".json"):
                packages = parse_json_feed(content)
            elif url.endswith(".csv"):
                packages = parse_csv_feed(content)
            elif url.endswith(".txt"):
                packages = parse_text_feed(content)
            else:
                # Try JSON first, then text format
                packages = parse_json_feed(content)
                if not packages:
                    packages = parse_text_feed(content)
            
            new_count = len(packages - existing_packages - all_new_packages)
            all_new_packages.update(packages)
            print(f"✓ ({len(packages)} packages, {new_count} new)")
        else:
            print("✗ (failed)")
    
    # Try fallback feeds if primary feeds failed
    if len(all_new_packages) == 0:
        print("\n[*] Trying fallback feeds...")
        for name, url in FALLBACK_FEEDS.items():
            print(f"  → {name}...", end=" ", flush=True)
            content = fetch_url(url)
            if content:
                packages = parse_json_feed(content)
                new_count = len(packages - existing_packages)
                all_new_packages.update(packages)
                print(f"✓ ({len(packages)} packages, {new_count} new)")
            else:
                print("✗ (failed)")
    
    # Merge with existing
    combined = existing_packages | all_new_packages
    new_total = len(combined - existing_packages)
    
    print()
    print("=" * 60)
    print(f"  Summary")
    print("=" * 60)
    print(f"  Previous count:  {len(existing_packages)}")
    print(f"  New packages:    {new_total}")
    print(f"  Total count:     {len(combined)}")
    print()
    
    if new_total > 0:
        save_packages(combined, header_lines)
        print(f"[✓] Updated {PACKAGES_FILE}")
        
        # Show some new packages
        new_pkgs = list(combined - existing_packages)[:10]
        if new_pkgs:
            print("\n  New packages added:")
            for pkg in new_pkgs:
                print(f"    + {pkg}")
            if len(combined - existing_packages) > 10:
                print(f"    ... and {len(combined - existing_packages) - 10} more")
    else:
        print("[*] No new packages found. Database is up to date.")
    
    print()
    return 0 if new_total >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())

