#!/usr/bin/env python3
"""
Update IOC feeds from remote sources.

This script fetches the latest threat intelligence from multiple sources
and merges it with your local data files (preserving any local additions).

Supported data files:
- compromised-packages.txt (package:version pairs)
- malicious-hashes.txt (algorithm:hash:description)
- exfil-endpoints.txt (domains/URLs)
- ioc-domains.txt (malicious domains)
- suspicious-namespaces.txt (npm namespaces)
- attacker-wallets.txt (crypto addresses)

Run periodically: python update_iocs.py
"""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"

# =============================================================================
# IOC FEED DEFINITIONS
# =============================================================================
# Each feed specifies: URL, target file, parser type, and optional transformer

FEEDS = {
    # -------------------------------------------------------------------------
    # COMPROMISED PACKAGES
    # -------------------------------------------------------------------------
    "cyberDracula_packages": {
        "url": "https://raw.githubusercontent.com/CyberDracula/shai-hulud-2-scanner/main/fallback/malicious-packages.json",
        "target": "compromised-packages.txt",
        "parser": "json_packages",
        "description": "CyberDracula's maintained package list",
    },
    "cobenian_packages": {
        "url": "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt",
        "target": "compromised-packages.txt",
        "parser": "text_lines",
        "description": "Cobenian's package list",
    },
    "cyberDracula_wiz": {
        "url": "https://raw.githubusercontent.com/CyberDracula/shai-hulud-2-scanner/main/fallback/wiz-research-data.json",
        "target": "compromised-packages.txt",
        "parser": "json_packages",
        "description": "Wiz.io research data",
    },
    
    # -------------------------------------------------------------------------
    # MALICIOUS HASHES
    # -------------------------------------------------------------------------
    "cyberDracula_hashes": {
        "url": "https://raw.githubusercontent.com/CyberDracula/shai-hulud-2-scanner/main/fallback/known-hashes.json",
        "target": "malicious-hashes.txt",
        "parser": "json_hashes",
        "description": "CyberDracula's hash database",
        "optional": True,  # May not exist
    },
    
    # -------------------------------------------------------------------------
    # EXFILTRATION ENDPOINTS  
    # -------------------------------------------------------------------------
    # Note: We curate these manually as external feeds tend to be noisy
    
    # -------------------------------------------------------------------------
    # SUSPICIOUS NAMESPACES
    # -------------------------------------------------------------------------
    "cyberDracula_namespaces": {
        "url": "https://raw.githubusercontent.com/CyberDracula/shai-hulud-2-scanner/main/fallback/targeted-namespaces.json",
        "target": "suspicious-namespaces.txt",
        "parser": "json_list",
        "description": "CyberDracula's targeted namespaces",
        "optional": True,
    },
}

# Additional feeds to try if primary feeds fail
FALLBACK_FEEDS = [
    "cyberDracula_wiz",
]


# =============================================================================
# FETCH UTILITIES
# =============================================================================

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
        return None


# =============================================================================
# PARSERS
# =============================================================================

def parse_json_packages(content: str) -> set:
    """Parse JSON package feeds (multiple formats supported)."""
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
            for pkg_name, pkg_data in data.items():
                # {package: {versions: [...]}} format
                if isinstance(pkg_data, dict) and "versions" in pkg_data:
                    for v in pkg_data["versions"]:
                        packages.add(f"{pkg_name}:{v}")
                # {package: [versions]} format
                elif isinstance(pkg_data, list):
                    for v in pkg_data:
                        packages.add(f"{pkg_name}:{v}")
                # {package: version} format
                elif isinstance(pkg_data, str):
                    packages.add(f"{pkg_name}:{pkg_data}")
    except json.JSONDecodeError:
        pass
    return packages


def parse_json_hashes(content: str) -> set:
    """Parse JSON hash feeds into algorithm:hash:description format."""
    hashes = set()
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    algo = item.get("algorithm", "sha256").lower()
                    hash_val = item.get("hash") or item.get("sha256") or item.get("sha1")
                    desc = item.get("description") or item.get("file") or item.get("name") or ""
                    if hash_val:
                        hashes.add(f"{algo}:{hash_val}:{desc}")
                elif isinstance(item, str):
                    # Assume sha256 if just a hash string
                    if len(item) == 64:
                        hashes.add(f"sha256:{item}:")
                    elif len(item) == 40:
                        hashes.add(f"sha1:{item}:")
        elif isinstance(data, dict):
            # {hash: description} or {hash: {metadata}}
            for hash_val, meta in data.items():
                if len(hash_val) == 64:
                    algo = "sha256"
                elif len(hash_val) == 40:
                    algo = "sha1"
                else:
                    continue
                desc = meta if isinstance(meta, str) else meta.get("description", "") if isinstance(meta, dict) else ""
                hashes.add(f"{algo}:{hash_val}:{desc}")
    except json.JSONDecodeError:
        pass
    return hashes


def parse_json_list(content: str) -> set:
    """Parse JSON array of strings."""
    items = set()
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    items.add(item)
        elif isinstance(data, dict):
            # Could be {item: metadata} format
            items.update(data.keys())
    except json.JSONDecodeError:
        pass
    return items


def parse_text_lines(content: str) -> set:
    """Parse text file with one entry per line."""
    items = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            items.add(line)
    return items


def parse_csv_packages(content: str) -> set:
    """Parse CSV format (package,version,...)."""
    packages = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.lower().startswith("package"):
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            pkg_name = parts[0].strip().strip('"')
            version = parts[1].strip().strip('"')
            if pkg_name and version:
                packages.add(f"{pkg_name}:{version}")
    return packages


PARSERS = {
    "json_packages": parse_json_packages,
    "json_hashes": parse_json_hashes,
    "json_list": parse_json_list,
    "text_lines": parse_text_lines,
    "csv_packages": parse_csv_packages,
}


# =============================================================================
# DATA FILE MANAGEMENT
# =============================================================================

def load_data_file(filepath: Path) -> tuple[set, list]:
    """Load existing data file, preserving header comments."""
    items = set()
    header_lines = []
    
    if not filepath.exists():
        return items, header_lines
    
    in_header = True
    try:
        with filepath.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if in_header and (not stripped or stripped.startswith("#")):
                    header_lines.append(line.rstrip())
                else:
                    in_header = False
                    if stripped and not stripped.startswith("#"):
                        items.add(stripped)
    except OSError:
        pass
    
    return items, header_lines


def save_data_file(filepath: Path, items: set, header_lines: list):
    """Save data file with header and sorted entries."""
    # Sort for consistent output
    if filepath.name == "compromised-packages.txt":
        # Sort packages by name then version
        sorted_items = sorted(items, key=lambda x: (x.split(":")[0].lower(), x))
    elif filepath.name == "malicious-hashes.txt":
        # Sort hashes by algorithm then hash
        sorted_items = sorted(items, key=lambda x: (x.split(":")[0], x.split(":")[1] if ":" in x else x))
    else:
        # Default alphabetical sort
        sorted_items = sorted(items, key=str.lower)
    
    with filepath.open("w", encoding="utf-8") as f:
        # Write header
        for line in header_lines:
            f.write(line + "\n")
        
        # Update or add timestamp
        timestamp_line = f"# Last updated: {datetime.now(timezone.utc).isoformat()}"
        header_has_timestamp = any("Last updated" in h for h in header_lines)
        
        if header_has_timestamp:
            # Timestamp is in header, update it in place (already written)
            pass
        else:
            f.write("\n" + timestamp_line + "\n")
        
        f.write("\n")
        
        # Write items
        for item in sorted_items:
            f.write(item + "\n")


# =============================================================================
# UPDATE LOGIC
# =============================================================================

def update_data_file(target_file: str, new_items: set, stats: dict) -> int:
    """Merge new items into target file, return count of new items added."""
    filepath = DATA_DIR / target_file
    existing, header = load_data_file(filepath)
    
    # Merge (preserves local additions)
    combined = existing | new_items
    added = len(combined) - len(existing)
    
    if added > 0:
        save_data_file(filepath, combined, header)
        stats[target_file] = {
            "previous": len(existing),
            "added": added,
            "total": len(combined),
        }
    elif target_file not in stats:
        stats[target_file] = {
            "previous": len(existing),
            "added": 0,
            "total": len(existing),
        }
    else:
        # Already tracked, just update total
        stats[target_file]["total"] = len(combined)
    
    return added


def fetch_feed(feed_name: str, feed_config: dict) -> set | None:
    """Fetch and parse a single feed."""
    url = feed_config["url"]
    parser_name = feed_config["parser"]
    
    content = fetch_url(url)
    if not content:
        return None
    
    parser = PARSERS.get(parser_name)
    if not parser:
        return None
    
    return parser(content)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Update IOC data files from remote threat intelligence feeds."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be updated without making changes",
    )
    parser.add_argument(
        "--feed",
        action="append",
        dest="feeds",
        help="Update only specific feed(s) by name",
    )
    parser.add_argument(
        "--list-feeds",
        action="store_true",
        help="List available feeds and exit",
    )
    args = parser.parse_args()
    
    # List feeds mode
    if args.list_feeds:
        print("Available IOC feeds:\n")
        for name, config in sorted(FEEDS.items()):
            optional = " (optional)" if config.get("optional") else ""
            print(f"  {name}{optional}")
            print(f"    Target: {config['target']}")
            print(f"    URL: {config['url']}")
            print(f"    Description: {config.get('description', 'N/A')}")
            print()
        return 0
    
    print("=" * 60)
    print("  Shai-Hulud IOC Feed Updater")
    print("=" * 60)
    print()
    
    # Collect items by target file
    items_by_file: dict[str, set] = {}
    feed_results: dict[str, tuple[int, int]] = {}  # feed -> (total, new)
    
    # Determine which feeds to process
    feeds_to_process = args.feeds if args.feeds else list(FEEDS.keys())
    
    print("[*] Fetching from IOC feeds...")
    for feed_name in feeds_to_process:
        if feed_name not in FEEDS:
            print(f"  → {feed_name}... ✗ (unknown feed)")
            continue
        
        feed_config = FEEDS[feed_name]
        is_optional = feed_config.get("optional", False)
        
        print(f"  → {feed_name}...", end=" ", flush=True)
        
        items = fetch_feed(feed_name, feed_config)
        
        if items is None:
            if is_optional:
                print("⊘ (not available)")
            else:
                print("✗ (failed)")
            continue
        
        if not items:
            print("⊘ (empty)")
            continue
        
        target = feed_config["target"]
        if target not in items_by_file:
            items_by_file[target] = set()
        
        # Track new items for this feed
        existing_for_target = items_by_file[target]
        new_from_feed = len(items - existing_for_target)
        items_by_file[target].update(items)
        
        feed_results[feed_name] = (len(items), new_from_feed)
        print(f"✓ ({len(items)} items, {new_from_feed} new)")
    
    # Update data files
    print()
    stats: dict[str, dict] = {}
    total_added = 0
    
    for target_file, items in items_by_file.items():
        if args.dry_run:
            filepath = DATA_DIR / target_file
            existing, _ = load_data_file(filepath)
            new_count = len(items - existing)
            stats[target_file] = {
                "previous": len(existing),
                "added": new_count,
                "total": len(existing | items),
            }
            total_added += new_count
        else:
            added = update_data_file(target_file, items, stats)
            total_added += added
    
    # Summary
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print()
    
    if not stats:
        print("  No data files updated.")
    else:
        for target_file, s in sorted(stats.items()):
            status = "→" if s["added"] > 0 else "="
            print(f"  {status} {target_file}")
            print(f"      Previous: {s['previous']:,}  Added: {s['added']:,}  Total: {s['total']:,}")
        print()
        print(f"  Total new entries: {total_added:,}")
    
    if args.dry_run:
        print()
        print("  [DRY RUN] No files were modified.")
    elif total_added > 0:
        print()
        print(f"  [✓] Data files updated in {DATA_DIR}/")
    else:
        print()
        print("  [*] All data files are up to date.")
    
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
