    #!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# High-signal filenames and workflow paths from Shai-Hulud analysis
IOC_FILENAMES = {
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json",
    "actionsSecrets.json",  # Double Base64 encoded credentials (Nov 2025)
    "setup_bun.js",  # Fake Bun installer (Second Coming attack)
    "bun_environment.js",  # Obfuscated payload (Second Coming attack)
    "bundle.js",  # Common obfuscated payload filename
    # Additional exfiltration artifacts
    "secrets.json",
    "env_dump.json",
    "ci_secrets.json",
    "runner_env.json",
    "github_context.json",
    "workflow_secrets.json",
    # TruffleHog-related artifacts
    "trufflehog_results.json",
    "trufflehog_output.json",
}

# Known malicious SHA256 hashes of bundle.js variants (V1-V7)
# Source: Socket.dev, JFrog security reports
MALICIOUS_HASHES = {
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
}

IOC_WORKFLOW_PATHS = {
    ".github/workflows/discussion.yaml",
    ".github/workflows/discussion.yml",
    ".github/workflows/formatter_123456789.yml",
    ".github/workflows/shai-hulud-workflow.yml",
    ".github/workflows/shai-hulud-workflow.yaml",
    ".github/workflows/shai-hulud.yml",
    ".github/workflows/shai-hulud.yaml",
    # Additional suspicious workflow names
    ".github/workflows/sync.yml",
    ".github/workflows/sync.yaml",
    ".github/workflows/update.yml",
    ".github/workflows/update.yaml",
    ".github/workflows/ci-helper.yml",
    ".github/workflows/ci-helper.yaml",
    ".github/workflows/auto-publish.yml",
    ".github/workflows/auto-publish.yaml",
}

# Workflow filename patterns (regex) for dynamic matching
IOC_WORKFLOW_PATTERNS = [
    r"formatter_\d+\.yml$",  # formatter_*.yml - Shai-Hulud 2.0 pattern
    r"formatter_\d+\.yaml$",
]

# Repo / description markers
IOC_STRINGS = {
    "Shai-Hulud",
    "Sha1-Hulud",
    "SHA1HULUD",
    "Sha1Hulud",
    "The Continued Coming",
    # Additional campaign markers
    "ShaiHulud",
    "shai_hulud",
    "SHAI_HULUD",
}

# Known malicious domains and exfiltration endpoints
IOC_DOMAINS = {
    "evilpackage.com",
    "npm-stats.com",
    "npm-registry.com",
    "registry-npm.com",
    "npmpkg.com",
    "npmpackage.com",
    "pkgstats.com",
    "telemetry-npm.com",
    "npmjs.help",  # Phishing domain from chalk/debug attack
}

# Exfiltration endpoints used by Shai-Hulud and similar attacks
# webhook.site is the PRIMARY exfil endpoint for Shai-Hulud
IOC_EXFIL_ENDPOINTS = {
    "webhook.site",  # PRIMARY - Shai-Hulud exfil endpoint
    "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",  # Known malicious webhook.site UUID
    "discord.com/api/webhooks",
    "api.telegram.org",
    "hooks.slack.com",
    "requestbin.com",
    "beeceptor.com",
    "pipedream.com",
    "zapier.com/hooks",
    "ngrok.io",
    "localtunnel.me",
    "serveo.net",
    "pastebin.com",
    "hastebin.com",
    "ix.io",
    "0x0.st",
    "transfer.sh",
    "file.io",
}

# SHA1 hashes for known malicious Shai-Hulud 2.0 files
# Source: gensecaihq/Shai-Hulud-2.0-Detector
MALICIOUS_SHA1_HASHES = {
    "d60ec97eea19fffb4809bc35b91033b52490ca11": "bun_environment.js",
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16": "setup_bun.js",
}

# Known attacker cryptocurrency wallet addresses
ATTACKER_WALLETS = {
    "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976",  # Ethereum
    "1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx",  # Bitcoin
    "TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67",  # Tron
}

# Crypto theft function names from chalk/debug attack (Sept 8, 2025)
CRYPTO_THEFT_FUNCTIONS = {
    "checkethereumw",
    "runmask",
    "newdlocal",
    "_0x19ca67",  # Obfuscated function name
}

# Suspicious code patterns in postinstall/preinstall scripts
SUSPICIOUS_SCRIPT_PATTERNS = [
    r"curl\s+.*\|\s*(?:bash|sh)",  # curl pipe to shell
    r"wget\s+.*\|\s*(?:bash|sh)",  # wget pipe to shell
    r"eval\s*\(\s*(?:atob|Buffer\.from)",  # eval with base64 decode
    r"eval\s+['\"`$]",  # eval with dynamic content
    r"new\s+Function\s*\(",  # dynamic function creation
    r"child_process.*exec",  # command execution
    r"\bexec(?:Sync)?\s*\(",  # exec calls
    r"\bspawn(?:Sync)?\s*\(",  # spawn calls
    r"https?://[^\s]*\?.*(?:env|token|secret)",  # URL with sensitive params
    r'Buffer\.from\s*\([^)]+,\s*[\'"]base64[\'"]\)',  # base64 decoding
    r"\batob\s*\(",  # base64 decode in browser context
    r"node\s+setup_bun\.js",  # Fake Bun installer (Second Coming attack)
    r"npx\s+--yes\s+[^@\s]+@",  # npx auto-install versioned package (suspicious)
    r"node\s+-e\s+['\"].*?(?:http|eval|Buffer\.from)",  # Inline Node.js execution
    r"releases/download.*trufflehog",  # TruffleHog binary download
    r"github\.com/trufflesecurity/trufflehog",  # TruffleHog GitHub download
]

# Destructive payload patterns (fallback when credential theft fails)
DESTRUCTIVE_PATTERNS = [
    r"rm\s+-rf\s+[\$~]HOME",  # rm -rf $HOME or ~HOME
    r"rm\s+-rf\s+~/",  # rm -rf ~/
    r"rm\s+-rf\s+/home/",  # rm -rf /home/
    r'fs\.rmSync\s*\([^)]*recursive\s*:\s*true',  # Node.js recursive delete
    r'fs\.rm\s*\([^)]*recursive\s*:\s*true',  # Node.js async recursive delete
    r"rimraf\s+[\$~]HOME",  # rimraf $HOME
    r"Remove-Item\s+-Recurse.*\$HOME",  # PowerShell recursive delete
    r"del\s+/s\s+/q.*%USERPROFILE%",  # Windows cmd delete
]

# Self-hosted runner backdoor patterns (Nov 2025 attack)
RUNNER_BACKDOOR_PATTERNS = {
    ".dev-env/",  # Hidden directory for persistent backdoor
    "SHA1HULUD",  # Runner naming pattern
    "Sha1Hulud",
    "sha1hulud",
}

# Compromised packages with known vulnerable version ranges
# Format: "package-name": [("min_version", "max_version"), ...] or None for all versions
# Use None as min to mean 0.0.0, None as max to mean infinity
# NOTE: This is a fallback list. The main list is loaded from compromised-packages.txt
COMPROMISED_PACKAGES = {
    # Historical compromises with known bad versions (fallback)
    "coa": [("2.0.3", "2.0.4"), ("2.1.1", "2.1.3"), ("3.0.1", "3.1.3")],
    "rc": [("1.2.9", "1.2.9"), ("1.3.9", "1.3.9"), ("2.3.9", "2.3.9")],
    "ua-parser-js": [("0.7.29", "0.7.29"), ("0.8.0", "0.8.0"), ("1.0.0", "1.0.0")],
    "event-stream": [("3.3.6", "3.3.6")],  # Contained flatmap-stream
    "flatmap-stream": [("0.1.0", "0.1.1")],  # Malicious package
    "colors": [("1.4.1", "1.4.44-liberty-2")],  # Protestware versions
    "faker": [("6.6.6", None)],  # Protestware versions 6.6.6+
    "node-ipc": [("10.1.1", "10.1.3"), ("11.0.0", "11.1.0")],  # Peacenotwar malware
    "peacenotwar": None,  # Entirely malicious
}

# Exact compromised package:version pairs loaded from external file
# This is populated by load_compromised_packages_file()
COMPROMISED_PACKAGES_EXACT: set = set()

# Suspicious npm namespaces known to be targeted by supply chain attacks
SUSPICIOUS_NAMESPACES = {
    "@ctrl",
    "@crowdstrike",
    "@art-ws",
    "@postman",
    "@asyncapi",
    "@zapier",
    "@ensdomains",
    "@posthog",
    "@lottiefiles",
    "@rspack",
    "@solana",
    # Additional targeted namespaces from Cobenian analysis
    "@nativescript-community",
    "@ahmedhfarag",
    "@operato",
    "@teselagen",
    "@things-factory",
    "@hestjs",
    "@nstudio",
    "@voiceflow",
    "@oku-ui",
    "@browserbasehq",
    "@ntnx",
    "@pergel",
    "@silgi",
    "@mcp-use",
}

LOCKFILE_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "yarn.lock",
}


def load_compromised_packages_file():
    """Load compromised packages from external file (package:version format)."""
    global COMPROMISED_PACKAGES_EXACT
    
    # Try to find compromised-packages.txt in script directory
    script_dir = Path(__file__).parent
    pkg_file = script_dir / "compromised-packages.txt"
    
    if not pkg_file.exists():
        return 0
    
    count = 0
    try:
        with pkg_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Format: package_name:version
                if ":" in line:
                    COMPROMISED_PACKAGES_EXACT.add(line)
                    count += 1
    except OSError:
        pass
    
    return count

# Global progress bar instance
_progress_bar = None


class ProgressBar:
    """Simple progress bar without external dependencies."""
    
    def __init__(self, total: int, desc: str = "Scanning", width: int = None, enabled: bool = True):
        self.total = max(total, 1)
        self.current = 0
        self.desc = desc
        self.enabled = enabled and sys.stderr.isatty()
        
        # Auto-detect terminal width
        if width is None:
            term_size = shutil.get_terminal_size((80, 20))
            self.width = min(40, term_size.columns - 40)
        else:
            self.width = width
        
        self._last_render = -1
    
    def update(self, n: int = 1):
        """Update progress by n steps."""
        self.current = min(self.current + n, self.total)
        self._render()
    
    def set_description(self, desc: str):
        """Update the description."""
        self.desc = desc
        self._render(force=True)
    
    def _render(self, force: bool = False):
        if not self.enabled:
            return
        
        # Only render every 1% to reduce flickering
        pct = int(100 * self.current / self.total)
        if not force and pct == self._last_render:
            return
        self._last_render = pct
        
        filled = int(self.width * self.current / self.total)
        bar = "█" * filled + "░" * (self.width - filled)
        
        # Clear line and print progress
        sys.stderr.write(f"\r\033[K{self.desc}: |{bar}| {pct:3d}% ({self.current}/{self.total})")
        sys.stderr.flush()
    
    def finish(self):
        """Complete the progress bar."""
        if self.enabled:
            self.current = self.total
            self._render(force=True)
            sys.stderr.write("\n")
            sys.stderr.flush()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.finish()


def count_directories(root: Path, skip_dirs: set) -> int:
    """Quick count of directories to scan for progress estimation."""
    count = 0
    try:
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            base = os.path.basename(dirpath)
            if base in skip_dirs:
                dirnames[:] = []
                continue
            count += 1
            # Sample-based estimation for large trees
            if count > 10000:
                # Estimate based on sample
                return count * 2
    except OSError:
        pass
    return max(count, 1)


def progress(iteration: int, label: str = "dirs"):
    """Update global progress bar if available."""
    global _progress_bar
    if _progress_bar is not None:
        _progress_bar.update(1)


def parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple of integers."""
    if not version_str:
        return (0,)
    # Strip leading 'v' and any prerelease/build metadata for comparison
    version_str = version_str.lstrip("v").split("-")[0].split("+")[0]
    parts = []
    for part in version_str.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            # Handle non-numeric parts (e.g., 'x' in ranges)
            parts.append(0)
    return tuple(parts) if parts else (0,)


def is_version_in_range(version: str, ranges: list) -> bool:
    """
    Check if a version falls within any of the specified vulnerable ranges.
    
    Args:
        version: The version string to check
        ranges: List of (min_version, max_version) tuples, or None for all versions
    
    Returns:
        True if the version is in a vulnerable range
    """
    if ranges is None:
        return True  # All versions considered vulnerable
    
    parsed_version = parse_version(version)
    
    for min_ver, max_ver in ranges:
        min_parsed = parse_version(min_ver) if min_ver else (0,)
        max_parsed = parse_version(max_ver) if max_ver else (999999,)
        
        if min_parsed <= parsed_version <= max_parsed:
            return True
    
    return False


def is_text_file(path: Path, max_bytes: int = 4096) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(max_bytes)
        if not chunk:
            return False
        return b"\x00" not in chunk
    except OSError:
        return False


def scan_for_ioc_files(root: Path):
    hits = []
    dir_count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if name in IOC_FILENAMES:
                hits.append(os.path.join(dirpath, name))
    return hits


def scan_for_workflows(root: Path):
    hits = []
    # Direct known paths
    for rel in IOC_WORKFLOW_PATHS:
        candidate = root / rel
        if candidate.is_file():
            hits.append(str(candidate))

    # Check for formatter_*.yml pattern in workflows directory
    workflows_dir = root / ".github" / "workflows"
    if workflows_dir.is_dir():
        for workflow_file in workflows_dir.iterdir():
            if workflow_file.is_file():
                for pattern in IOC_WORKFLOW_PATTERNS:
                    if re.search(pattern, workflow_file.name):
                        hits.append(str(workflow_file))
                        break

    # Generic search for discussion body echo pattern
    pattern = re.compile(r"github\.event\.discussion\.body")

    dir_count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".yml", ".yaml")):
                continue
            path = Path(dirpath) / name
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pattern.search(content):
                hits.append(str(path))
    return sorted(set(hits))


def scan_for_ioc_strings(root: Path):
    hits = []
    dir_count = 0
    pattern = re.compile("|".join(re.escape(s) for s in IOC_STRINGS), re.IGNORECASE)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules"}:
            dirnames[:] = []
            continue

        for name in filenames:
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 512 * 1024:
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            match = pattern.search(content)
            if match:
                matched_str = match.group(0)
                # Find line containing match
                for i, line in enumerate(content.splitlines(), 1):
                    if matched_str.lower() in line.lower():
                        snippet = f"line {i}: {line.strip()[:80]}"
                        hits.append((str(path), matched_str, snippet))
                        break
                else:
                    hits.append((str(path), matched_str, None))
    return hits


def parse_package_lock(path: Path):
    """Parse package-lock.json and return dict of {package_name: version}."""
    pkgs = {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return pkgs
    if isinstance(data, dict):
        # npm v1 lockfile format (dependencies at top level)
        if "dependencies" in data and isinstance(data["dependencies"], dict):
            for name, info in data["dependencies"].items():
                if isinstance(info, dict) and "version" in info:
                    pkgs[name] = info["version"]
                elif isinstance(info, str):
                    pkgs[name] = info
        # npm v2/v3 lockfile format (packages with node_modules/ prefix)
        if "packages" in data and isinstance(data["packages"], dict):
            for key, info in data["packages"].items():
                if key.startswith("node_modules/"):
                    name = key.split("node_modules/")[-1]  # Handle nested node_modules
                    if isinstance(info, dict) and "version" in info:
                        pkgs[name] = info["version"]
    return pkgs


def parse_yarn_lock(path: Path):
    """Parse yarn.lock and return dict of {package_name: version}."""
    pkgs = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return pkgs

    current_pkg = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        
        # Package declaration line (not indented, ends with :)
        if not line.startswith(" ") and stripped.endswith(":"):
            key = stripped[:-1].strip().strip('"').strip("'")
            # Extract package name from first entry (may have multiple comma-separated)
            first_entry = key.split(",")[0].strip().strip('"').strip("'")
            if first_entry.startswith("@"):
                # Scoped package: @scope/name@version
                parts = first_entry.split("@")
                if len(parts) >= 3:
                    current_pkg = "@" + parts[1]
            else:
                # Regular package: name@version
                current_pkg = first_entry.split("@")[0]
        # Version line (indented, starts with "version")
        elif line.startswith("  ") and stripped.startswith("version"):
            if current_pkg:
                version_match = re.search(r'version\s+["\']?([^"\'\\s]+)["\']?', stripped)
                if version_match:
                    pkgs[current_pkg] = version_match.group(1)
                current_pkg = None
    return pkgs


def parse_pnpm_lock(path: Path):
    """Parse pnpm-lock.yaml and return dict of {package_name: version}."""
    pkgs = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return pkgs

    # pnpm lockfile v6+ format: packages section with /@scope/name@version: or /name@version:
    # Also handles older formats
    pkg_pattern = re.compile(r"^  ['\"]?/?(@?[^@'\"/]+(?:/[^@'\"]+)?)@([^:'\"]+)['\"]?:", re.MULTILINE)
    
    for match in pkg_pattern.finditer(text):
        name = match.group(1)
        version = match.group(2)
        if name and version:
            pkgs[name] = version
    
    return pkgs


def scan_lockfiles_for_packages(root: Path):
    """Scan lockfiles for compromised packages, checking version ranges and exact matches."""
    matches = {}
    dir_count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if name not in LOCKFILE_NAMES:
                continue
            path = Path(dirpath) / name
            pkgs = {}
            if name == "package-lock.json":
                pkgs = parse_package_lock(path)
            elif name.startswith("pnpm-lock"):
                pkgs = parse_pnpm_lock(path)
            elif name == "yarn.lock":
                pkgs = parse_yarn_lock(path)
            
            # Check each package against compromised list
            bad = []
            for pkg_name, pkg_version in pkgs.items():
                # First check exact package:version from external file (1700+ packages)
                pkg_key = f"{pkg_name}:{pkg_version}"
                if pkg_key in COMPROMISED_PACKAGES_EXACT:
                    bad.append((pkg_name, pkg_version, "exact match"))
                    continue
                
                # Then check version ranges from built-in list
                if pkg_name in COMPROMISED_PACKAGES:
                    vuln_ranges = COMPROMISED_PACKAGES[pkg_name]
                    if is_version_in_range(pkg_version, vuln_ranges):
                        bad.append((pkg_name, pkg_version, vuln_ranges))
            
            if bad:
                matches[str(path)] = bad
    return matches


def scan_for_malicious_domains(root: Path):
    """Scan for known malicious exfiltration domains in source files."""
    hits = []
    dir_count = 0
    pattern = re.compile("|".join(re.escape(d) for d in IOC_DOMAINS), re.IGNORECASE)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".yml", ".yaml", ".json")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 1024 * 1024:  # Skip files > 1MB
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            match = pattern.search(content)
            if match:
                # Find the line containing the match
                matched_domain = match.group(0)
                for i, line in enumerate(content.splitlines(), 1):
                    if matched_domain.lower() in line.lower():
                        snippet = f"line {i}: {line.strip()[:80]}"
                        hits.append((str(path), matched_domain, snippet))
                        break
                else:
                    hits.append((str(path), matched_domain, None))
    return hits


def scan_for_suspicious_scripts(root: Path):
    """Scan package.json files for suspicious preinstall/postinstall scripts."""
    hits = {}
    dir_count = 0
    patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_SCRIPT_PATTERNS]

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if name != "package.json":
                continue
            path = Path(dirpath) / name
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            scripts = data.get("scripts", {})
            if not isinstance(scripts, dict):
                continue

            suspicious_scripts = []
            for script_name in ["preinstall", "postinstall", "prepare", "prepublish", "prepublishOnly"]:
                script_content = scripts.get(script_name, "")
                if not script_content:
                    continue
                for pattern in patterns:
                    if pattern.search(script_content):
                        suspicious_scripts.append((script_name, script_content[:200]))
                        break

            if suspicious_scripts:
                hits[str(path)] = suspicious_scripts
    return hits


def scan_for_env_exfiltration(root: Path):
    """Scan for suspicious environment variable access patterns."""
    hits = []
    dir_count = 0
    patterns_with_desc = [
        (re.compile(r"process\.env\[.*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|API_KEY)", re.IGNORECASE), "process.env[SECRET]"),
        (re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE), "${{ secrets.* }}"),
        (re.compile(r"\$\{\{\s*github\.token", re.IGNORECASE), "${{ github.token }}"),
        (re.compile(r"GITHUB_TOKEN", re.IGNORECASE), "GITHUB_TOKEN"),
        (re.compile(r"NPM_TOKEN", re.IGNORECASE), "NPM_TOKEN"),
        (re.compile(r"NODE_AUTH_TOKEN", re.IGNORECASE), "NODE_AUTH_TOKEN"),
        (re.compile(r"AWS_ACCESS_KEY", re.IGNORECASE), "AWS_ACCESS_KEY"),
        (re.compile(r"AWS_SECRET", re.IGNORECASE), "AWS_SECRET"),
    ]

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 512 * 1024:
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            # Look for multiple env access patterns combined with network calls
            found_patterns = []
            for pattern, desc in patterns_with_desc:
                if pattern.search(content):
                    found_patterns.append(desc)
            
            network_match = re.search(r"(fetch|axios|http\.request|https\.request|XMLHttpRequest)", content)

            if len(found_patterns) >= 2 and network_match:
                hits.append((str(path), found_patterns, network_match.group(1)))
    return hits


def scan_for_obfuscated_code(root: Path):
    """Scan for heavily obfuscated JavaScript that may hide malicious behavior."""
    hits = []
    dir_count = 0

    # Patterns indicating obfuscation with descriptions
    obfuscation_patterns = [
        (r"\\x[0-9a-fA-F]{2}", "hex escapes"),
        (r"\\u[0-9a-fA-F]{4}", "unicode escapes"),
        (r"_0x[a-fA-F0-9]+", "obfuscator vars (_0x...)"),
        (r"\['\\x", "hex array access"),
    ]

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store", "dist", "build"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".mjs", ".cjs")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 512 * 1024:
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            # Count obfuscation indicators
            indicators = []
            for pattern, desc in obfuscation_patterns:
                matches = len(re.findall(pattern, content))
                if matches > 10:
                    indicators.append(f"{desc} ({matches}x)")

            # High density of short variable names is suspicious
            short_vars = len(re.findall(r"\b[a-z]\b", content))
            if short_vars > len(content) / 50:
                indicators.append(f"short vars ({short_vars}x)")

            if len(indicators) >= 2:
                hits.append((str(path), indicators))
    return hits


def scan_github_actions_secrets(root: Path):
    """Scan GitHub Actions workflows for suspicious secrets access patterns."""
    hits = []
    workflows_dir = root / ".github" / "workflows"

    if not workflows_dir.is_dir():
        return hits

    suspicious_patterns = [
        r"echo\s+.*\$\{\{\s*secrets\.",  # Echoing secrets
        r"env:\s*\n\s+\w+:\s*\$\{\{\s*secrets\.",  # Secrets in env vars
        r"curl.*\$\{\{\s*secrets\.",  # Secrets in curl commands
        r"wget.*\$\{\{\s*secrets\.",  # Secrets in wget commands
        r"toJSON\s*\(\s*secrets\s*\)",  # Dumping all secrets
        r"github\.event\.discussion\.body",  # Discussion body (common exfil vector)
        r"github\.event\.issue\.body",  # Issue body exfil
        r"github\.event\.comment\.body",  # Comment body exfil
    ]
    patterns = [re.compile(p, re.IGNORECASE) for p in suspicious_patterns]

    for workflow_file in workflows_dir.glob("*.y*ml"):
        try:
            content = workflow_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        matched_patterns = []
        for pattern in patterns:
            if pattern.search(content):
                matched_patterns.append(pattern.pattern)

        if matched_patterns:
            hits.append((str(workflow_file), matched_patterns))

    return hits


def scan_git_branches(root: Path):
    """Scan for Shai-Hulud related git branches (local and remote)."""
    hits = []
    git_dir = root / ".git"
    if not git_dir.is_dir():
        return hits

    suspicious_branch_patterns = [
        r"shai[-_]?hulud",
        r"sha1[-_]?hulud",
        r"malware",
        r"exfil",
        r"payload",
    ]
    pattern = re.compile("|".join(suspicious_branch_patterns), re.IGNORECASE)

    try:
        # Check local branches
        result = subprocess.run(
            ["git", "-C", str(root), "branch", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                branch = line.strip().lstrip("* ").strip()
                if pattern.search(branch):
                    hits.append(("branch", branch))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return hits


def scan_git_remotes(root: Path):
    """Scan for suspicious git remote URLs."""
    hits = []
    git_dir = root / ".git"
    if not git_dir.is_dir():
        return hits

    suspicious_patterns = [
        r"shai[-_]?hulud",
        r"sha1[-_]?hulud",
    ]
    pattern = re.compile("|".join(suspicious_patterns), re.IGNORECASE)

    try:
        result = subprocess.run(
            ["git", "-C", str(root), "remote", "-v"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if pattern.search(line):
                    parts = line.split()
                    if len(parts) >= 2:
                        hits.append((parts[0], parts[1]))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return hits


def scan_for_trufflehog_artifacts(root: Path):
    """Scan for TruffleHog or similar secret-scanning tool artifacts left by malware."""
    hits = []
    dir_count = 0

    # Patterns for TruffleHog output files and commands
    trufflehog_patterns = [
        r"trufflehog",
        r"gitleaks",
        r"detect-secrets",
        r"git-secrets",
    ]
    pattern = re.compile("|".join(trufflehog_patterns), re.IGNORECASE)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            # Check for tool-related filenames
            if pattern.search(name):
                hits.append(str(Path(dirpath) / name))
                continue

            # Check shell scripts for secret scanning tool usage
            if name.endswith((".sh", ".bash", ".zsh")):
                path = Path(dirpath) / name
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    if pattern.search(content) and re.search(r"(npm|git|github)", content, re.IGNORECASE):
                        hits.append(str(path))
                except OSError:
                    continue

    return hits


def scan_for_suspicious_namespaces(root: Path):
    """Scan lockfiles for packages from suspicious namespaces that may need review."""
    matches = {}
    dir_count = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if name not in LOCKFILE_NAMES:
                continue
            path = Path(dirpath) / name
            pkgs = {}
            if name == "package-lock.json":
                pkgs = parse_package_lock(path)
            elif name.startswith("pnpm-lock"):
                pkgs = parse_pnpm_lock(path)
            elif name == "yarn.lock":
                pkgs = parse_yarn_lock(path)

            # Check for packages from suspicious namespaces
            suspicious = []
            for pkg_name, pkg_version in pkgs.items():
                for ns in SUSPICIOUS_NAMESPACES:
                    if pkg_name.startswith(ns + "/"):
                        # Only flag if not in known compromised list (those are already caught)
                        pkg_key = f"{pkg_name}:{pkg_version}"
                        if pkg_name not in COMPROMISED_PACKAGES and pkg_key not in COMPROMISED_PACKAGES_EXACT:
                            suspicious.append((pkg_name, pkg_version, ns))
                        break

            if suspicious:
                matches[str(path)] = suspicious

    return matches


def scan_for_base64_payloads(root: Path):
    """Scan for suspicious base64-encoded payloads in source files."""
    hits = []
    dir_count = 0

    # Match large base64 strings (potential encoded payloads)
    base64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{100,}={0,2})["\']')

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store", "dist", "build"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 1024 * 1024:  # Skip files > 1MB
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            b64_matches = base64_pattern.findall(content)
            decode_match = re.search(r"(atob|Buffer\.from|base64)", content, re.IGNORECASE)
            # Flag if there are large base64 strings combined with decode operations
            if b64_matches and decode_match:
                # Get context around the base64 usage
                snippet = f"base64 string ({len(b64_matches[0])} chars) + {decode_match.group(1)}"
                hits.append((str(path), snippet))

    return hits


def scan_npmrc_files(root: Path):
    """Scan .npmrc files for suspicious registry configurations."""
    hits = []
    
    # Known official registries
    official_registries = {
        "registry.npmjs.org",
        "registry.npmmirror.com",  # China mirror
        "registry.npm.taobao.org",  # Taobao mirror (legacy)
        "npm.pkg.github.com",  # GitHub packages
        "registry.yarnpkg.com",  # Yarn
    }
    
    # Suspicious patterns in .npmrc
    suspicious_patterns = [
        (r"//[^/]+/:_authToken\s*=\s*\S+", "Auth token exposed in .npmrc"),
        (r"//[^/]+/:_password\s*=", "Password in .npmrc"),
        (r"_auth\s*=", "Legacy auth in .npmrc"),
        (r"always-auth\s*=\s*true", "always-auth enabled (may leak creds)"),
    ]
    
    # Find all .npmrc files
    npmrc_locations = [
        root / ".npmrc",
        Path.home() / ".npmrc",  # User's global .npmrc
    ]
    
    # Also walk to find project-level .npmrc files
    dir_count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)
        
        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue
        
        if ".npmrc" in filenames:
            npmrc_locations.append(Path(dirpath) / ".npmrc")
    
    # Check each .npmrc file
    for npmrc_path in set(npmrc_locations):
        if not npmrc_path.is_file():
            continue
        
        try:
            content = npmrc_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        
        findings = []
        
        # Check for non-standard registry
        registry_match = re.search(r"registry\s*=\s*https?://([^\s/]+)", content)
        if registry_match:
            registry_host = registry_match.group(1)
            if not any(official in registry_host for official in official_registries):
                findings.append(f"Non-standard registry: {registry_host}")
        
        # Check suspicious patterns
        for pattern, description in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(description)
        
        # Check for scope-specific registries pointing to unknown hosts
        scope_registries = re.findall(r"@[\w-]+:registry\s*=\s*https?://([^\s/]+)", content)
        for scope_reg in scope_registries:
            if not any(official in scope_reg for official in official_registries):
                findings.append(f"Scope registry: {scope_reg}")
        
        if findings:
            hits.append((str(npmrc_path), findings))
    
    return hits


def scan_git_hooks(root: Path):
    """Scan git hooks for suspicious content."""
    hits = []
    hooks_dir = root / ".git" / "hooks"
    
    if not hooks_dir.is_dir():
        return hits
    
    suspicious_patterns = [
        (r"curl\s+.*\|", "curl piped to shell"),
        (r"wget\s+.*\|", "wget piped to shell"),
        (r"eval\s+", "eval usage"),
        (r"base64\s+-d", "base64 decode"),
        (r"\$\(curl", "command substitution with curl"),
        (r"nc\s+-", "netcat usage"),
        (r"/dev/tcp/", "bash TCP redirect"),
    ]
    
    for hook_file in hooks_dir.iterdir():
        if not hook_file.is_file():
            continue
        # Skip sample files
        if hook_file.name.endswith(".sample"):
            continue
        
        try:
            content = hook_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        
        findings = []
        for pattern, description in suspicious_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                # Get line containing the match
                for i, line in enumerate(content.splitlines(), 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(f"{description} (line {i}): {line.strip()[:60]}")
                        break
        
        if findings:
            hits.append((str(hook_file), findings))
    
    return hits


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str:
    """Compute hash of a file using specified algorithm."""
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    else:
        hasher = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return ""


def scan_for_malicious_hashes(root: Path):
    """Scan JavaScript files for known malicious SHA256 and SHA1 hashes."""
    hits = []
    dir_count = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".mjs", ".cjs")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            # Skip very large files (unlikely to be malicious payload)
            if size > 1024 * 1024:
                continue
            
            # Check SHA256 hashes
            sha256_hash = compute_file_hash(path, "sha256")
            if sha256_hash in MALICIOUS_HASHES:
                hits.append((str(path), f"SHA256:{sha256_hash}"))
                continue
            
            # Check SHA1 hashes (Shai-Hulud 2.0 specific files)
            sha1_hash = compute_file_hash(path, "sha1")
            if sha1_hash in MALICIOUS_SHA1_HASHES:
                matched_file = MALICIOUS_SHA1_HASHES[sha1_hash]
                hits.append((str(path), f"SHA1:{sha1_hash} ({matched_file})"))

    return hits


def scan_for_exfil_endpoints(root: Path):
    """Scan for known exfiltration endpoints like webhook.site."""
    hits = []
    dir_count = 0
    pattern = re.compile("|".join(re.escape(e) for e in IOC_EXFIL_ENDPOINTS), re.IGNORECASE)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".yml", ".yaml", ".json")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 1024 * 1024:
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            match = pattern.search(content)
            if match:
                matched_endpoint = match.group(0)
                for i, line in enumerate(content.splitlines(), 1):
                    if matched_endpoint.lower() in line.lower():
                        snippet = f"line {i}: {line.strip()[:80]}"
                        hits.append((str(path), matched_endpoint, snippet))
                        break
                else:
                    hits.append((str(path), matched_endpoint, None))

    return hits


def scan_for_crypto_theft(root: Path):
    """Scan for cryptocurrency theft patterns from chalk/debug attack."""
    hits = []
    dir_count = 0
    
    # Patterns for crypto theft detection
    wallet_pattern = re.compile("|".join(re.escape(w) for w in ATTACKER_WALLETS))
    func_pattern = re.compile("|".join(re.escape(f) for f in CRYPTO_THEFT_FUNCTIONS))
    xhr_pattern = re.compile(r"XMLHttpRequest\.prototype\.send")
    
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 1024 * 1024:
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            
            findings = []
            
            # Check for known attacker wallets
            wallet_match = wallet_pattern.search(content)
            if wallet_match:
                findings.append(f"attacker wallet: {wallet_match.group(0)}")
            
            # Check for known malicious function names
            func_match = func_pattern.search(content)
            if func_match:
                findings.append(f"crypto theft function: {func_match.group(0)}")
            
            # Check for XMLHttpRequest prototype hijacking
            if xhr_pattern.search(content):
                # Only flag if combined with other suspicious patterns
                eth_addr = re.search(r"0x[a-fA-F0-9]{40}", content)
                if eth_addr or wallet_match or func_match:
                    findings.append("XMLHttpRequest hijacking + crypto patterns")
            
            if findings:
                hits.append((str(path), findings))

    return hits


def scan_for_destructive_payloads(root: Path):
    """Scan for destructive payload patterns (fallback when theft fails)."""
    hits = []
    dir_count = 0
    patterns = [re.compile(p, re.IGNORECASE) for p in DESTRUCTIVE_PATTERNS]

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}:
            dirnames[:] = []
            continue

        for name in filenames:
            if not name.endswith((".js", ".ts", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except (FileNotFoundError, OSError):
                continue
            if size > 512 * 1024:
                continue
            if not is_text_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            
            for pattern in patterns:
                match = pattern.search(content)
                if match:
                    for i, line in enumerate(content.splitlines(), 1):
                        if pattern.search(line):
                            snippet = f"line {i}: {line.strip()[:80]}"
                            hits.append((str(path), match.group(0), snippet))
                            break
                    break

    return hits


def scan_for_runner_backdoors(root: Path):
    """Scan for self-hosted runner backdoor patterns (.dev-env/, SHA1HULUD)."""
    hits = []
    dir_count = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_count += 1
        progress(dir_count)

        base = os.path.basename(dirpath)
        if base in {".git", ".cache", "node_modules"}:
            dirnames[:] = []
            continue

        # Check for .dev-env backdoor directory
        if ".dev-env" in dirnames:
            dev_env_path = Path(dirpath) / ".dev-env"
            hits.append((str(dev_env_path), "Potential runner backdoor directory"))

        # Check directory names for SHA1HULUD pattern
        for dirname in dirnames:
            for pattern in RUNNER_BACKDOOR_PATTERNS:
                if pattern.lower() in dirname.lower():
                    hits.append((str(Path(dirpath) / dirname), f"Runner backdoor pattern: {pattern}"))

        # Check workflow files for self-hosted runners with suspicious names
        for name in filenames:
            if not name.endswith((".yml", ".yaml")):
                continue
            path = Path(dirpath) / name
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            
            for pattern in RUNNER_BACKDOOR_PATTERNS:
                if pattern.lower() in content.lower():
                    hits.append((str(path), f"Self-hosted runner pattern: {pattern}"))
                    break

    return hits


def main():
    parser = argparse.ArgumentParser(
        description="Scan for Shai-Hulud npm supply-chain IOCs on a local tree."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Root path to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON for programmatic consumption",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only output findings, suppress progress messages",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()

    if not root.exists():
        print(f"[!] Root path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    # Load compromised packages from external file
    pkg_count = load_compromised_packages_file()
    if not args.json and pkg_count > 0:
        print(f"[*] Loaded {pkg_count} compromised package versions from database\n")

    global _progress_bar
    
    show_progress = not args.json and not args.quiet and sys.stderr.isatty()
    
    if not args.json:
        print(f"[*] Scanning {root} for Shai-Hulud indicators...\n")
    
    # Count directories for progress bar (21 scan phases now)
    skip_dirs = {".git", ".cache", "node_modules", ".npm", ".pnpm-store"}
    if show_progress:
        sys.stderr.write("Counting directories...\r")
        sys.stderr.flush()
        total_dirs = count_directories(root, skip_dirs)
        # Multiply by number of scan passes (roughly)
        total_work = total_dirs * 21
        _progress_bar = ProgressBar(total_work, desc="Scanning", enabled=True)
    
    # Core IOC scans
    if show_progress:
        _progress_bar.set_description("IOC files")
    ioc_files = scan_for_ioc_files(root)
    
    if show_progress:
        _progress_bar.set_description("Workflows")
    workflows = scan_for_workflows(root)
    
    if show_progress:
        _progress_bar.set_description("IOC strings")
    strings = scan_for_ioc_strings(root)
    
    if show_progress:
        _progress_bar.set_description("Lockfiles")
    lock_matches = scan_lockfiles_for_packages(root)

    # Hash verification against known malicious files
    if show_progress:
        _progress_bar.set_description("Hash check")
    malicious_hashes = scan_for_malicious_hashes(root)

    # Extended detection vectors
    if show_progress:
        _progress_bar.set_description("Domains")
    malicious_domains = scan_for_malicious_domains(root)
    
    if show_progress:
        _progress_bar.set_description("Exfil endpoints")
    exfil_endpoints = scan_for_exfil_endpoints(root)
    
    if show_progress:
        _progress_bar.set_description("Scripts")
    suspicious_scripts = scan_for_suspicious_scripts(root)
    
    if show_progress:
        _progress_bar.set_description("Env exfil")
    env_exfil = scan_for_env_exfiltration(root)
    
    if show_progress:
        _progress_bar.set_description("Obfuscation")
    obfuscated = scan_for_obfuscated_code(root)
    
    if show_progress:
        _progress_bar.set_description("GH Actions")
    actions_secrets = scan_github_actions_secrets(root)

    # Crypto theft detection (chalk/debug attack)
    if show_progress:
        _progress_bar.set_description("Crypto theft")
    crypto_theft = scan_for_crypto_theft(root)
    
    # Destructive payload detection
    if show_progress:
        _progress_bar.set_description("Destructive")
    destructive_payloads = scan_for_destructive_payloads(root)
    
    # Runner backdoor detection
    if show_progress:
        _progress_bar.set_description("Backdoors")
    runner_backdoors = scan_for_runner_backdoors(root)

    # Git repository scanning
    if show_progress:
        _progress_bar.set_description("Git branches")
    git_branches = scan_git_branches(root)
    
    if show_progress:
        _progress_bar.set_description("Git remotes")
    git_remotes = scan_git_remotes(root)
    
    if show_progress:
        _progress_bar.set_description("Git hooks")
    git_hooks = scan_git_hooks(root)

    # Additional detection vectors
    if show_progress:
        _progress_bar.set_description("Trufflehog")
    trufflehog_artifacts = scan_for_trufflehog_artifacts(root)
    
    if show_progress:
        _progress_bar.set_description("Namespaces")
    suspicious_namespaces = scan_for_suspicious_namespaces(root)
    
    if show_progress:
        _progress_bar.set_description("Base64")
    base64_payloads = scan_for_base64_payloads(root)
    
    if show_progress:
        _progress_bar.set_description(".npmrc")
    npmrc_issues = scan_npmrc_files(root)
    
    # Finish progress bar
    if show_progress and _progress_bar:
        _progress_bar.finish()
        _progress_bar = None
        print()  # Add spacing after progress bar

    # Categorize findings by severity
    high_severity = {
        "ioc_files": ioc_files,
        "suspicious_workflows": workflows,
        "compromised_packages": lock_matches,
        "malicious_hashes": malicious_hashes,  # CRITICAL: Known malicious file hashes
        "malicious_domains": malicious_domains,
        "exfil_endpoints": exfil_endpoints,  # webhook.site, etc.
        "crypto_theft": crypto_theft,  # Crypto theft patterns
        "destructive_payloads": destructive_payloads,  # rm -rf $HOME, etc.
        "runner_backdoors": runner_backdoors,  # .dev-env/, SHA1HULUD
        "actions_secrets_exposure": [(p, pats) for p, pats in actions_secrets],
        "git_branches": git_branches,
        "git_remotes": git_remotes,
        "git_hooks": git_hooks,
        "npmrc_issues": npmrc_issues,
    }

    medium_severity = {
        "ioc_strings": strings,
        "suspicious_scripts": suspicious_scripts,
        "env_exfiltration": env_exfil,
        "trufflehog_artifacts": trufflehog_artifacts,
        "base64_payloads": base64_payloads,
    }

    low_severity = {
        "obfuscated_code": obfuscated,
        "suspicious_namespaces": suspicious_namespaces,
    }

    all_findings = list(high_severity.values()) + list(medium_severity.values()) + list(low_severity.values())

    # Calculate severity counts
    high_count = sum(len(f) if isinstance(f, (list, dict)) else 0 for f in high_severity.values())
    medium_count = sum(len(f) if isinstance(f, (list, dict)) else 0 for f in medium_severity.values())
    low_count = sum(len(f) if isinstance(f, (list, dict)) else 0 for f in low_severity.values())
    total_findings = high_count + medium_count + low_count

    # JSON output mode
    if args.json:
        output = {
            "root": str(root),
            "summary": {
                "total_findings": total_findings,
                "high_severity": high_count,
                "medium_severity": medium_count,
                "low_severity": low_count,
                "compromised": high_count > 0,
            },
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
        }
        print(json.dumps(output, indent=2, default=str))
        sys.exit(2 if high_count > 0 else (1 if medium_count > 0 else 0))

    # Color and style definitions
    C_RESET = "\033[0m"
    C_BOLD = "\033[1m"
    C_DIM = "\033[2m"
    C_RED = "\033[91m"
    C_YELLOW = "\033[93m"
    C_BLUE = "\033[94m"
    C_GREEN = "\033[92m"
    C_CYAN = "\033[96m"
    C_MAGENTA = "\033[95m"
    
    # Box drawing
    BOX_TL, BOX_TR, BOX_BL, BOX_BR = "╭", "╮", "╰", "╯"
    BOX_H, BOX_V = "─", "│"
    
    def box_top(width=70):
        return f"{BOX_TL}{BOX_H * (width - 2)}{BOX_TR}"
    
    def box_mid(text, width=70):
        padding = width - 4 - len(text.replace('\033[0m', '').replace('\033[1m', '').replace('\033[91m', '').replace('\033[93m', '').replace('\033[94m', '').replace('\033[92m', '').replace('\033[96m', ''))
        # Strip ANSI for length calc
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', text)
        padding = width - 4 - len(clean)
        return f"{BOX_V} {text}{' ' * max(0, padding)} {BOX_V}"
    
    def box_bottom(width=70):
        return f"{BOX_BL}{BOX_H * (width - 2)}{BOX_BR}"
    
    def section_header(icon, title, color=C_CYAN):
        return f"\n{color}{C_BOLD}{icon}  {title}{C_RESET}"
    
    def finding_item(path, indent=0):
        prefix = "  " * indent
        return f"{prefix}{C_DIM}→{C_RESET} {path}"

    if not any(all_findings):
        print()
        print(f"{C_GREEN}{box_top()}{C_RESET}")
        print(f"{C_GREEN}{box_mid('')}{C_RESET}")
        print(f"{C_GREEN}{box_mid(f'{C_BOLD}✓  NO SHAI-HULUD INDICATORS DETECTED{C_RESET}{C_GREEN}')}{C_RESET}")
        print(f"{C_GREEN}{box_mid('')}{C_RESET}")
        print(f"{C_GREEN}{box_bottom()}{C_RESET}")
        print()
        print(f"{C_DIM}This is NOT a guarantee of safety. Consider:{C_RESET}")
        print(f"  {C_DIM}•{C_RESET} Review high-risk npm projects manually")
        print(f"  {C_DIM}•{C_RESET} Rotate credentials if you suspect exposure")
        print(f"  {C_DIM}•{C_RESET} Enable npm 2FA and restrict publish permissions")
        print(f"  {C_DIM}•{C_RESET} Run {C_CYAN}npm audit{C_RESET} for known vulnerabilities")
        print()
        sys.exit(0)

    # Header
    print()
    if high_count > 0:
        hdr_color = C_RED
        hdr_icon = "☠"
        hdr_text = "SHAI-HULUD DETECTED"
    elif medium_count > 0:
        hdr_color = C_YELLOW
        hdr_icon = "⚠"
        hdr_text = "SUSPICIOUS ACTIVITY FOUND"
    else:
        hdr_color = C_BLUE
        hdr_icon = "◐"
        hdr_text = "SCAN COMPLETE"
    
    print(f"{hdr_color}{box_top()}{C_RESET}")
    print(f"{hdr_color}{box_mid('')}{C_RESET}")
    print(f"{hdr_color}{box_mid(f'{C_BOLD}{hdr_icon}  {hdr_text}{C_RESET}{hdr_color}')}{C_RESET}")
    print(f"{hdr_color}{box_mid('')}{C_RESET}")
    print(f"{hdr_color}{box_bottom()}{C_RESET}")

    # === CRITICAL / HIGH SEVERITY ===
    if ioc_files:
        print(section_header("🚨", "CRITICAL: Malicious IOC files detected", C_RED))
        for p in sorted(ioc_files):
            print(finding_item(p, 1))

    if workflows:
        print(section_header("🚨", "CRITICAL: Suspicious GitHub workflows", C_RED))
        for p in sorted(workflows):
            print(finding_item(p, 1))

    if git_branches:
        print(section_header("🚨", "CRITICAL: Suspicious git branches", C_RED))
        for item_type, name in git_branches:
            print(f"    {C_DIM}→{C_RESET} {item_type}: {C_RED}{name}{C_RESET}")

    if git_remotes:
        print(section_header("🚨", "CRITICAL: Suspicious git remotes", C_RED))
        for remote_name, url in git_remotes:
            print(f"    {C_DIM}→{C_RESET} {remote_name}: {C_RED}{url}{C_RESET}")
    
    if git_hooks:
        print(section_header("🚨", "CRITICAL: Suspicious git hooks", C_RED))
        for hook_path, findings in git_hooks:
            print(f"    {C_DIM}📄{C_RESET} {hook_path}")
            for finding in findings:
                print(f"       {C_RED}✗{C_RESET} {C_DIM}{finding}{C_RESET}")

    if lock_matches:
        print(section_header("⛔", "HIGH: Compromised packages in lockfiles", C_RED))
        for lf, pkgs in lock_matches.items():
            print(f"    {C_DIM}📦{C_RESET} {lf}")
            for pkg_name, pkg_version, vuln_ranges in pkgs:
                if vuln_ranges == "exact match":
                    range_str = "exact match from database"
                elif vuln_ranges is None:
                    range_str = "all versions"
                else:
                    range_str = ", ".join(f"{r[0] or '0'}-{r[1] or 'latest'}" for r in vuln_ranges)
                print(f"       {C_RED}✗{C_RESET} {pkg_name}@{C_RED}{pkg_version}{C_RESET} {C_DIM}({range_str}){C_RESET}")

    if malicious_hashes:
        print(section_header("☠", "CRITICAL: Known malicious file hashes detected", C_RED))
        for path, hash_info in malicious_hashes:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_RED}✗{C_RESET} {C_RED}{hash_info}{C_RESET}")

    if malicious_domains:
        print(section_header("⛔", "HIGH: Malicious domains found", C_RED))
        for path, domain, snippet in malicious_domains:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_RED}✗{C_RESET} matched: {C_RED}{domain}{C_RESET}")
            if snippet:
                print(f"       {C_DIM}└─ {snippet}{C_RESET}")

    if exfil_endpoints:
        print(section_header("⛔", "HIGH: Exfiltration endpoints found (webhook.site, etc.)", C_RED))
        for path, endpoint, snippet in exfil_endpoints:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_RED}✗{C_RESET} endpoint: {C_RED}{endpoint}{C_RESET}")
            if snippet:
                print(f"       {C_DIM}└─ {snippet}{C_RESET}")

    if crypto_theft:
        print(section_header("⛔", "HIGH: Cryptocurrency theft patterns detected", C_RED))
        for path, findings in crypto_theft:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            for finding in findings:
                print(f"       {C_RED}✗{C_RESET} {finding}")

    if destructive_payloads:
        print(section_header("⛔", "HIGH: Destructive payload patterns detected", C_RED))
        for path, pattern, snippet in destructive_payloads:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_RED}✗{C_RESET} pattern: {C_RED}{pattern}{C_RESET}")
            if snippet:
                print(f"       {C_DIM}└─ {snippet}{C_RESET}")

    if runner_backdoors:
        print(section_header("⛔", "HIGH: Self-hosted runner backdoor patterns", C_RED))
        for path, description in runner_backdoors:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_RED}✗{C_RESET} {description}")

    if actions_secrets:
        print(section_header("⛔", "HIGH: Secrets exposure in GitHub Actions", C_RED))
        for workflow_path, patterns in actions_secrets:
            print(f"    {C_DIM}📄{C_RESET} {workflow_path}")
            for pattern in patterns:
                print(f"       {C_DIM}└─{C_RESET} {pattern}")
    
    if npmrc_issues:
        print(section_header("⛔", "HIGH: Suspicious .npmrc configuration", C_RED))
        for npmrc_path, findings in npmrc_issues:
            print(f"    {C_DIM}📄{C_RESET} {npmrc_path}")
            for finding in findings:
                print(f"       {C_RED}✗{C_RESET} {finding}")

    # === MEDIUM SEVERITY ===
    if strings:
        print(section_header("⚠", "MEDIUM: Shai-Hulud strings detected", C_YELLOW))
        for path, matched_str, snippet in strings:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_YELLOW}!{C_RESET} matched: {C_YELLOW}{matched_str}{C_RESET}")
            if snippet:
                print(f"       {C_DIM}└─ {snippet}{C_RESET}")

    if suspicious_scripts:
        print(section_header("⚠", "MEDIUM: Suspicious install scripts", C_YELLOW))
        for pkg_path, scripts in suspicious_scripts.items():
            print(f"    {C_DIM}📦{C_RESET} {pkg_path}")
            for script_name, script_content in scripts:
                print(f"       {C_YELLOW}!{C_RESET} {script_name}: {C_DIM}{script_content[:60]}...{C_RESET}")

    if env_exfil:
        print(section_header("⚠", "MEDIUM: Potential environment exfiltration", C_YELLOW))
        for path, patterns_found, network_fn in env_exfil:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_YELLOW}!{C_RESET} env vars: {C_YELLOW}{', '.join(patterns_found)}{C_RESET}")
            print(f"       {C_DIM}└─ network: {network_fn}{C_RESET}")

    if trufflehog_artifacts:
        print(section_header("⚠", "MEDIUM: Secret-scanning artifacts", C_YELLOW))
        for p in sorted(trufflehog_artifacts):
            print(finding_item(p, 1))

    if base64_payloads:
        print(section_header("⚠", "MEDIUM: Suspicious base64 payloads", C_YELLOW))
        for path, snippet in base64_payloads:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_YELLOW}!{C_RESET} {C_DIM}{snippet}{C_RESET}")

    # === LOW SEVERITY ===
    if obfuscated:
        print(section_header("◐", "LOW: Obfuscated JavaScript (review manually)", C_BLUE))
        for path, indicators in obfuscated:
            print(f"    {C_DIM}📄{C_RESET} {path}")
            print(f"       {C_BLUE}?{C_RESET} {C_DIM}{', '.join(indicators)}{C_RESET}")

    if suspicious_namespaces:
        print(section_header("◐", "LOW: Packages from targeted namespaces", C_BLUE))
        for lf, pkgs in suspicious_namespaces.items():
            print(f"    {C_DIM}📦{C_RESET} {lf}")
            for pkg_name, pkg_version, namespace in pkgs:
                print(f"       {C_BLUE}?{C_RESET} {pkg_name}@{pkg_version} {C_DIM}({namespace}){C_RESET}")

    # Summary box
    print()
    print(f"{C_DIM}{'─' * 70}{C_RESET}")
    print(f"{C_BOLD}  SUMMARY{C_RESET}")
    print(f"{C_DIM}{'─' * 70}{C_RESET}")
    print()
    print(f"  {C_BOLD}Total findings:{C_RESET} {total_findings}")
    print()
    
    # Severity bars
    max_bar = 30
    if high_count > 0 or medium_count > 0 or low_count > 0:
        max_count = max(high_count, medium_count, low_count, 1)
        
        high_bar = int((high_count / max_count) * max_bar) if high_count else 0
        med_bar = int((medium_count / max_count) * max_bar) if medium_count else 0
        low_bar = int((low_count / max_count) * max_bar) if low_count else 0
        
        print(f"  {C_RED}● Critical/High{C_RESET}  {'█' * high_bar}{C_DIM}{'░' * (max_bar - high_bar)}{C_RESET}  {high_count}")
        print(f"  {C_YELLOW}● Medium{C_RESET}         {'█' * med_bar}{C_DIM}{'░' * (max_bar - med_bar)}{C_RESET}  {medium_count}")
        print(f"  {C_BLUE}● Low{C_RESET}            {'█' * low_bar}{C_DIM}{'░' * (max_bar - low_bar)}{C_RESET}  {low_count}")
    print()

    # Recommendations
    print(f"{C_DIM}{'─' * 70}{C_RESET}")
    print(f"{C_BOLD}  RECOMMENDATIONS{C_RESET}")
    print(f"{C_DIM}{'─' * 70}{C_RESET}")
    print()

    if high_count > 0:
        print(f"  {C_RED}{C_BOLD}⚡ IMMEDIATE ACTION REQUIRED{C_RESET}")
        print()
        print(f"  {C_RED}1.{C_RESET} Disconnect affected systems from the network")
        print(f"  {C_RED}2.{C_RESET} Revoke and rotate ALL credentials:")
        print(f"     {C_DIM}•{C_RESET} GitHub PATs, npm tokens, cloud keys")
        print(f"     {C_DIM}•{C_RESET} CI/CD secrets, service accounts")
        print(f"  {C_RED}3.{C_RESET} Clean install: {C_CYAN}rm -rf node_modules && npm cache clean --force{C_RESET}")
        print(f"  {C_RED}4.{C_RESET} Audit GitHub for unauthorized repos, branches, workflows")
        print(f"  {C_RED}5.{C_RESET} Enable 2FA on all accounts")
        print()

    if medium_count > 0:
        print(f"  {C_YELLOW}{C_BOLD}⚠ FOLLOW-UP REQUIRED{C_RESET}")
        print()
        print(f"  {C_YELLOW}1.{C_RESET} Review flagged files for malicious behavior")
        print(f"  {C_YELLOW}2.{C_RESET} Check package.json scripts before {C_CYAN}npm install{C_RESET}")
        print(f"  {C_YELLOW}3.{C_RESET} Use {C_CYAN}npm install --ignore-scripts{C_RESET} in CI")
        print(f"  {C_YELLOW}4.{C_RESET} Run {C_CYAN}npm audit{C_RESET} and {C_CYAN}npm audit signatures{C_RESET}")
        print()

    if low_count > 0:
        print(f"  {C_BLUE}{C_BOLD}ℹ  BEST PRACTICES{C_RESET}")
        print()
        print(f"  {C_BLUE}•{C_RESET} Obfuscated files may be legitimate minified code")
        print(f"  {C_BLUE}•{C_RESET} Verify targeted namespace packages from official sources")
        print(f"  {C_BLUE}•{C_RESET} Use lockfile-only installs: {C_CYAN}npm ci{C_RESET}")
        print()

    # Footer
    print(f"{C_DIM}{'─' * 70}{C_RESET}")
    print(f"  {C_DIM}More info:{C_RESET} {C_CYAN}https://orca.security/resources/blog/shai-hulud-npm-malware-wave-2/{C_RESET}")
    print()

    # Exit with appropriate code for CI/CD integration
    # 2 = high severity findings (likely compromised)
    # 1 = medium severity findings (needs review)
    # 0 = no findings or low severity only
    sys.exit(2 if high_count > 0 else (1 if medium_count > 0 else 0))


if __name__ == "__main__":
    main()

