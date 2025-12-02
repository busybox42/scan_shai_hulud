# 🪱 scan_shai_hulud

A comprehensive scanner for detecting [Shai-Hulud](https://orca.security/resources/blog/shai-hulud-npm-malware-wave-2/) npm supply chain malware and related indicators of compromise (IOCs).

## What is Shai-Hulud?

Shai-Hulud is a sophisticated npm supply chain attack that has compromised hundreds of packages across multiple waves. The malware:

- Steals credentials (npm tokens, GitHub PATs, AWS keys, etc.)
- Exfiltrates secrets via GitHub discussions and malicious domains
- Creates unauthorized repositories and branches for data exfiltration
- Spreads through compromised maintainer accounts
- Uses TruffleHog to scan for additional secrets

## Features

- **21 detection vectors** covering files, packages, code patterns, and configurations
- **1,677+ compromised packages** database from multiple security advisories
- **Known malicious file hashes** - SHA256 verification against 7 known malicious bundles
- **Cryptocurrency theft detection** - wallet addresses, malicious functions from chalk/debug attack
- **Exfiltration endpoint detection** - webhook.site, Discord webhooks, Telegram, etc.
- **Destructive payload detection** - `rm -rf $HOME`, `fs.rmSync` with recursive
- **Self-hosted runner backdoor detection** - `.dev-env/`, SHA1HULUD patterns
- **Matched content display** - see exactly what triggered each finding
- **Severity classification** - Critical, High, Medium, Low
- **Progress bar** with phase indicators
- **CI/CD integration** - exit codes and JSON output
- **Zero dependencies** - single Python file, stdlib only

## Installation

```bash
# Clone or download
git clone https://github.com/yourusername/scan_shai_hulud.git
cd scan_shai_hulud

# Or just download the script
curl -O https://raw.githubusercontent.com/yourusername/scan_shai_hulud/main/scan_shai_hulud.py
chmod +x scan_shai_hulud.py
```

**Requirements:** Python 3.7+

## Usage

```bash
# Scan current directory
python scan_shai_hulud.py

# Scan specific path
python scan_shai_hulud.py /path/to/project

# JSON output for CI/CD
python scan_shai_hulud.py --json /path/to/project

# Quiet mode (no progress bar)
python scan_shai_hulud.py -q /path/to/project
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings or low severity only |
| `1` | Medium severity findings (review recommended) |
| `2` | High/Critical severity findings (likely compromised) |

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Scan for Shai-Hulud
  run: |
    python scan_shai_hulud.py --json . > scan_results.json
    python scan_shai_hulud.py .
```

## Detection Methods

### 🚨 Critical Severity

| Detection | Description |
|-----------|-------------|
| IOC Files | Known malicious filenames (`cloud.json`, `truffleSecrets.json`, `bundle.js`, etc.) |
| Workflows | Suspicious GitHub Actions (`discussion.yaml`, `shai-hulud-workflow.yml`) |
| Git Branches | Branches named `shai-hulud`, `malware`, `exfil`, etc. |
| Git Remotes | Remote URLs pointing to Shai-Hulud repositories |
| Git Hooks | Malicious content in `.git/hooks/` |

### ⛔ High Severity

| Detection | Description |
|-----------|-------------|
| Compromised Packages | 1,677+ known compromised package versions |
| Malicious File Hashes | SHA256 match against 7 known malicious bundle.js variants |
| Malicious Domains | Known exfiltration endpoints (`npm-stats.com`, etc.) |
| Exfil Endpoints | webhook.site, Discord webhooks, Telegram, ngrok, etc. |
| Crypto Theft | Attacker wallet addresses, malicious function names |
| Destructive Payloads | `rm -rf $HOME`, `fs.rmSync` recursive delete patterns |
| Runner Backdoors | `.dev-env/` directories, SHA1HULUD self-hosted runners |
| Secrets Exposure | GitHub Actions leaking secrets via echo, curl, toJSON |
| .npmrc Issues | Non-standard registries, exposed auth tokens |

### ⚠️ Medium Severity

| Detection | Description |
|-----------|-------------|
| IOC Strings | `Shai-Hulud`, `The Continued Coming`, etc. in source files |
| Suspicious Scripts | Dangerous patterns in `preinstall`/`postinstall` scripts |
| Env Exfiltration | Multiple secret access patterns + network calls |
| Base64 Payloads | Large encoded strings with decode operations |
| TruffleHog Artifacts | Secret-scanning tool output files |

### ◐ Low Severity

| Detection | Description |
|-----------|-------------|
| Obfuscated Code | Heavy use of hex escapes, `_0x` vars (may be minified code) |
| Targeted Namespaces | Packages from `@ctrl`, `@crowdstrike`, `@art-ws`, etc. |

## Example Output

```
╭──────────────────────────────────────────────────────────────────────╮
│                                                                      │
│ ⚠  SUSPICIOUS ACTIVITY FOUND                                         │
│                                                                      │
╰──────────────────────────────────────────────────────────────────────╯

⚠  MEDIUM: Suspicious base64 payloads
    📄 /project/src/lib/pdf.min.js
       ! base64 string (2048 chars) + Buffer.from

◐  LOW: Obfuscated JavaScript (review manually)
    📄 /project/coverage/lcov-report/prettify.js
       ? hex escapes (156x), short vars (2340x)

──────────────────────────────────────────────────────────────────────
  SUMMARY
──────────────────────────────────────────────────────────────────────

  Total findings: 2

  ● Critical/High  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0
  ● Medium         ███████████████░░░░░░░░░░░░░░░  1
  ● Low            ██████████████████████████████  1

──────────────────────────────────────────────────────────────────────
  RECOMMENDATIONS
──────────────────────────────────────────────────────────────────────

  ⚠ FOLLOW-UP REQUIRED

  1. Review flagged files for malicious behavior
  2. Check package.json scripts before npm install
  3. Use npm install --ignore-scripts in CI
  4. Run npm audit and npm audit signatures

  ℹ  BEST PRACTICES

  • Obfuscated files may be legitimate minified code
  • Verify targeted namespace packages from official sources
  • Use lockfile-only installs: npm ci
```

## Compromised Packages

The scanner includes a comprehensive database of **1,677+ compromised package versions** from multiple attack campaigns:

**September 2025 - Chalk/Debug Crypto Theft Attack:**
- Popular packages with 2+ billion weekly downloads: `chalk`, `debug`, `ansi-styles`, `supports-color`
- XMLHttpRequest hijacking to steal cryptocurrency wallet addresses

**September/November 2025 - Shai-Hulud Worm:**
- `@ctrl/tinycolor`, `@ctrl/ngx-codemirror`, `@ctrl/deluge`
- `@asyncapi/*`, `@zapier/*`, `@ensdomains/*`, `@posthog/*`
- `@crowdstrike/*`, `@art-ws/*`, `@postman/*`
- Self-replicating via compromised maintainer accounts

**November 2025 - "Second Coming" Fake Bun Attack:**
- Fake Bun runtime installer via `setup_bun.js`
- Automated TruffleHog credential scanning
- Self-hosted GitHub Actions runner backdoors

**Historical Supply Chain Attacks:**
- `event-stream`, `flatmap-stream` (2018)
- `coa`, `rc`, `ua-parser-js` (2021)
- `colors`, `faker` protestware (2022)
- `node-ipc` peacenotwar malware (2022)

The package list is maintained in `data/compromised-packages.txt` and sourced from:
- [StepSecurity](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Semgrep Security Advisory](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- [JFrog](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- [Socket.dev](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)
- [gensecaihq/Shai-Hulud-2.0-Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector)
- [Aikido Security](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [Wiz.io](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

## What To Do If Compromised

If the scanner finds **High/Critical** severity issues:

1. **Disconnect** affected systems from the network
2. **Revoke and rotate** ALL credentials:
   - GitHub personal access tokens
   - npm tokens (`NPM_TOKEN`, `NODE_AUTH_TOKEN`)
   - Cloud provider keys (AWS, GCP, Azure)
   - CI/CD secrets
3. **Clean install** dependencies:
   ```bash
   rm -rf node_modules package-lock.json
   npm cache clean --force
   npm install
   ```
4. **Audit GitHub** for unauthorized:
   - Repositories (especially named "Shai-Hulud")
   - Branches
   - Workflow changes
   - Deploy keys and OAuth apps
5. **Enable 2FA** on all accounts

## References

**Primary Sources:**
- [Aikido Security: Shai-Hulud Strikes Again](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [Wiz.io: Shai-Hulud 2.0 Investigation](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Orca Security: Shai-Hulud Wave 2 Analysis](https://orca.security/resources/blog/shai-hulud-npm-malware-wave-2/)
- [StepSecurity: @ctrl/tinycolor Compromise](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)

**Detection Tools:**
- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) - Bash-based detector (1677+ packages)
- [gensecaihq/Shai-Hulud-2.0-Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector) - GitHub Action with SARIF support
- [CyberDracula/shai-hulud-2-scanner](https://github.com/CyberDracula/shai-hulud-2-scanner) - Node.js forensic tool (behavioral heuristics)

**Additional Resources:**
- [Kaspersky Securelist: Shai-Hulud Worm Analysis](https://securelist.com/shai-hulud-worm-infects-500-npm-packages-in-a-supply-chain-attack/)
- [Cohesity: Supply Chain Compromise Advisory](https://www.cohesity.com/trust/redlab/advisories/supply-chain-compromise-shai-hulud/)

## License

MIT

## Contributing

PRs welcome! If you discover new IOCs or compromised packages, please open an issue or PR.

**To add new compromised packages**, edit `data/compromised-packages.txt`:

```
# Format: package_name:version (one per line)
# Lines starting with # are comments
@scope/package-name:1.2.3
another-package:4.5.6
```

**To add new detection patterns**, edit the relevant constants in `scan_shai_hulud.py`:

```python
# Known malicious file hashes
MALICIOUS_HASHES = {"sha256hash..."}

# Exfiltration endpoints
IOC_EXFIL_ENDPOINTS = {"webhook.site", ...}

# Attacker wallet addresses
ATTACKER_WALLETS = {"0x...", ...}
```

