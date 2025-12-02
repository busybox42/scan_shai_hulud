# Test Samples for scan_shai_hulud

This directory contains **intentionally malicious-looking files** for testing the scanner.

⚠️ **These are NOT actual malware** - they contain patterns that trigger detection.

## Expected Detections

Run: `python ../scan_shai_hulud.py .`

| File | Expected Detection | Severity |
|------|-------------------|----------|
| `cloud.json` | IOC filename | HIGH |
| `truffleSecrets.json` | IOC filename | HIGH |
| `.github/workflows/discussion.yml` | Suspicious workflow | HIGH |
| `package-lock.json` | Compromised package | HIGH |
| `malicious-script.js` | Exfil endpoint, IOC strings | HIGH |
| `package.json` | Suspicious install script | MEDIUM |
| `obfuscated.js` | Obfuscation patterns | LOW |
| `env-stealer.js` | Env exfiltration pattern | MEDIUM |

## Usage

```bash
cd test-samples
python ../scan_shai_hulud.py .

# Or with JSON output
python ../scan_shai_hulud.py --json . | jq '.summary'
```

Expected result: Exit code 2 (high severity findings)

