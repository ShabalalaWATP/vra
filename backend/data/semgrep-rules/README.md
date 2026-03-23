# Semgrep Rules — Offline Security Rule Database

VRAgent ships with **bundled baseline rules** for 12 languages. These work
immediately in an air-gapped environment with no setup required.

## Bundled Rules (ships with VRAgent)

| Language | File | Rules | Covers |
|----------|------|-------|--------|
| Python | `python/security.yaml` | 21 | SQLi, command injection, eval, pickle, yaml, path traversal, SSRF, crypto, XSS, JWT, CSRF, XXE |
| Python | `python/frameworks.yaml` | 21 | Django, Flask, FastAPI, SQLAlchemy framework-specific patterns |
| JavaScript | `javascript/security.yaml` | 16 | XSS, SQLi, command injection, eval, path traversal, SSRF, prototype pollution, ReDoS |
| JavaScript | `javascript/frameworks.yaml` | 15 | Express, React, Node.js, MongoDB NoSQL injection, JWT, file upload, CORS |
| TypeScript | `typescript/security.yaml` | 6 | Prisma raw queries, NestJS auth guards, Zod passthrough, type safety bypasses |
| Java | `java/security.yaml` | 11 | SQLi, deserialization, XXE, command injection, weak ciphers, Spring CSRF/CORS |
| Go | `go/security.yaml` | 9 | SQLi, shell exec, path traversal, SSRF, weak crypto, TLS skip verify |
| Ruby | `ruby/security.yaml` | 8 | SQLi, system exec, XSS (raw/html_safe), Marshal, CSRF, mass assignment |
| PHP | `php/security.yaml` | 9 | SQLi, exec, XSS, unserialize, file inclusion, eval, SSRF, weak hash |
| C# | `csharp/security.yaml` | 8 | SQLi, Process.Start, Html.Raw, BinaryFormatter, XXE, weak crypto |
| Kotlin | `kotlin/security.yaml` | 6 | SQLi, Runtime.exec, WebView JS, cleartext traffic, deserialization |
| Terraform | `terraform/security.yaml` | 7 | S3 public, open security groups, RDS public, no encryption, hardcoded secrets |
| Dockerfile | `dockerfile/security.yaml` | 6 | Root user, :latest tag, curl|sh, secrets in ENV |
| Generic | `generic/security.yaml` | 7 | AWS keys, private keys, GitHub tokens, JWT, connection strings |

**Total: ~150 bundled rules**

## Expanding Coverage (recommended)

The bundled rules cover the most critical patterns. For full coverage
(3000+ rules), download the official Semgrep community rules:

### On an internet-connected machine:

```bash
cd backend
python -m scripts.download_semgrep_rules --output data/semgrep-rules/
```

This downloads the full [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)
repository (LGPL-2.1 licensed) plus community extras.

### Copy to air-gapped deployment:

```bash
# On internet machine — create the bundle
tar czf semgrep-rules-bundle.tar.gz data/semgrep-rules/

# Transfer to air-gapped machine (USB, secure file transfer, etc.)

# On air-gapped machine — extract
cd /path/to/vragent/backend
tar xzf semgrep-rules-bundle.tar.gz
```

The app will automatically detect and use all `.yaml` and `.yml` rule files
in the `data/semgrep-rules/` directory tree.

## Adding Custom Rules

Drop any valid Semgrep YAML rule file into the appropriate language
subdirectory. The app will pick it up on the next scan.

```yaml
# data/semgrep-rules/python/my-custom-rules.yaml
rules:
  - id: my-org.python.custom-check
    pattern: dangerous_function($INPUT)
    message: "Custom check for our internal library."
    severity: WARNING
    languages: [python]
    metadata:
      category: security
      confidence: MEDIUM
```
