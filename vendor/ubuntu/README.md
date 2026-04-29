Ubuntu-focused vendored assets live here when you want a plain `git clone` on Ubuntu to carry scanner/runtime dependencies with the repo.

This directory is a clone-bundle payload. It must be generated on a connected Ubuntu/Linux host with the same CPU architecture and Python minor version as the air-gapped target.

Current VRAgent requirement: Python 3.12.x. `manifest.json` should report Python 3.12.x and a matching CPU architecture; rebuild this directory before using `install.sh --offline` if it does not.
The frontend toolchain requires Node.js 22.x LTS or newer; the current `node_modules.tar.gz` was built with Node.js 22.22.2 and npm 10.9.7.

Expected layout:

```text
vendor/ubuntu/
├── manifest.json           # target compatibility and exact bundled versions
├── python/                 # CPython 3.12 Linux wheelhouse for backend deps + semgrep + bandit
├── tools/
│   ├── python_vendor.tar.gz        # pre-bundled Semgrep + Bandit runtime
│   ├── codeql.tar.gz.part-*        # split Linux CodeQL bundle
│   └── jadx.tar.gz                 # jadx distribution
└── node_modules.tar.gz     # optional frontend tooling archive
```

Generate this tree on a connected Ubuntu machine:

```bash
bash ./prepare_ubuntu_vendor.sh
```

Notes:
- Prepare on the same CPU architecture as the target Ubuntu VM.
- Prepare with Python 3.12.x; VRAgent rejects wheelhouses built with another Python minor version.
- The wrapper selects native Linux Python 3.12 automatically and includes `node_modules.tar.gz` by default.
- `install.sh` automatically prefers `vendor/ubuntu/` over network installs.
- `install.sh` automatically extracts the vendored tool archives into `backend/tools/`, so Semgrep, Bandit, CodeQL, and jadx do not depend on user-level installs.
- Large bundles are split into Git-safe `*.part-*` chunks when needed; `install.sh` reassembles them automatically.
- Use `--skip-node-modules` only if the target machine can use your internal npm mirror.

Expected versions in the manifest:

| Component | Expected version |
|-----------|------------------|
| Python minor | 3.12 |
| Semgrep | 1.156.0 |
| Bandit | 1.9.4 |
| tree-sitter | 0.20.4 |
| tree-sitter-languages | 1.10.2 |
| Node.js | 22.22.2 for current `node_modules.tar.gz` |
| npm | 10.9.7 for current `node_modules.tar.gz` |
| CodeQL | 2.25.1, if included |
| jadx | 1.5.5, if included |
| package-lock | v3 |

Target Ubuntu VM flow after this directory is committed:

```bash
git clone <your-vragent-repo-url>
cd vragent
bash ./install.sh --offline
bash ./start.sh
```

If you intentionally want to use your internal `pip` and `npm` mirrors instead of the vendored wheelhouse or `node_modules.tar.gz`, run `bash ./install.sh` without `--offline`.
