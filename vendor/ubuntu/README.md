Ubuntu-focused vendored assets live here when you want a plain `git clone` on Ubuntu to carry scanner/runtime dependencies with the repo.

Expected layout:

```text
vendor/ubuntu/
├── manifest.json
├── python/                 # wheelhouse for backend deps + semgrep + bandit
├── tools/
│   ├── python_vendor.tar.gz        # pre-bundled Semgrep + Bandit runtime
│   ├── codeql.tar.gz.part-*        # split Linux CodeQL bundle
│   └── jadx.tar.gz                 # jadx distribution
└── node_modules.tar.gz     # optional frontend tooling archive
```

Generate this tree on a connected Ubuntu machine:

```bash
cd backend
python -m scripts.prepare_ubuntu_vendor --include-node-modules
```

Notes:
- Prepare on the same CPU architecture as the target Ubuntu VM.
- Prepare on the same Python minor version as the target Ubuntu VM if you plan to commit the wheelhouse.
- `install.sh` automatically prefers `vendor/ubuntu/` over network installs.
- `install.sh` automatically extracts the vendored tool archives into `backend/tools/`, so Semgrep, Bandit, CodeQL, and jadx do not depend on user-level installs.
- Large bundles are split into Git-safe `*.part-*` chunks when needed; `install.sh` reassembles them automatically.
- `node_modules.tar.gz` is optional if the target machine can use your internal npm mirror.

Target Ubuntu VM flow after this directory is committed:

```bash
git clone <your-vragent-repo-url>
cd vragent
bash ./install.sh --offline
bash ./start.sh
```

If you intentionally want to use your internal `pip` and `npm` mirrors instead of the vendored wheelhouse or `node_modules.tar.gz`, run `bash ./install.sh` without `--offline`.
