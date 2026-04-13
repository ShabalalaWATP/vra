.PHONY: dev setup db migrate backend frontend serve install install-all clean \
       airgap-bundle ubuntu-vendor \
       download-rules download-advisories download-icons download-codeql download-data \
       check-tools

# ── Quick start ──────────────────────────────────────────────────
# Full dev environment (db + backend + frontend)
dev: db backend frontend

# ── Database ─────────────────────────────────────────────────────
db:
	cd backend && python -m alembic upgrade head

migrate:
	cd backend && python -m alembic upgrade head

# ── Servers ──────────────────────────────────────────────────────
backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd frontend && npm run dev

serve:
	cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# ── Installation ─────────────────────────────────────────────────
# Install Python + Node dependencies only
install:
	cd backend && pip install -e ".[dev]"
	if [ -f frontend/package-lock.json ]; then cd frontend && (npm ci || npm install); else cd frontend && npm install; fi

# Install everything: deps + scanners + data + codeql + jadx
install-all: install install-scanners download-data download-codeql download-jadx
	@echo ""
	@echo "=== All dependencies installed ==="
	@echo "Run 'make check-tools' to verify installation."

# Install scanner tools (Semgrep, Bandit; ESLint comes from frontend deps)
install-scanners:
	pip install semgrep bandit
	@echo "ESLint is installed locally in frontend/node_modules via the frontend install step."

airgap-bundle:
	cd backend && python -m scripts.prepare_airgap_bundle --output ../vragent-airgap-bundle.tar.gz

ubuntu-vendor:
	cd backend && python -m scripts.prepare_ubuntu_vendor

# ── Offline data downloads ───────────────────────────────────────
# Download all offline data (rules + advisories + icons)
download-data: download-rules download-advisories download-icons

# Download Semgrep community rules (~50MB)
download-rules:
	cd backend && python -m scripts.download_semgrep_rules --output data/semgrep-rules/

# Download OSV advisory database (~250MB)
download-advisories:
	cd backend && python -m scripts.sync_advisories --output data/advisories/

# Download technology icons (~5MB)
download-icons:
	cd backend && python -m scripts.download_icons --output data/icons/

# Download CodeQL CLI (~500MB)
download-codeql:
	cd backend && python -m scripts.download_codeql --output tools/codeql

# Download jadx APK decompiler (~30MB)
download-jadx:
	cd backend && python -m scripts.download_jadx --output tools/jadx

# ── Utilities ────────────────────────────────────────────────────
# Check which tools are installed and available
check-tools:
	@echo "=== VRAgent Tool Check ==="
	@echo ""
	@printf "  Python:     " && python --version 2>&1 || echo "NOT FOUND"
	@printf "  Node.js:    " && node --version 2>&1 || echo "NOT FOUND"
	@printf "  npm:        " && npm --version 2>&1 || echo "NOT FOUND"
	@printf "  Semgrep:    " && semgrep --version 2>&1 || echo "NOT FOUND"
	@printf "  Bandit:     " && bandit --version 2>&1 || echo "NOT FOUND"
	@printf "  ESLint:     " && (test -x frontend/node_modules/.bin/eslint && frontend/node_modules/.bin/eslint --version 2>&1 || echo "NOT FOUND")
	@printf "  CodeQL:     " && (backend/tools/codeql/codeql version --format=terse 2>&1 || codeql version --format=terse 2>&1 || echo "NOT FOUND")
	@echo "  SQLite DB:  $$(test -f backend/data/vragent.db && echo 'backend/data/vragent.db' || echo 'NOT FOUND')"
	@echo ""
	@echo "  Semgrep rules: $$(find backend/data/semgrep-rules -name '*.yaml' 2>/dev/null | wc -l) rules"
	@echo "  Advisory DB:   $$(test -f backend/data/advisories/manifest.json && echo 'present' || echo 'NOT FOUND')"
	@echo "  Icons:         $$(find backend/data/icons -name '*.svg' 2>/dev/null | wc -l) icons"
	@echo ""

# Create a new alembic migration
migration:
	cd backend && python -m alembic revision --autogenerate -m "$(msg)"

# Clean up everything
clean:
	docker compose down -v
	rm -rf backend/__pycache__ backend/app/__pycache__
	rm -rf frontend/node_modules frontend/dist
