# VRAgent

**Offline AI-Assisted Static Vulnerability Research Platform**

<p align="center">
  <img src="frontend/public/logo.jpg" alt="VRAgent Logo" width="200" />
</p>

VRAgent is a production-grade, fully offline security analysis platform that combines deterministic static analysis tools (Semgrep, Bandit, ESLint, CodeQL) with AI-driven multi-pass code inspection to produce analyst-quality vulnerability reports. It is designed to run in air-gapped environments with no internet dependency at runtime.

VRAgent is **not** a scanner dashboard. It is **not** an LLM wrapper. It is a hybrid agentic system where:

- **Deterministic tools** provide breadth, repeatability, and structured signals
- **AI agents** provide reasoning, context, prioritisation, verification, and explanation
- **The AI directly reads and analyses source files** throughout the scan lifecycle
- **The system revisits files and adjusts its beliefs** based on new evidence

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Scan Pipeline](#scan-pipeline)
- [Agent Orchestrator](#agent-orchestrator)
- [Scanner Integrations](#scanner-integrations)
- [Advanced Analysis](#advanced-analysis)
  - [APK / Android Scanning](#apk--android-scanning)
  - [Documentation Intelligence](#documentation-intelligence)
- [Database Schema](#database-schema)
- [Frontend](#frontend)
- [Report Generation](#report-generation)
- [Project Structure](#project-structure)
- [Installation — Air-Gapped Deployment](#installation--air-gapped-deployment)
  - [Prerequisites](#prerequisites)
  - [CodeQL Installation](#codeql-installation)
  - [jadx Installation](#jadx-installation-for-apk-scanning)
  - [Windows 11 Installation](#windows-11-installation)
  - [Ubuntu Installation](#ubuntu-installation)
  - [Offline Data Preparation](#offline-data-preparation)
  - [First Run](#first-run)
- [Configuration](#configuration)
- [LLM Provider Setup](#llm-provider-setup)
- [Scan Modes](#scan-modes)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Fully offline / air-gapped** — no runtime internet calls. All rules, advisories, icons, and assets are local
- **6 integrated scanners** — Semgrep (1,952 rules), Bandit, ESLint (45+ security rules), CodeQL (2,000+ security queries), secrets scanner (50+ patterns), dependency auditor (257K advisories)
- **257,000+ vulnerability advisories** — offline OSV database covering npm, PyPI, Maven, Go, Crates, NuGet, RubyGems, Packagist, Pub, Hex
- **7 specialised AI agents** — triage, architecture, dependency risk, investigation, rule selection, verification, reporting
- **Agentic multi-pass investigation** — the AI planner chooses between 7 actions (INVESTIGATE_FILES, TRACE_FLOW, DEEP_DIVE, CROSS_REFERENCE, TARGETED_SCAN, VERIFY_EARLY, STOP) based on live scan state
- **20 AI tools** — file reading, code search, call graph traversal, import resolution, taint flow queries, scanner execution, dependency queries, Android-specific tools
- **Taint tracking** — AI-inferred source-to-sink data flow analysis verified against static call graphs with inter-procedural resolution
- **Call graph & import resolution** — static call graph construction, import resolution across files, callers/callees queries exposed to AI
- **Exploit validation & PoC generation** — the verifier agent assesses exploitability and generates proof-of-concept templates
- **Documentation intelligence** — reads README, SECURITY.md, API docs, and setup guides early in the scan to inform the AI's investigation strategy
- **APK / Android scanning** — upload APK files for jadx decompilation with Android-specific analysis (manifest parsing, exported components, 6 Android-specific AI tools)
- **OWASP Top 10 mapping** — every finding mapped to OWASP 2021 categories via CWE IDs (200+ CWE-to-OWASP mappings) with category-based fallback
- **Executive risk score** — A-F letter grade with weighted severity/confidence/exploitability scoring
- **CWE references** — each finding includes CWE IDs, displayed as badges in the UI and used for OWASP mapping
- **Component security scorecard** — per-component A-F grades based on finding density and severity
- **SBOM (Software Bill of Materials)** — full dependency inventory with version, ecosystem, dev/prod classification, and vulnerability status
- **Obfuscation detection** — entropy-based and pattern-based detection of minified, packed, or obfuscated code with report-level noting
- **Monorepo support** — workspace detection for Yarn, npm, Lerna, Gradle, Maven, Go workspaces
- **Real-time progress** — WebSocket-driven live scan progress with phase tracking, ETA estimation, scan line animations, and terminal-style event logs
- **Professional reports** — AI-generated narratives with 4 architecture diagrams, 7 Chart.js visualizations, OWASP mapping, component scorecard, SBOM, scan coverage, and risk scoring
- **PDF & DOCX export** — structured reports with headings, tables, code blocks, severity labels, and embedded diagrams
- **449 technology icons** — bundled SVG icons for languages, frameworks, databases, and cloud services, embedded in diagrams via base64 data URIs
- **4 architecture diagrams** — System Overview, Security Architecture, Data Flow, and Attack Surface diagrams with fullscreen zoom/pan viewer
- **Scan history** — saved scans with search, status filtering, and delete functionality
- **Cross-platform** — runs on Windows 11 and Ubuntu Linux
- **Context-window aware** — supports 128K, 200K, and 400K token models with adaptive compaction
- **Dark-themed analyst UI** — HUD-style interface with animated progress, gradient borders, particle backgrounds, and Chart.js analytics dashboard

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          FRONTEND (React 19)                          │
│  Home │ Dashboard │ New Scan │ Progress │ Report │ History │ Settings  │
│                                                                       │
│  TypeScript · Tailwind CSS · Vite · Chart.js · WebSocket              │
│  Locally bundled: JetBrains Mono font · lucide-react icons            │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ HTTP / WebSocket
┌───────────────────────────────┴──────────────────────────────────────┐
│                         BACKEND (FastAPI)                              │
│                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────────┐  │
│  │  REST API     │  │  WebSocket   │  │  Background Task Runner     │  │
│  │  /api/*       │  │  /ws/{id}    │  │  Scan Pipeline Orchestrator │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬─────────────────┘  │
│         │                 │                       │                    │
│  ┌──────┴─────────────────┴───────────────────────┴──────────────────┐│
│  │                     SCAN ORCHESTRATOR                              ││
│  │                                                                    ││
│  │  ┌──────────┐ ┌───────────┐ ┌─────────────┐ ┌──────────────────┐  ││
│  │  │ Triage   │→│Architecture│→│ Dependency  │→│  Investigator    │  ││
│  │  │ Agent    │ │ Agent      │ │ Risk Agent  │ │  Agent (agentic) │  ││
│  │  └──────────┘ └───────────┘ └─────────────┘ └────────┬─────────┘  ││
│  │       │                                               │            ││
│  │       │  ┌───────────────┐ ┌───────────┐ ┌──────────┐│            ││
│  │       │  │ Rule Selector │←│  Verifier │←│ Reporter ││            ││
│  │       │  │ Agent         │ │  Agent    │ │ Agent    │←┘           ││
│  │       │  └───────────────┘ └───────────┘ └──────────┘             ││
│  │       │                                                            ││
│  │  ┌────┴────────────────────────────────────────────────────────┐   ││
│  │  │ Planner (7 actions) · 20 AI Tools · Doc Intelligence       │   ││
│  │  │ ScanContext · LLMClient · AgentToolkit · EventBus           │   ││
│  │  └────────────────────────────────────────────────────────────┘   ││
│  └───────────────────────────────────────────────────────────────────┘│
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                      SCANNER ADAPTERS                          │   │
│  │  Semgrep │ Bandit │ ESLint │ CodeQL │ Secrets │ DepAudit      │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                     ANALYSIS MODULES                           │   │
│  │  CallGraph · ImportResolver · TaintTracking · InterProcedural  │   │
│  │  TreeSitter · FileScorer · Obfuscation · Diagram · DocIntel    │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                     EXTERNAL TOOLS                             │   │
│  │  CodeQL CLI (2,000+ queries) │ jadx (APK decompiler)          │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  Python 3.11+ · FastAPI · SQLAlchemy · Pydantic · httpx · matplotlib  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────┴──────────────────────────────────────┐
│                        POSTGRESQL 16                                  │
│  projects · scans · files · findings · evidence · reports · exports   │
│  dependencies · secrets · scanner_results · symbols · agent_decisions │
└──────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────┴──────────────────────────────────────┐
│                       OFFLINE DATA STORES                             │
│  1,952 Semgrep rules │ 45+ ESLint security rules │ CodeQL query packs │
│  257K OSV advisories │ 449 technology SVG icons │ Bundled fonts        │
└──────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────┴──────────────────────────────────────┐
│                    LOCAL LLM ENDPOINT                                  │
│  Any OpenAI-compatible API — auto-detects /v1/, /chat/completions,    │
│  /api/v1/ paths. Works with vLLM, Ollama, llama.cpp, LocalAI, TGI    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Scan Pipeline

VRAgent runs a 7-stage pipeline with feedback loops. Each stage is executed by a specialised AI agent with access to 20 tools, 6 scanners, and the shared scan context. An agentic planner decides what to investigate next.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            SCAN PIPELINE                                  │
│                                                                           │
│  ┌────────────┐    ┌───────────────┐    ┌───────────────┐   ┌──────────┐ │
│  │ 1. TRIAGE  │───→│2. UNDERSTAND  │───→│3. DEPENDENCIES│──→│4. INVEST-│ │
│  │            │    │               │    │               │   │  IGATE   │ │
│  │Fingerprint │    │AI reads files │    │Match packages │   │Agentic   │ │
│  │6 scanners  │    │4 diagrams     │    │vs 257K CVEs   │   │multi-pass│ │
│  │Read docs   │    │Doc-informed   │    │CWE enrichment │   │20 tools  │ │
│  │Call graph  │    │Components     │    │Usage analysis  │   │Planner   │ │
│  │Score files │    │Attack surface │    │               │   │decides   │ │
│  └────────────┘    └───────────────┘    └───────┬───────┘   └────┬─────┘ │
│                                                  │                │       │
│                                         ┌────────┴────────┐      │       │
│                                         │FEEDBACK: boost   │      │       │
│                                         │files importing   │──────┘       │
│                                         │vulnerable deps   │              │
│                                         └──────────────────┘              │
│                                                                           │
│  ┌───────────────┐   ┌───────────────┐    ┌──────────────────┐           │
│  │5. TARGETED    │──→│6. VERIFY      │───→│7. REPORT         │           │
│  │   SCAN        │   │               │    │                  │           │
│  │AI selects     │   │Challenge each │    │AI narratives     │           │
│  │Semgrep rules  │   │finding, PoC   │    │Risk score (A-F)  │           │
│  │for follow-up  │   │generation,    │    │OWASP mapping     │           │
│  │               │   │exploit chains │    │SBOM, charts      │           │
│  │               │   │taint verify   │    │4 diagrams        │           │
│  └───────┬───────┘   └───────┬───────┘    └──────────────────┘           │
│          │                    │                                            │
│  ┌───────┴────────┐   ┌──────┴────────┐                                   │
│  │FEEDBACK: new   │   │FEEDBACK: if   │                                   │
│  │hits trigger    │   │<30% confirmed │                                   │
│  │mini-invest.    │   │re-investigate │                                   │
│  └────────────────┘   └───────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Repository Triage

The Triage Agent rapidly fingerprints the codebase:

- **Language detection** — identifies all programming languages, frameworks, build tools, and package ecosystems
- **File indexing** — catalogues all source files, filters out binaries, generated code, vendor directories, and node_modules
- **Monorepo detection** — identifies workspace managers (Yarn workspaces, Lerna, npm workspaces, Gradle multi-project, Maven multi-module, Go workspaces)
- **Obfuscation detection** — entropy-based analysis to identify minified, packed, or obfuscated files. Reports obfuscation level and confidence in the final report
- **Documentation discovery** — reads README, SECURITY.md, API docs, setup guides, .env.example files (up to 15 docs, prioritised by relevance)
- **Baseline scanner runs** — executes all applicable scanners in parallel (Semgrep baseline, Bandit for Python, ESLint for JS/TS, CodeQL database creation, secrets scan, dependency audit)
- **Documentation AI analysis** — one LLM call extracts env vars, API endpoints, auth mechanisms, deployment info, default credentials, and investigation hints from project docs
- **File priority scoring** — scores every file using 15+ deterministic signals (entry points, routes, auth code, DB access, crypto, deserialization, scanner hit density, dependency risk proximity), boosted by documentation intelligence
- **Call graph construction** — static call graph built from import analysis and call site matching across files
- **Structural metadata extraction** — Tree-sitter parsing for symbol extraction (functions, classes, imports, routes)

### Stage 2: Application Understanding

The Architecture Agent builds a mental model of the application:

- **AI reads top-priority files** directly — not summaries, the actual source code
- **Identifies architecture** — frontend/backend layers, API boundaries, database access patterns, auth flow, external integrations
- **Maps trust boundaries** — where untrusted input enters, where privileged operations occur
- **Identifies attack surface** — entry points, exposed endpoints, file upload handlers, command execution, template rendering
- **Documentation-informed** — uses documentation intelligence (from Stage 1) to verify developer claims against actual code
- **Produces 4 architecture diagram specifications** — System Overview, Security Architecture, Data Flow, and Attack Surface (rendered as Mermaid diagrams with 449 bundled tech icons)

### Stage 3: Dependency Risk Assessment

The Dependency Risk Agent matches all project dependencies against the offline advisory database:

- **Parses manifests and lockfiles** — package.json, package-lock.json, requirements.txt, Pipfile.lock, pom.xml, build.gradle, go.sum, Cargo.lock, *.csproj, Gemfile.lock, composer.lock, pubspec.lock, mix.lock
- **Matches against 257,000+ OSV advisories** — with CVE IDs, CVSS scores, CWE classifications, affected version ranges, fixed versions, vulnerable functions
- **Assesses exploitability** — AI evaluates whether the vulnerable dependency is actually used in a security-relevant way
- **Boosts file scores** — files that import vulnerable packages get their investigation priority increased (feedback loop)

### Stage 4: Agentic Vulnerability Investigation

The Investigator Agent performs multi-pass adaptive investigation — this is the core of VRAgent's intelligence:

- **Planner-driven agentic loop** — a dedicated Planner Agent decides what to do next from 7 possible actions:
  - `INVESTIGATE_FILES` — read and analyse high-priority files
  - `TRACE_FLOW` — follow data from source to sink across files
  - `DEEP_DIVE` — focused analysis on a specific function or code block
  - `CROSS_REFERENCE` — compare related files to understand interactions
  - `TARGETED_SCAN` — run specific Semgrep rules on specific files
  - `VERIFY_EARLY` — challenge a finding before continuing
  - `STOP` — the planner decides enough evidence has been collected
- **AI reads actual source files** — functions, classes, configuration, surrounding context
- **Taint flow tracing** — identifies where untrusted input enters, how it propagates, and where it reaches dangerous sinks
- **Call graph verification** — uses the static call graph to verify whether traced paths are actually reachable
- **Evidence collection** — each candidate finding accumulates supporting evidence and opposing evidence
- **Adaptive re-prioritisation** — file scores are updated during investigation based on what's been discovered
- **Pass budgets by scan mode** — Light: 1 pass, Regular: 2 passes, Heavy: 3+ passes

### Stage 5: Targeted Scanner Follow-up

The Rule Selector Agent chooses specific Semgrep rules for follow-up scanning:

- **AI selects rules** based on languages detected, frameworks identified, and suspicion types discovered during investigation
- **Runs targeted Semgrep passes** using the selected rule directories
- **New hits trigger mini-investigations** — if targeted scans find new issues, the Investigator runs a follow-up pass on those files (feedback loop)

### Stage 6: Verification

The Verifier Agent rigorously challenges each candidate finding:

- **Challenges each finding** — checks for input validation, output encoding, framework protections, auth enforcement, dead code, test-only code, unreachable code
- **Exploit chain detection** — identifies when multiple individually low-severity findings combine into a high-severity attack chain
- **Exploit difficulty assessment** — classifies as easy, moderate, difficult, or theoretical
- **PoC generation** — generates proof-of-concept templates (curl commands, Python scripts, HTTP requests) showing how the vulnerability could be exploited
- **Taint flow verification** — cross-references taint flows against the call graph to verify reachability
- **False positive dismissal** — findings with insufficient evidence or strong counter-evidence are dismissed
- **Re-investigation trigger** — if fewer than 30% of findings are confirmed in Heavy mode, triggers a deeper investigation pass (feedback loop)

### Stage 7: Reporting & Diagram

The Reporter Agent generates the final output:

- **AI-written narratives** — each finding gets a detailed explanation of what the vulnerability is, why it matters, how it could be exploited, and how to fix it
- **Architecture diagram rendering** — the diagram spec from Stage 2 is rendered to a Mermaid diagram, then to SVG/PNG for embedding
- **Executive summary** — overall risk assessment, key findings, and recommendations
- **Methodology section** — documents which scanners were used, which rules were applied, which model was used, and any limitations

### Context Management

Throughout the pipeline, VRAgent manages the AI's context window intelligently:

- **Token estimation** — conservative estimate of ~3.2 characters per token
- **Pre-send validation** — every prompt is validated against the model's context window before sending
- **Auto-truncation** — if a prompt exceeds the budget, content is truncated with a clear marker
- **Adaptive compaction** — between stages, if the accumulated context exceeds a threshold, a compaction pass summarises what's been learned and releases memory
- **Compaction thresholds scale with model size** — smaller models compact more aggressively
- **Supports 128K, 200K, and 400K token windows** — configurable per LLM profile

---

## Agent Orchestrator

The orchestrator is the central controller that runs the scan pipeline, manages agent execution, handles feedback loops, and emits real-time progress.

### Agents and Their Tools

Every agent has access to a shared **AgentToolkit** providing 20 tools:

| Tool | Description |
|------|-------------|
| `read_file(path)` | Read a source file with automatic truncation for large files |
| `read_file_range(path, start, end)` | Read specific line ranges from a file |
| `search_code(pattern, path)` | Regex-based code search across the codebase |
| `list_directory(path)` | List directory contents with type indicators |
| `get_file_symbols(path)` | Tree-sitter symbol extraction (functions, classes, imports, routes) |
| `get_scanner_hits(path)` | Retrieve all scanner results for a specific file |
| `run_semgrep(rules_dir, targets)` | Run Semgrep with specific rules on specific files |
| `run_bandit(targets)` | Run Bandit on specific Python files |
| `query_findings()` | Query current candidate findings |
| `query_taint_flows()` | Query discovered taint flows |
| `get_file_imports(path)` | Get imports/requires from a file |
| `get_resolved_imports(path)` | Get resolved import paths (file → file mapping) |
| `find_files_importing(module)` | Find all files that import a specific module |
| `get_call_graph_for_file(path)` | Get callers and callees for functions in a file |
| `trace_call_chain(file, func, depth)` | Trace inter-procedural call chains across files |
| `get_callers_of(file, func)` | Find all callers of a specific function |
| `get_entry_points_reaching(file)` | Find entry points that can reach a file |
| `query_cve(package, version)` | Query the offline CVE/CWE database for a specific package |
| `check_file_exists(path)` | Check whether a file exists |
| `query_android_manifest()` | Query parsed AndroidManifest.xml (APK scans only) |

### Planner Agent

The Planner is the agent that makes VRAgent agentic. It receives:

- Current scan state (what's been checked, what was found, what remains)
- File priority queue
- Current candidate findings and their evidence status
- Scanner hit counts and distributions

It outputs one of 7 actions with target files and reasoning. The orchestrator executes the chosen action, updates the scan state, and asks the planner again. This loop continues until the planner says `STOP` or the iteration budget is exhausted.

### Compaction

When the accumulated context approaches the model's limit, the compaction system:

1. Summarises all findings, evidence, and scan state into a compact representation
2. Preserves key facts (confirmed findings, critical taint flows, architecture understanding)
3. Discards low-value detail (dismissed findings, fully-explored dead ends)
4. Runs recursively if a single compaction pass isn't enough

---

## Scanner Integrations

### Semgrep (1,952+ rules)

VRAgent ships with 1,952 bundled Semgrep rules covering:

| Language | Rule Count | Categories |
|----------|-----------|------------|
| Python | ~350 | injection, deserialization, crypto, SSRF, path traversal, Django, Flask, FastAPI |
| JavaScript | ~300 | XSS, prototype pollution, injection, Express, React, Node.js |
| TypeScript | ~200 | type confusion, injection, Angular, React, Next.js |
| Java | ~300 | injection, XXE, SSRF, deserialization, Spring, Struts |
| Go | ~200 | injection, crypto, gorilla/mux, gin, net/http |
| Ruby | ~150 | injection, mass assignment, Rails, ERB |
| PHP | ~150 | injection, file inclusion, Laravel, WordPress |
| C# | ~100 | injection, crypto, ASP.NET, Entity Framework |
| Kotlin | ~50 | Android, injection, WebView |
| Rust | ~50 | unsafe blocks, memory safety, FFI |
| Scala | ~30 | injection, Play framework |
| Swift | ~30 | iOS, crypto, keychain |
| Generic | ~42 | secrets, credentials, hardcoded keys (all languages) |

**Baseline scan** uses language-filtered core rules for speed. **Targeted scans** use the full rule set, selected by the Rule Selector Agent based on discovered suspicions.

Rules are stored in `backend/data/semgrep-rules/` organised by language directory.

### Bandit

Python-specific security analysis:
- Hardcoded passwords and secrets (B105, B106, B107)
- Command injection (B602-B607)
- Unsafe deserialization (B301-B303)
- Weak cryptography (B324)
- SQL injection (B608)
- Template injection (B701-B703)

### ESLint

JavaScript/TypeScript security analysis with a custom security configuration:
- Unsafe DOM manipulation (innerHTML, document.write)
- eval() and Function() usage
- Prototype pollution patterns
- Missing security headers

### CodeQL

Deep semantic analysis with deterministic taint tracking:
- Creates language-specific databases (Python, JavaScript, Java, Go, Ruby, C#, C/C++, Swift)
- Runs pre-compiled security query packs
- SARIF output with full taint flow paths
- Databases are cached per scan for reuse across multiple query runs

### Secrets Scanner

Offline regex + entropy detection for 40+ secret patterns:
- Cloud provider keys (AWS, GCP, Azure)
- API tokens (GitHub, GitLab, Slack, Stripe, Twilio)
- JWTs, RSA/EC private keys, SSH keys
- Database connection strings
- Hardcoded passwords and credentials
- Internal URLs and IP addresses
- Email addresses and phone numbers
- Entropy-based filtering to reduce false positives

### Dependency Auditor

Offline vulnerability matching against 257,000+ OSV advisories:
- Supports 10 ecosystems: npm, PyPI, Maven, Go, Crates, NuGet, RubyGems, Packagist, Pub, Hex
- Version range matching using semver and PEP 440
- CVE IDs, CVSS scores, CWE classifications
- Affected version ranges and fixed version information
- Vulnerable function lists where available
- AI-assessed relevance (is the vulnerable code path actually used?)

---

## Advanced Analysis

### Call Graph

VRAgent builds a lightweight static call graph by:
1. Parsing imports using language-specific resolvers (Python, JS/TS, Java, Go, Ruby, PHP, Rust)
2. Resolving imports to actual files on disk
3. Extracting call sites from function bodies
4. Building edges with confidence scores

The call graph supports:
- `callers_of(function)` — who calls this function?
- `callees_of(function)` — what does this function call?
- `find_path(source, sink)` — is there a call path from A to B?

### Taint Tracking

AI-inferred taint tracking traces data from sources to sinks:

**Sources**: request parameters, environment variables, file reads, database queries, user input, API responses

**Sinks**: SQL execution, OS command execution, template rendering, file writes, HTTP responses, deserialization

Each taint flow records:
- Source file, line, and type
- Sink file, line, and type
- Intermediate functions/files the data passes through
- Whether sanitisation was detected
- Whether the call graph confirms reachability

### Import Resolution

Language-specific import resolvers map import statements to files:

| Language | Import Patterns |
|----------|----------------|
| Python | `import x`, `from x import y`, relative imports |
| JavaScript/TypeScript | `import`, `require()`, `import()` |
| Java | `import com.example.Class` |
| Go | `import "github.com/..."` |
| Ruby | `require`, `require_relative` |
| PHP | `use`, `require_once`, `include` |
| Rust | `use crate::`, `mod` |

### Obfuscation Detection

Entropy-based and pattern-based detection:
- Shannon entropy calculation per file
- Pattern matching for webpack bundles, esbuild output, UglifyJS
- Filename pattern detection (.min.js, .bundle.js, .packed.js)
- Confidence scoring: 0.4+ = potentially obfuscated, 0.7+ = likely non-analysable
- Obfuscated files are still analysed but the report notes the limitation

### Tree-sitter Parsing

AST-based structural analysis for 20+ languages:
- Function and class extraction with line boundaries
- Import statement parsing
- Symbol cataloguing
- Route and handler detection
- Language-aware code chunking for AI consumption

### APK / Android Scanning

VRAgent can scan Android APK files by decompiling them to Java source code:

1. **Upload APK** — the frontend detects APK uploads and shows a "Decompiling APK" phase in the progress tracker
2. **jadx decompilation** — the APK is decompiled using jadx (bundled in `tools/jadx/`) to produce readable Java/Kotlin source
3. **AndroidManifest.xml parsing** — extracts package name, permissions, exported components, intent filters, content providers, min/target SDK
4. **Android-specific file scoring** — boosts files containing `WebView`, `SharedPreferences`, `ContentProvider`, `BroadcastReceiver`, exported `Activity`/`Service`
5. **6 Android-specific AI tools** — `query_android_manifest`, `find_component_handler`, `check_intent_filters`, `find_webview_usage`, `query_android_permissions`, `check_network_security_config`
6. **Android-aware prompts** — all AI agents receive APK-specific context (decompilation artifacts, ProGuard/R8 obfuscation, Android security patterns)
7. **Report context** — the final report notes that analysis was performed on decompiled code and flags obfuscation as a limitation

### Documentation Intelligence

VRAgent reads project documentation early in the scan to inform the AI's investigation:

1. **Discovery** — fast filesystem scan for 20+ documentation patterns (README.md, SECURITY.md, ARCHITECTURE.md, API docs, .env.example, docs/ directory)
2. **AI summarisation** — one LLM call extracts structured JSON: app description, environment variables, API endpoints, auth mechanisms, deployment info, external services, security notes, default credentials, config files, investigation hints
3. **Downstream injection** — the compact summary (~500-1000 tokens) is injected into architecture agent, investigator, planner, and reporter prompts
4. **File scoring boosts** — config files referenced in docs get priority boosts; env-related files boosted when env vars are mentioned; default credentials trigger investigation observations
5. **Verification mindset** — all downstream agents are told: "Documentation describes INTENT, not necessarily REALITY. Verify claims against actual code."

---

## Database Schema

VRAgent uses PostgreSQL 16 with the following schema:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│   projects   │────→│    scans     │────→│   scan_configs   │
│              │     │              │     │                  │
│ id           │     │ id           │     │ scan_id          │
│ name         │     │ project_id   │     │ scanners (JSONB) │
│ description  │     │ llm_profile_id│    │ llm_model        │
│ repo_path    │     │ mode         │     │ scan_mode        │
│ created_at   │     │ status       │     └──────────────────┘
│ updated_at   │     │ current_phase│
└──────────────┘     │ current_task │     ┌──────────────────┐
                     │ started_at   │────→│   scan_events    │
                     │ completed_at │     │                  │
                     │ error_message│     │ scan_id          │
                     └──────┬───────┘     │ phase            │
                            │             │ level            │
                     ┌──────┴───────┐     │ message          │
                     │    files     │     │ detail (JSONB)   │
                     │              │     │ created_at       │
                     │ id           │     └──────────────────┘
                     │ scan_id      │
                     │ path         │     ┌──────────────────┐
                     │ language     │────→│  file_summaries  │
                     │ size_bytes   │     │                  │
                     │ line_count   │     │ file_id          │
                     │ priority_score│    │ summary          │
                     │ score_reasons│     │ purpose          │
                     │ is_test      │     │ layer            │
                     │ is_config    │     │ security_notes   │
                     │ is_generated │     └──────────────────┘
                     └──────┬───────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
   ┌──────┴───────┐ ┌──────┴───────┐ ┌───────┴──────┐
   │   findings   │ │  symbols     │ │  secret_     │
   │              │ │              │ │  candidates  │
   │ id           │ │ file_id      │ │              │
   │ scan_id      │ │ name         │ │ scan_id      │
   │ title        │ │ type         │ │ file_path    │
   │ severity     │ │ line         │ │ line_number  │
   │ confidence   │ └──────────────┘ │ pattern      │
   │ category     │                  │ confidence   │
   │ description  │                  │ entropy_score│
   │ explanation  │                  └──────────────┘
   │ impact       │
   │ remediation  │     ┌──────────────────────┐
   │ code_snippet │────→│      evidence        │
   │ status       │     │                      │
   │ exploit_     │     │ finding_id           │
   │  difficulty  │     │ file_id              │
   │ exploit_     │     │ type (supporting/    │
   │  prerequisites│    │       opposing/      │
   │ exploit_     │     │       contextual)    │
   │  template    │     │ description          │
   │ attack_      │     │ code_snippet         │
   │  scenario    │     │ line_range           │
   └──────────────┘     │ source               │
                        └──────────────────────┘

   ┌──────────────┐     ┌──────────────────────┐
   │ dependencies │────→│ dependency_findings  │
   │              │     │                      │
   │ scan_id      │     │ dependency_id        │
   │ ecosystem    │     │ advisory_id          │
   │ name         │     │ cve_id               │
   │ version      │     │ severity             │
   │ source_file  │     │ cvss_score           │
   │ is_dev       │     │ summary              │
   └──────────────┘     │ affected_range       │
                        │ fixed_version        │
                        │ cwes (JSONB)         │
                        │ vulnerable_functions │
                        │ relevance            │
                        │ ai_assessment        │
                        └──────────────────────┘

   ┌──────────────────┐     ┌──────────────────┐
   │ agent_decisions  │     │ compaction_       │
   │                  │     │  summaries        │
   │ scan_id          │     │                   │
   │ agent            │     │ scan_id           │
   │ phase            │     │ phase             │
   │ action           │     │ summary           │
   │ reasoning        │     │ key_facts (JSONB) │
   │ files_inspected  │     └──────────────────┘
   │ tokens_used      │
   │ duration_ms      │     ┌──────────────────┐
   └──────────────────┘     │    reports       │
                            │                  │
   ┌──────────────────┐     │ scan_id          │
   │  llm_profiles    │     │ app_summary      │
   │                  │     │ architecture     │
   │ id               │     │ diagram_spec     │
   │ name             │     │ diagram_image    │
   │ base_url         │     │ methodology      │
   │ api_key          │     │ limitations      │
   │ model_name       │     │ tech_stack(JSONB)│
   │ cert_path        │     │ report_html      │
   │ timeout_seconds  │     └────────┬─────────┘
   │ context_window   │              │
   │ max_output_tokens│     ┌────────┴─────────┐
   │ use_max_         │     │export_artifacts  │
   │  completion_     │     │                  │
   │  tokens          │     │ report_id        │
   │ concurrency      │     │ format           │
   └──────────────────┘     │ file_path        │
                            │ file_size        │
                            └──────────────────┘
```

---

## Frontend

### Screens

1. **Dashboard** — recent projects, recent scans, quick-start buttons, project statistics, logo featured prominently
2. **New Scan** — project selection, codebase upload or APK upload, repo path input, scan mode selector (Light/Regular/Heavy), LLM profile selector, scanner toggles, start scan button
3. **Scan Progress** — real-time phase indicator with 7 stages (8 for APK scans), gradient progress bar with shimmer animation, scan line effects on active phase, pulsing substep indicators, ETA estimation, elapsed time counter, 5 telemetry stats (Files, Findings, Phase, Elapsed, ETA), terminal-style event log with blinking cursor
4. **Report** — full analyst-quality report with: executive risk score (A-F grade), app summary with codebase statistics, 4 tabbed architecture diagrams (zoom/pan/fullscreen), 7 Chart.js analytics charts, severity-filtered finding cards with CWE badges, OWASP Top 10 mapping, component security scorecard, SBOM table, scan coverage stats, secrets table, dependency risks table, methodology section, PDF/DOCX export buttons
5. **Scan History** — searchable/filterable scan list with status pills, mode badges, duration, delete with confirmation, direct links to reports
6. **Settings** — LLM profile management (base URL, API key, model, context window preset 128K/200K/400K, max_tokens vs max_completion_tokens toggle, timeout, concurrency, cert bundle path), scanner configuration, test connection button

### Design

- **Dark theme by default** — navy/slate backgrounds with cyan/teal accents
- **HUD-style components** — corner brackets, animated gradient borders, glow effects
- **Animated particle network background** — canvas-based floating node network on the dashboard
- **Terminal-style event log** — monospace text with cursor blink, line numbers, and colour-coded severity
- **Animated counters** — numbers that count up on state changes
- **Chart.js analytics** — 7 chart types (Doughnut, Bar, Polar Area, Radar) with dark theme, size-capped containers
- **Locally bundled fonts** — JetBrains Mono and Inter included in the build for offline use
- **Responsive layout** — works on 1080p and above

---

## Report Generation

The final report includes:

1. **Executive Risk Score** — A-F letter grade with 0-100 risk score, weighted by severity, confidence, and exploitability. One-sentence risk summary for non-technical stakeholders
2. **What Does This App Do?** — AI-generated explanation of the application's purpose, architecture, layers, trust boundaries, data flows, deployment shape, and external integrations. Informed by documentation intelligence (README, API docs, setup guides)
3. **Codebase Statistics** — language distribution with file counts, framework detection, source file totals
4. **Architecture Diagrams** — 4 Mermaid diagrams (System Overview, Security Architecture, Data Flow, Attack Surface) with tab selector, fullscreen mode, zoom/pan, and copy-to-clipboard for mermaid specs. Primary diagram rendered with 449 bundled tech icons
5. **Scan Analytics Dashboard** — 7 Chart.js visualizations: Severity Donut, Confidence Distribution, Scanner Hit Distribution, Dependency Risk Donut, Finding Categories, Attack Surface Radar, Language Distribution (Polar Area)
6. **Security Findings** — each finding includes: title, severity, confidence, CWE IDs, OWASP category mapping, affected files, vulnerable code snippet, explanation, impact, supporting/opposing evidence, remediation guidance, exploit difficulty, attack scenario, PoC template (where applicable)
7. **Secrets & Sensitive Data** — candidates with type, location, confidence, and why flagged
8. **Dependency Risks** — vulnerable packages with CVE IDs, CVSS scores, CWEs, affected ranges, fixed versions, AI-assessed relevance
9. **OWASP Top 10 Mapping** — all findings mapped to OWASP 2021 categories via CWE IDs (200+ mappings), showing count, max severity, and finding titles per category
10. **Component Security Scorecard** — per-component A-F grades with score bars, criticality ratings, finding counts, and attack surface exposure flags
11. **Software Bill of Materials (SBOM)** — full dependency inventory with package name, version, ecosystem, dev/prod type, and vulnerability status. Paginated with ecosystem breakdown
12. **Scan Coverage** — total files, AI-inspected count, AI calls made, scan mode, scanners used, documentation files analysed, obfuscation/monorepo/APK indicators
13. **Methodology & Limitations** — scan mode, scanners used, rule versions, advisory DB version, model used, confidence caveats, blind spots, documentation analysis notes

### Export Formats

- **In-app HTML** — rendered in the browser with full interactivity
- **PDF** — generated via WeasyPrint with proper typography, code blocks, and embedded diagrams
- **DOCX** — generated via python-docx with headings, tables, code formatting, and embedded images

---

## Project Structure

```
vragent/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI application entry point
│   │   ├── config.py                  # Pydantic settings (env vars)
│   │   ├── database.py                # SQLAlchemy async engine + session
│   │   │
│   │   ├── api/                       # REST API layer
│   │   │   ├── projects.py            # Project CRUD endpoints
│   │   │   ├── scans.py               # Scan creation, control, events
│   │   │   ├── findings.py            # Finding retrieval and filtering
│   │   │   ├── reports.py             # Report retrieval and export
│   │   │   ├── llm_profiles.py        # LLM profile management
│   │   │   └── health.py              # Health checks and tool availability
│   │   │
│   │   ├── models/                    # SQLAlchemy ORM models
│   │   │   ├── project.py             # Project model
│   │   │   ├── scan.py                # Scan + ScanConfig + ScanEvent
│   │   │   ├── file.py                # File + FileSummary + Symbol
│   │   │   ├── finding.py             # Finding + Evidence + FindingFile
│   │   │   ├── dependency.py          # Dependency + DependencyFinding
│   │   │   ├── secret.py              # SecretCandidate
│   │   │   ├── llm_profile.py         # LLM connection profiles
│   │   │   ├── report.py              # Report + ExportArtifact
│   │   │   └── agent_decision.py      # AgentDecision + CompactionSummary
│   │   │
│   │   ├── schemas/                   # Pydantic request/response schemas
│   │   │   ├── project.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   ├── report.py
│   │   │   └── llm_profile.py
│   │   │
│   │   ├── orchestrator/              # Scan engine
│   │   │   ├── engine.py              # Main pipeline runner (8 stages)
│   │   │   ├── scan_context.py        # Shared scan state (findings, taint flows, scores)
│   │   │   ├── llm_client.py          # OpenAI-compatible LLM client
│   │   │   ├── compaction.py          # Context compaction logic
│   │   │   ├── tools.py               # AgentToolkit (14 tools for agents)
│   │   │   │
│   │   │   ├── agents/                # Agent implementations
│   │   │   │   ├── base.py            # BaseAgent abstract class
│   │   │   │   ├── triage.py          # Repository fingerprinting + baseline scans
│   │   │   │   ├── architecture.py    # Application understanding
│   │   │   │   ├── dependency.py      # Dependency risk assessment
│   │   │   │   ├── investigator.py    # Multi-pass vulnerability investigation
│   │   │   │   ├── planner.py         # Agentic action selection
│   │   │   │   ├── rule_selector.py   # Targeted Semgrep rule selection
│   │   │   │   ├── verifier.py        # Finding verification + exploit validation
│   │   │   │   └── reporter.py        # Report narrative generation
│   │   │   │
│   │   │   └── prompts/               # LLM prompt templates
│   │   │       ├── triage.py
│   │   │       ├── architecture.py
│   │   │       ├── investigation.py
│   │   │       ├── planner.py
│   │   │       ├── verification.py
│   │   │       └── reporting.py
│   │   │
│   │   ├── scanners/                  # Scanner adapter layer
│   │   │   ├── base.py                # ScannerAdapter abstract class
│   │   │   ├── registry.py            # Scanner discovery + availability checks
│   │   │   ├── semgrep.py             # Semgrep adapter (baseline + targeted)
│   │   │   ├── bandit.py              # Bandit adapter (Python)
│   │   │   ├── eslint.py              # ESLint adapter (JS/TS)
│   │   │   ├── codeql.py              # CodeQL adapter (taint tracking)
│   │   │   ├── secrets.py             # Secrets scanner (regex + entropy)
│   │   │   └── dep_audit.py           # Dependency vulnerability matcher
│   │   │
│   │   ├── analysis/                  # Code analysis modules
│   │   │   ├── call_graph.py          # Inter-procedural call graph
│   │   │   ├── import_resolver.py     # Language-specific import resolution
│   │   │   ├── treesitter.py          # Tree-sitter AST parsing
│   │   │   ├── fingerprint.py         # Repository fingerprinting
│   │   │   ├── file_scorer.py         # Deterministic file priority scoring
│   │   │   ├── obfuscation.py         # Minification/obfuscation detection
│   │   │   ├── diagram.py             # Architecture diagram rendering
│   │   │   ├── structure.py           # Code structure analysis
│   │   │   └── paths.py               # Cross-platform path utilities
│   │   │
│   │   ├── services/                  # Business logic
│   │   │   ├── scan_service.py        # Scan lifecycle management
│   │   │   ├── report_service.py      # Report generation + export
│   │   │   └── export_service.py      # PDF/DOCX rendering
│   │   │
│   │   └── events/                    # Real-time event system
│   │       └── bus.py                 # WebSocket event bus
│   │
│   ├── data/                          # Offline data stores
│   │   ├── semgrep-rules/             # 1,952 Semgrep rules by language
│   │   │   ├── python/                # ~350 Python security rules
│   │   │   ├── javascript/            # ~300 JavaScript rules
│   │   │   ├── typescript/            # ~200 TypeScript rules
│   │   │   ├── java/                  # ~300 Java rules
│   │   │   ├── go/                    # ~200 Go rules
│   │   │   ├── ruby/                  # ~150 Ruby rules
│   │   │   ├── php/                   # ~150 PHP rules
│   │   │   ├── csharp/                # ~100 C# rules
│   │   │   ├── kotlin/                # ~50 Kotlin rules
│   │   │   ├── rust/                  # ~50 Rust rules
│   │   │   ├── scala/                 # ~30 Scala rules
│   │   │   ├── swift/                 # ~30 Swift rules
│   │   │   └── generic/               # ~42 generic rules (secrets, etc.)
│   │   │
│   │   ├── advisories/                # OSV vulnerability database
│   │   │   ├── npm.json               # npm advisories
│   │   │   ├── pypi.json              # PyPI advisories
│   │   │   ├── maven.json             # Maven advisories
│   │   │   ├── go.json                # Go advisories
│   │   │   ├── crates.json            # Crates.io advisories
│   │   │   ├── nuget.json             # NuGet advisories
│   │   │   ├── rubygems.json          # RubyGems advisories
│   │   │   ├── packagist.json         # Packagist advisories
│   │   │   ├── pub.json               # Pub (Dart) advisories
│   │   │   ├── hex.json               # Hex (Elixir) advisories
│   │   │   └── manifest.json          # DB version, sync date, counts
│   │   │
│   │   ├── eslint-configs/            # Security ESLint configuration
│   │   │   └── security.json
│   │   │
│   │   └── icons/                     # 500+ technology SVG icons
│   │       ├── react.svg
│   │       ├── python.svg
│   │       ├── postgresql.svg
│   │       └── ...
│   │
│   ├── tools/                         # External tool installations
│   │   └── codeql/                    # CodeQL CLI bundle (downloaded separately)
│   │       ├── codeql(.exe)           # CodeQL binary
│   │       └── qlpacks/              # Pre-compiled query packs
│   │
│   ├── scripts/                       # Setup and data preparation scripts
│   │   ├── download_semgrep_rules.py  # Download Semgrep community rules
│   │   ├── sync_advisories.py         # Download OSV advisory database
│   │   ├── download_codeql.py         # Download CodeQL CLI bundle
│   │   └── download_icons.py          # Download technology SVG icons
│   │
│   ├── alembic/                       # Database migrations
│   │   ├── alembic.ini
│   │   └── versions/
│   │
│   ├── tests/                         # Test suite
│   │   ├── test_scanners/
│   │   ├── test_analysis/
│   │   ├── test_orchestrator/
│   │   └── test_api/
│   │
│   ├── pyproject.toml                 # Python project configuration
│   └── Dockerfile                     # Backend container image
│
├── frontend/
│   ├── public/
│   │   └── logo.jpg                   # VRAgent logo
│   │
│   ├── src/
│   │   ├── main.tsx                   # React entry point
│   │   ├── App.tsx                    # Router + layout
│   │   │
│   │   ├── pages/                     # Page components
│   │   │   ├── DashboardPage.tsx      # Project overview + quick start
│   │   │   ├── NewScanPage.tsx        # Scan configuration
│   │   │   ├── ScanProgressPage.tsx   # Real-time progress view
│   │   │   ├── ReportPage.tsx         # Finding display + export
│   │   │   ├── HistoryPage.tsx        # Scan history list
│   │   │   └── SettingsPage.tsx       # LLM + scanner configuration
│   │   │
│   │   ├── components/                # Reusable UI components
│   │   │   ├── ParticleBackground.tsx # Animated particle network
│   │   │   ├── HudFrame.tsx           # HUD-style card frame
│   │   │   ├── AnimatedCounter.tsx    # Number animation
│   │   │   ├── TypingText.tsx         # Typewriter text effect
│   │   │   ├── PhaseIndicator.tsx     # Scan phase progress
│   │   │   ├── EventLog.tsx           # Terminal-style event log
│   │   │   ├── FindingCard.tsx        # Finding display card
│   │   │   └── ExportButtons.tsx      # PDF/DOCX export triggers
│   │   │
│   │   ├── hooks/                     # Custom React hooks
│   │   │   ├── useApi.ts              # API client hook
│   │   │   ├── useScanProgress.ts     # WebSocket scan progress
│   │   │   └── useWebSocket.ts        # WebSocket connection
│   │   │
│   │   └── api/                       # API client
│   │       └── client.ts              # Typed API client
│   │
│   ├── package.json                   # NPM dependencies
│   ├── vite.config.ts                 # Vite build configuration
│   ├── tsconfig.json                  # TypeScript configuration
│   ├── tailwind.config.js             # Tailwind CSS configuration
│   └── Dockerfile                     # Frontend container image
│
├── docker-compose.yml                 # Full-stack orchestration
├── Makefile                           # Development commands
└── README.md                          # This file
```

---

## Installation — Air-Gapped Deployment

VRAgent is designed for environments with no direct internet access at runtime. However, **package managers (pip, npm) and GitHub are available via internal mirrors**, so standard installation commands work.

> **Key distinction:** `pip install`, `npm install`, `git clone`, and GitHub release downloads all work via your organisation's internal mirrors. The constraint is that the **running application** makes no internet calls — all LLM communication goes to a local endpoint, all scanner rules/advisories/icons are bundled locally, and the frontend has no external CDN dependencies.

### Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11 or higher | Backend runtime |
| Node.js | 18 or higher | Frontend build |
| PostgreSQL | 16 | Data persistence |
| Git | 2.x | Optional — for repo analysis features |
| Semgrep | Latest | Static analysis scanner |
| Bandit | Latest | Python security scanner |
| CodeQL | Latest | Semantic analysis (optional but recommended) |

---

### Offline Data Preparation

Since pip/npm/GitHub are available via internal mirrors, these commands can be run directly on the deployment system.

#### 1. Clone the VRAgent Repository

```bash
git clone <your-vragent-repo-url>
cd vragent
```

#### 2. Download Python Dependencies for Offline Install

```bash
# Create a directory for offline wheels
mkdir -p offline-packages/python

# Download all backend dependencies as wheel files
cd backend
pip download -d ../offline-packages/python -r <(pip-compile pyproject.toml --output-file=-)
# Or simpler:
pip download -d ../offline-packages/python ".[dev]"
cd ..
```

#### 3. Download Node.js Dependencies for Offline Install

```bash
cd frontend

# Install normally first (generates package-lock.json)
npm install

# Create a tarball of node_modules for transfer
tar czf ../offline-packages/node_modules.tar.gz node_modules/
cd ..
```

#### 4. Download Semgrep Rules (1,952 rules)

```bash
cd backend
python -m scripts.download_semgrep_rules --output data/semgrep-rules/
cd ..
```

This downloads the official Semgrep community rules from GitHub and organises them by language. Output size: ~50MB.

#### 5. Download OSV Advisory Database (257,000+ advisories)

```bash
cd backend
python -m scripts.sync_advisories --output data/advisories/
cd ..
```

This downloads the full OSV vulnerability database from Google Cloud Storage. Output size: ~250MB compressed.

#### 6. Download Technology Icons

```bash
cd backend
python -m scripts.download_icons --output data/icons/
cd ..
```

Downloads 500+ technology SVG icons for architecture diagrams. Output size: ~5MB.

#### 7. Download Semgrep Binary (if not using pip)

Semgrep can be installed via pip (`pip install semgrep`) which is the recommended approach. If you need the standalone binary:

```bash
# On the internet-connected machine, install semgrep and locate the binary
pip install semgrep
which semgrep  # Linux/Mac
where semgrep  # Windows

# Copy the entire semgrep installation to offline-packages/
```

#### 8. Download Bandit

```bash
# Bandit installs via pip — it's included in the pip download above
# No separate download needed
pip install bandit
```

#### 9. Download ESLint

```bash
# Create an ESLint package for offline use
mkdir -p offline-packages/eslint
cd offline-packages/eslint
npm init -y
npm install eslint @eslint/js --save
tar czf ../eslint-bundle.tar.gz .
cd ../..
```

#### 10. Package Everything for Transfer

```bash
# Create the transfer package
tar czf vragent-offline-bundle.tar.gz \
    vragent/ \
    offline-packages/
```

If you prepared the bundle on a separate machine, transfer `vragent-offline-bundle.tar.gz` to the deployment system. If pip/npm mirrors are available on the deployment system, you can skip the bundle and install directly.

---

### CodeQL Installation

CodeQL is a standalone binary distributed by GitHub. It is **not** available via pip or npm, but since GitHub is accessible via internal mirrors, the download script works directly.

#### Download & Install

```bash
cd vragent/backend
python -m scripts.download_codeql --output tools/codeql/
```

This downloads from GitHub releases (~500MB), extracts, and verifies the installation. The script auto-detects your platform (Windows/Linux/macOS).

If the script doesn't work, download manually from `https://github.com/github/codeql-action/releases/latest`:
- **Windows**: `codeql-bundle-win64.tar.gz`
- **Linux x86_64**: `codeql-bundle-linux64.tar.gz`
- **Linux ARM64**: `codeql-bundle-linux-arm64.tar.gz`

Extract into `backend/tools/codeql/`. The binary should be at `backend/tools/codeql/codeql` (or `codeql.exe` on Windows).

Extract the bundle into `backend/tools/codeql/`:

```bash
# Linux
cd vragent/backend/tools/
tar xzf /path/to/codeql-bundle-linux64.tar.gz
# This creates: tools/codeql/codeql (the binary)

# Windows (PowerShell)
cd vragent\backend\tools\
tar xzf C:\path\to\codeql-bundle-win64.tar.gz
# This creates: tools\codeql\codeql.exe
```

#### Verify Installation

```bash
# Linux
./backend/tools/codeql/codeql version
./backend/tools/codeql/codeql resolve qlpacks | grep security

# Windows
backend\tools\codeql\codeql.exe version
backend\tools\codeql\codeql.exe resolve qlpacks | findstr security
```

Expected output:
```
CodeQL command-line toolchain release 2.x.x
...
codeql/python-security-queries
codeql/javascript-security-queries
codeql/java-security-queries
...
```

#### Configure VRAgent to Use CodeQL

VRAgent auto-detects CodeQL in `backend/tools/codeql/`. If installed elsewhere, set the environment variable:

```bash
# Linux
export VRAGENT_CODEQL_BINARY=/opt/codeql/codeql

# Windows
set VRAGENT_CODEQL_BINARY=C:\tools\codeql\codeql.exe
```

#### CodeQL is Optional

VRAgent works without CodeQL. If CodeQL is not installed, the scan will skip CodeQL-based analysis and rely on AI-inferred taint tracking and the other scanners. The report will note that CodeQL was not available.

### jadx Installation (for APK Scanning)

jadx is required only if you want to scan Android APK files. Like CodeQL, it is a standalone binary — not available via pip or npm, but downloadable from GitHub (accessible via internal mirrors).

```bash
cd backend
python -m scripts.download_jadx --output tools/jadx
```

If the script doesn't work, download manually from `https://github.com/skylot/jadx/releases`:
1. Download `jadx-<version>.zip` (the binary release, not source)
2. Extract into `backend/tools/jadx/`
3. Verify: `backend/tools/jadx/bin/jadx --version` (Linux) or `backend/tools/jadx/bin/jadx.bat --version` (Windows)

#### jadx is Optional

VRAgent works without jadx. If jadx is not installed, the APK upload option will be disabled. All codebase scanning features work independently.

---

### Windows 11 Installation

#### Step 1: Install System Prerequisites

**Python 3.11+**

Download from `https://www.python.org/downloads/` or install via your package manager.

```powershell
# Run the installer with "Add Python to PATH" checked
# Verify:
python --version
# Expected: Python 3.11.x or higher
```

**Node.js 18+**

Download the LTS installer from `https://nodejs.org/` or install via your package manager.

```powershell
node --version
# Expected: v18.x.x or higher

npm --version
# Expected: 9.x.x or higher
```

**PostgreSQL 16**

Download from `https://www.postgresql.org/download/windows/` or install via your package manager. Use the EnterpriseDB installer on Windows.

```powershell
# During installation:
# - Set password for postgres user
# - Default port: 5432
# - Install pgAdmin (optional but helpful)

# After installation, create the VRAgent database:
psql -U postgres
```

```sql
CREATE USER vragent WITH PASSWORD 'vragent';
CREATE DATABASE vragent OWNER vragent;
GRANT ALL PRIVILEGES ON DATABASE vragent TO vragent;
\q
```

**Semgrep**

```powershell
# Semgrep installs via pip (included in offline wheels)
pip install semgrep
semgrep --version
```

**Bandit**

```powershell
# Bandit installs via pip (included in offline wheels)
pip install bandit
bandit --version
```

#### Step 2: Extract VRAgent

```powershell
# Extract the transfer bundle
tar xzf vragent-offline-bundle.tar.gz
cd vragent
```

#### Step 3: Install Backend Dependencies

```powershell
cd backend

# From offline wheels:
pip install --no-index --find-links=..\offline-packages\python -e ".[dev]"

# Or if you have internet on the prep machine and just copied the repo:
pip install -e ".[dev]"
```

#### Step 4: Install Frontend Dependencies

```powershell
cd ..\frontend

# From offline node_modules:
tar xzf ..\offline-packages\node_modules.tar.gz

# Or if you ran npm install on the prep machine:
# node_modules/ should already be present
```

#### Step 5: Install CodeQL (Optional)

```powershell
cd ..\backend\tools
tar xzf C:\path\to\codeql-bundle-win64.tar.gz
# Verify:
.\codeql\codeql.exe version
```

#### Step 6: Install ESLint (for JS/TS scanning)

```powershell
# ESLint can be installed globally or locally
npm install -g eslint
# Or from offline bundle:
cd ..\offline-packages\eslint
npm install -g .
```

#### Step 7: Run Database Migrations

```powershell
cd ..\..\backend
alembic upgrade head
```

#### Step 8: Start VRAgent

Open two terminal windows:

**Terminal 1 — Backend:**
```powershell
cd vragent\backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend:**
```powershell
cd vragent\frontend
npm run dev
```

Open your browser to `http://localhost:3000`

---

### Ubuntu Installation

#### Step 1: Install System Prerequisites

```bash
# Update package list (do this before going air-gapped, or use local apt mirror)
sudo apt update

# Python 3.11+
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip

# Node.js 18+ (via NodeSource or local .deb)
# Option A: NodeSource (requires internet)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Option B: Download .deb files on prep machine, copy to air-gapped
# wget https://deb.nodesource.com/node_18.x/pool/main/n/nodejs/nodejs_18.x.x-1nodesource1_amd64.deb
# sudo dpkg -i nodejs_18.x.x-1nodesource1_amd64.deb

# Verify
python3 --version   # 3.11+
node --version       # v18+
npm --version        # 9+

# PostgreSQL 16
sudo apt install -y postgresql-16 postgresql-client-16

# Build tools (needed for some Python packages)
sudo apt install -y build-essential libpq-dev libffi-dev

# WeasyPrint dependencies (for PDF generation)
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libcairo2 libffi-dev shared-mime-info
```

#### Step 2: Configure PostgreSQL

```bash
sudo -u postgres psql
```

```sql
CREATE USER vragent WITH PASSWORD 'vragent';
CREATE DATABASE vragent OWNER vragent;
GRANT ALL PRIVILEGES ON DATABASE vragent TO vragent;
\q
```

#### Step 3: Extract VRAgent

```bash
tar xzf vragent-offline-bundle.tar.gz
cd vragent
```

#### Step 4: Create Python Virtual Environment

```bash
cd backend
python3.11 -m venv venv
source venv/bin/activate

# From offline wheels:
pip install --no-index --find-links=../offline-packages/python -e ".[dev]"

# Or with internet access:
pip install -e ".[dev]"
```

#### Step 5: Install Semgrep and Bandit

```bash
# These are Python packages, installed via pip:
pip install semgrep bandit

# Verify:
semgrep --version
bandit --version
```

#### Step 6: Install Frontend Dependencies

```bash
cd ../frontend

# From offline node_modules:
tar xzf ../offline-packages/node_modules.tar.gz

# Or with internet:
npm install
```

#### Step 7: Install ESLint

```bash
npm install -g eslint
```

#### Step 8: Install CodeQL (Optional)

```bash
cd ../backend/tools
tar xzf /path/to/codeql-bundle-linux64.tar.gz
chmod +x codeql/codeql
./codeql/codeql version
```

#### Step 9: Run Database Migrations

```bash
cd ..
source venv/bin/activate
alembic upgrade head
```

#### Step 10: Start VRAgent

**Option A: Using Make**

```bash
cd ..
make backend   # Terminal 1
make frontend  # Terminal 2
```

**Option B: Manual**

Terminal 1 — Backend:
```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Terminal 2 — Frontend:
```bash
cd frontend
npm run dev
```

Open your browser to `http://localhost:3000`

**Option C: Docker Compose** (if Docker is available)

```bash
docker compose up -d
```

This starts PostgreSQL, the backend, and the frontend in containers. Open `http://localhost:3000`.

---

### First Run

1. Open `http://localhost:3000` in your browser
2. Go to **Settings** and configure your LLM provider:
   - **Base URL**: your local OpenAI-compatible endpoint (e.g., `http://localhost:8080/v1`)
   - **API Key**: your endpoint's API key (or any string if auth is not required)
   - **Model Name**: the model identifier (e.g., `llama-3.1-70b`, `qwen2.5-72b`, `mistral-large`)
   - **Context Window**: select the model's context window size (128K, 200K, or 400K tokens)
   - **Max Output Tokens**: maximum tokens per completion (recommended: 4096)
   - Click **Test Connection** to verify
   - Click **Save Profile**
3. Go to **Dashboard** and create a new project:
   - Enter a project name
   - Enter the path to the codebase you want to scan (absolute path on the server)
4. Click **New Scan**:
   - Select your project
   - Choose a scan mode (start with **Light** to verify everything works)
   - Select your LLM profile
   - Click **Start Scan**
5. Watch the real-time progress as VRAgent analyses the codebase
6. When complete, review the findings in the **Report** view
7. Export to PDF or DOCX as needed

---

## Configuration

All configuration is via environment variables with the `VRAGENT_` prefix, or via the UI for LLM profiles.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VRAGENT_DATABASE_URL` | `postgresql+asyncpg://vragent:vragent@localhost:5432/vragent` | PostgreSQL connection string |
| `VRAGENT_HOST` | `0.0.0.0` | Backend bind address |
| `VRAGENT_PORT` | `8000` | Backend port |
| `VRAGENT_DEBUG` | `false` | Debug mode |
| `VRAGENT_DATA_DIR` | `backend/data` | Path to offline data directory |
| `VRAGENT_UPLOAD_DIR` | `backend/uploads` | Uploaded file storage |
| `VRAGENT_EXPORT_DIR` | `backend/exports` | Report export storage |
| `VRAGENT_SEMGREP_BINARY` | `semgrep` | Path to Semgrep binary |
| `VRAGENT_BANDIT_BINARY` | `bandit` | Path to Bandit binary |
| `VRAGENT_ESLINT_BINARY` | `eslint` | Path to ESLint binary |
| `VRAGENT_CODEQL_BINARY` | `codeql` | Path to CodeQL binary |
| `VRAGENT_SEMGREP_RULES_DIR` | `data/semgrep-rules` | Custom Semgrep rules path |
| `VRAGENT_ADVISORY_DB_DIR` | `data/advisories` | Custom advisory DB path |
| `VRAGENT_DEFAULT_SCAN_MODE` | `regular` | Default scan mode |
| `VRAGENT_MAX_FILE_SIZE_BYTES` | `1000000` (1MB) | Maximum file size to analyse |
| `VRAGENT_MAX_FILES_PER_SCAN` | `10000` | Maximum files per scan |

---

## LLM Provider Setup

VRAgent works with any OpenAI-compatible API endpoint. The LLM runs separately — VRAgent connects to it over HTTP.

### Supported LLM Servers

| Server | Endpoint Format | Notes |
|--------|----------------|-------|
| **vLLM** | `http://host:port/v1` | Production-grade, supports `max_completion_tokens` |
| **Ollama** | `http://host:11434/v1` | Easy setup, good for testing |
| **llama.cpp server** | `http://host:8080/v1` | Lightweight, single-model |
| **text-generation-inference** | `http://host:port/v1` | HuggingFace's server |
| **LocalAI** | `http://host:8080/v1` | OpenAI-compatible wrapper |
| **LM Studio** | `http://host:1234/v1` | Desktop app with server mode |

### Recommended Models

For security analysis, use the largest model you can run with at least 128K context:

| Model | Min VRAM | Context | Quality |
|-------|----------|---------|---------|
| Qwen2.5-72B | 48GB | 128K | Excellent |
| Llama 3.1 70B | 48GB | 128K | Excellent |
| DeepSeek-V2.5 | 48GB | 128K | Very good |
| Mistral Large | 48GB | 128K | Very good |
| Qwen2.5-32B | 24GB | 128K | Good |
| Llama 3.1 8B | 8GB | 128K | Adequate for Light scans |

### Context Window Configuration

Configure the context window in the LLM Settings page to match your model:

- **128K tokens** — standard for most 70B+ models
- **200K tokens** — extended context models
- **400K tokens** — ultra-long context models (Qwen2.5 with YaRN, etc.)

VRAgent adapts its compaction strategy based on the selected context window:
- Smaller windows: more aggressive compaction, shorter file reads
- Larger windows: gentler compaction, can read more files per prompt

### `max_tokens` vs `max_completion_tokens`

Different LLM servers use different field names for the output token limit:

- **`max_tokens`** — used by older OpenAI API, llama.cpp, some Ollama versions
- **`max_completion_tokens`** — used by newer OpenAI API, vLLM, newer Ollama

Toggle the **"Use max_completion_tokens"** checkbox in LLM Settings to match your server. If unsure, try with it unchecked first. If you get errors about unknown parameters, toggle it.

---

## Scan Modes

| Mode | Files Inspected | AI Passes | Scanner Depth | Typical Duration | Use Case |
|------|----------------|-----------|--------------|-----------------|----------|
| **Light** | Top 10 priority files | 1 pass | Baseline only | 5–15 minutes | Quick triage, smoke test |
| **Regular** | Top 40 priority files | 2 passes | Baseline + targeted | 15–45 minutes | Default assessment |
| **Heavy** | 100+ files | 3+ passes | Full rule set | 45–120 minutes | Deep security review |

All modes run the full scanner suite (Semgrep, Bandit, ESLint, CodeQL, secrets, dependencies). The difference is in how many files the AI inspects directly and how many investigation passes it performs.

---

## API Reference

### Projects

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/projects` | Create a new project |
| `GET` | `/api/projects` | List all projects |
| `GET` | `/api/projects/{id}` | Get project details |
| `DELETE` | `/api/projects/{id}` | Delete a project |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scans` | Create a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan details |
| `POST` | `/api/scans/{id}/start` | Start a scan (async) |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `DELETE` | `/api/scans/{id}` | Delete a scan (not running) |
| `GET` | `/api/scans/{id}/events` | Get scan events |

### Findings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/findings` | List findings (filter by scan_id, severity, status) |
| `GET` | `/api/findings/{id}` | Get finding details with evidence |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/reports/{scan_id}` | Get report for a scan |
| `POST` | `/api/reports/{scan_id}/export` | Export report (format: pdf, docx, html) |

### LLM Profiles

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/llm-profiles` | Create an LLM profile |
| `GET` | `/api/llm-profiles` | List all profiles |
| `PUT` | `/api/llm-profiles/{id}` | Update a profile |
| `DELETE` | `/api/llm-profiles/{id}` | Delete a profile |

### WebSocket

| Path | Description |
|------|-------------|
| `WS /ws/{scan_id}` | Subscribe to real-time scan progress events |

Event types: `progress`, `event`, `finding`, `complete`

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Service health and scanner availability |

---

## Troubleshooting

### Common Issues

**"Semgrep not found"**
- Ensure Semgrep is installed: `pip install semgrep`
- Or set `VRAGENT_SEMGREP_BINARY` to the full path

**"CodeQL not found"**
- CodeQL is optional. The scan works without it
- If you want CodeQL, extract the bundle to `backend/tools/codeql/`
- Or set `VRAGENT_CODEQL_BINARY` to the full path of the `codeql` binary

**"No advisories found"**
- Run `python -m scripts.sync_advisories` to re-download the advisory database
- Copy `data/advisories/` to the air-gapped system
- Verify `data/advisories/manifest.json` exists

**"Database connection refused"**
- Ensure PostgreSQL is running: `sudo systemctl status postgresql`
- Verify the database exists: `psql -U vragent -d vragent`
- Check `VRAGENT_DATABASE_URL` matches your PostgreSQL configuration

**"WebSocket connection failed"**
- Ensure the backend is running on port 8000
- Check that no firewall is blocking WebSocket connections
- The frontend connects to `ws://localhost:8000/ws/{scan_id}`

**"LLM connection test failed"**
- Verify your LLM server is running and accessible
- Check the base URL ends with `/v1` (e.g., `http://localhost:8080/v1`)
- Try toggling the `max_completion_tokens` setting
- Check the cert path if using HTTPS with self-signed certificates

**"PDF export fails"**
- WeasyPrint requires system libraries. On Ubuntu: `sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2`
- On Windows, WeasyPrint requires GTK3 runtime. See: `https://doc.courtbouillon.org/weasyprint/stable/first_steps.html`

**"Scan takes too long"**
- Use **Light** mode for quick triage
- Reduce `VRAGENT_MAX_FILES_PER_SCAN` for very large codebases
- Ensure your LLM server has adequate GPU resources — slow inference means slow scans
- Check the event log for signs of LLM timeout (increase timeout in LLM Settings)

**"Out of memory during scan"**
- Large codebases can consume significant memory during Tree-sitter parsing
- Reduce `VRAGENT_MAX_FILE_SIZE_BYTES` to skip very large files
- Ensure PostgreSQL has adequate `shared_buffers` configured

### Logs

Backend logs are written to stdout. Set `VRAGENT_DEBUG=true` for verbose logging:

```bash
VRAGENT_DEBUG=true uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## License

VRAgent is proprietary software. All rights reserved.

### Third-Party Licenses

- Semgrep community rules: LGPL-2.1
- OSV advisory data: CC-BY-4.0
- CodeQL CLI: GitHub CodeQL Terms of Use (free for open source, requires license for commercial use on closed-source code)
- Technology icons: Various open-source licenses (MIT, Apache 2.0)
