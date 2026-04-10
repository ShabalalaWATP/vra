"""Architecture Agent — build understanding of what the app does."""

import json
import logging

from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior security researcher analysing a software application.
Your task is to understand what this application does, how it is structured, and where its security-relevant attack surface lies.

You will be given:
- A repository fingerprint (languages, frameworks, file count)
- The top priority files with their code contents

Produce a JSON response with these fields:
{
  "app_summary": "2-4 paragraph detailed description of what this application does, what problem it solves, who its users are, and how it is deployed",
  "app_type": "web_app|api|cli|library|microservice|mobile_backend|monolith|static_site",
  "components": [{"name": "component name", "purpose": "what it does", "files": ["key files"], "criticality": "critical|high|medium|low", "in_attack_surface": true, "handles_user_input": true}],
  "layers": {
    "frontend": ["files/dirs"],
    "backend": ["files/dirs"],
    "database": ["files/dirs"],
    "config": ["files/dirs"],
    "infra": ["files/dirs"]
  },
  "entry_points": [{"file": "path", "function": "name", "type": "http_endpoint|cli_command|websocket|scheduled_task|message_handler", "method": "GET|POST|etc", "path": "/api/..."}],
  "trust_boundaries": ["list of trust boundary descriptions — where does trusted code meet untrusted input?"],
  "data_flows": [{"from": "component/file", "to": "component/file", "data": "what flows", "sensitive": true/false}],
  "attack_surface": ["list of specific attack surface points — not generic, reference actual files and functions"],
  "auth_mechanisms": [{"type": "jwt|session|oauth|api_key|basic|none", "implementation": "where and how", "weaknesses": "any observed weaknesses"}],
  "external_integrations": ["databases, APIs, message queues, cloud services the app connects to"],
  "diagrams": [
    {
      "title": "System Overview",
      "description": "High-level architecture showing main components and their connections",
      "mermaid": "<valid mermaid flowchart TD code>"
    },
    {
      "title": "Security Architecture",
      "description": "Trust boundaries, auth flows, data entry points, sensitive data stores",
      "mermaid": "<valid mermaid flowchart TD code>"
    },
    {
      "title": "Data Flow",
      "description": "How data moves through the application from user input to storage and back",
      "mermaid": "<valid mermaid flowchart LR code>"
    },
    {
      "title": "Attack Surface",
      "description": "All points where an attacker could interact with the application",
      "mermaid": "<valid mermaid flowchart TD code>"
    }
  ],
  "security_observations": ["specific security observations referencing actual code seen — not generic advice"]
}

CRITICAL RULES FOR MERMAID DIAGRAMS:
All diagrams MUST use standard "flowchart TD" or "flowchart LR" syntax. Do NOT use architecture-beta, C4, or other experimental diagram types.

Syntax rules you MUST follow:
1. Start each diagram with "flowchart TD" (top-down) or "flowchart LR" (left-right)
2. Node IDs must be simple alphanumeric (e.g., A, B, server1, db). No spaces, no special chars in IDs.
3. NEVER use special characters inside labels that break mermaid: no quotes, no unescaped parentheses inside labels, no ampersands, no angle brackets. Use simple plain text only.
4. Use subgraphs for grouping: subgraph Title\\n...\\nend
5. Arrows: A --> B, A -->|label| B, A -.->|dashed| B, A ==>|thick| B
6. Style classes for risk highlighting using classDef at the bottom.
7. NEVER put icons inside subgraph titles — icons only go inside node labels.

USE ICONS IN NODE LABELS for visual clarity. The following icon packs are available:
- fa: (FontAwesome Solid) — fa:shield, fa:server, fa:database, fa:lock, fa:globe, fa:code, fa:user, fa:bug, fa:key, fa:file, fa:folder, fa:gear, fa:network-wired, fa:cloud, fa:fire, fa:eye, fa:upload, fa:download, fa:terminal, fa:envelope, fa:warning
- fab: (FontAwesome Brands) — fab:php, fab:js, fab:python, fab:docker, fab:github, fab:aws, fab:react, fab:node-js, fab:android, fab:apple, fab:linux, fab:windows
- mdi: (Material Design) — mdi:application, mdi:api, mdi:database, mdi:security, mdi:web, mdi:file-code, mdi:router, mdi:memory, mdi:server, mdi:middleware, mdi:webhook

Icon syntax: Place "prefix:icon-name" at the START of the label text inside brackets.
Examples:
  A[fa:globe Web Frontend]
  B[fa:server API Backend]
  C[(fa:database MySQL)]
  D[fa:shield Auth Middleware]
  E[fa:bug Vulnerable Endpoint]

USE DIFFERENT NODE SHAPES with icons:
- [fa:icon Label] = rectangle (general components)
- ([fa:icon Label]) = stadium/pill (API endpoints, routes)
- [(fa:icon Label)] = cylinder (databases, data stores)
- {{fa:icon Label}} = hexagon (security controls, firewalls)
- ((fa:icon Label)) = circle (users, actors, external entities)

Example of a valid System Overview diagram:
flowchart TD
    subgraph Frontend
        UI([fa:globe Web UI])
        Static[fa:file Static Assets]
    end

    subgraph Backend
        API([fa:server REST API])
        Auth{{fa:shield Auth Service}}
        Worker(fa:gear Background Worker)
    end

    subgraph Storage
        DB[(fa:database SQLite)]
        Cache[(mdi:memory Redis Cache)]
    end

    UI --> API
    Static --> UI
    API --> Auth
    API --> DB
    API --> Cache
    Worker --> DB

    classDef danger fill:#7f1d1d,stroke:#f87171,color:#fecaca
    classDef warn fill:#7c2d12,stroke:#fb923c,color:#fed7aa
    classDef safe fill:#14532d,stroke:#4ade80,color:#bbf7d0
    classDef store fill:#1e3a5f,stroke:#60a5fa,color:#bfdbfe

Example of a valid Security Architecture diagram:
flowchart TD
    subgraph External
        User((fa:user Browser User))
        Attacker((fa:bug Attacker))
    end

    subgraph Trust Boundary
        LB{{fa:shield Load Balancer}}
        APIGw([fa:server API Gateway])
        AuthMw{{fa:lock Auth Check}}
    end

    subgraph Internal
        App[fa:code Application Logic]
        DB[(fa:database Database)]
    end

    User -->|HTTPS| LB
    Attacker -.->|Attack Vector| LB
    LB --> APIGw
    APIGw --> AuthMw
    AuthMw -->|Validated| App
    App --> DB

    classDef danger fill:#7f1d1d,stroke:#f87171,color:#fecaca
    classDef warn fill:#7c2d12,stroke:#fb923c,color:#fed7aa
    classDef safe fill:#14532d,stroke:#4ade80,color:#bbf7d0
    classDef store fill:#1e3a5f,stroke:#60a5fa,color:#bfdbfe
    class Attacker danger
    class LB,APIGw warn
    class AuthMw safe
    class DB store

IMPORTANT: Every node MUST have an icon. Use at least 3 different node shapes per diagram. Always include classDef colour assignments at the bottom. Keep diagrams clean with 8-15 nodes.
Do NOT include any markdown fencing or backticks — just the raw mermaid code starting with "flowchart"."""


class ArchitectureAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "architecture"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_phase = "understanding"
        ctx.current_task = "Building application understanding"
        await self.emit(ctx, "Analysing application architecture...")

        budget = ctx.iteration_budget["phase2_file_reads"]
        top_files = ctx.file_queue[:budget]

        # Read top files
        file_contents = {}
        for file_path in top_files:
            if ctx.cancelled:
                return
            ctx.current_task = f"Reading {file_path}"
            content = await self.read_file(ctx, file_path)
            file_contents[file_path] = content
            ctx.files_inspected.add(file_path)
            ctx.files_processed += 1

        await self.emit(ctx, f"Read {len(file_contents)} files for architecture analysis")

        # Build prompt
        user_content = self._build_prompt(ctx, file_contents)

        # Call LLM
        ctx.current_task = "AI analysing architecture"
        await self.emit(ctx, "AI building application model...")

        # Architecture JSON is large (4 mermaid diagrams + components + data flows).
        # Use max_output_tokens from the LLM profile, minimum 8192.
        output_tokens = max(8192, self.llm.max_output_tokens)

        result = None
        last_error = None
        for attempt in range(2):
            try:
                result = await self.llm.chat_json(
                    SYSTEM_PROMPT, user_content, max_tokens=output_tokens,
                )
                ctx.ai_calls_made += 1
                if result and (result.get("app_summary") or result.get("components")):
                    break
                # Empty result — retry with fewer files
                if attempt == 0:
                    await self.emit(ctx, "Architecture AI returned empty — retrying with reduced context...", level="warn")
                    half = len(file_contents) // 2
                    for path in list(file_contents.keys())[half:]:
                        file_contents.pop(path, None)
                    user_content = self._build_prompt(ctx, file_contents)
            except Exception as e:
                last_error = e
                if attempt == 0:
                    await self.emit(ctx, f"Architecture attempt failed: {e}. Retrying with less context...", level="warn")
                    half = len(file_contents) // 2
                    for path in list(file_contents.keys())[half:]:
                        file_contents.pop(path, None)
                    user_content = self._build_prompt(ctx, file_contents)

        if not result or not (result.get("app_summary") or result.get("components")):
            error_msg = str(last_error) if last_error else "LLM returned empty response"
            await self.emit(ctx, f"Architecture analysis failed after retries: {error_msg}. Using fallback.", level="error")
            await self.log_decision(ctx, action="architecture_failed", reasoning=error_msg)
            ctx.app_summary = (
                f"Architecture analysis unavailable (LLM error). "
                f"Repo contains {ctx.files_total} files in "
                f"{', '.join(ctx.languages) or 'unknown'} languages."
            )
            ctx.components = []
            ctx.entry_points = []
            ctx.attack_surface = []
            ctx.trust_boundaries = []
            return

        # Update context with all extracted fields
        ctx.app_summary = result.get("app_summary", "")
        ctx.app_type = result.get("app_type", "")
        # Support both old single diagram_spec and new multi-diagram format
        diagrams = result.get("diagrams", [])
        if diagrams and isinstance(diagrams, list):
            ctx.diagram_spec = diagrams[0].get("mermaid", "") if diagrams else ""
        else:
            ctx.diagram_spec = result.get("diagram_spec", "")
            # Wrap legacy single diagram in the new format
            if ctx.diagram_spec:
                diagrams = [{"title": "System Architecture", "description": "Overall system architecture", "mermaid": ctx.diagram_spec}]

        ctx.architecture_notes = json.dumps({
            "components": result.get("components", []),
            "layers": result.get("layers", {}),
            "auth_mechanisms": result.get("auth_mechanisms", []),
            "external_integrations": result.get("external_integrations", []),
            "data_flows": result.get("data_flows", []),
            "diagrams": diagrams,
        })
        ctx.trust_boundaries = result.get("trust_boundaries", [])
        ctx.attack_surface = result.get("attack_surface", [])
        ctx.entry_points = result.get("entry_points", [])
        ctx.key_observations.extend(result.get("security_observations", []))

        # Component scoping — extract and apply
        components = result.get("components", [])
        ctx.components = components

        # Build scoped attack surface from component data
        for comp in components:
            if comp.get("in_attack_surface") or comp.get("criticality") in ("critical", "high"):
                for file_path in comp.get("files", []):
                    ctx.scoped_attack_surface.add(file_path)
                    # Boost attack surface files
                    ctx.boost_file(file_path, 8.0, f"component:{comp.get('name', '?')} (attack surface)")

            if comp.get("criticality") == "low" and not comp.get("in_attack_surface"):
                # Penalise low-criticality utility files
                for file_path in comp.get("files", []):
                    ctx.boost_file(file_path, -5.0, f"component:{comp.get('name', '?')} (low criticality)")

        # Reprioritise after scoping
        ctx.reprioritise_queue()

        attack_surface_count = len(ctx.scoped_attack_surface)

        # Emit progress with updated counts
        await self.emit_progress(ctx, task="Architecture and component scoping complete")

        entry_pts = result.get("entry_points", [])
        await self.emit(
            ctx,
            f"Architecture analysis complete. "
            f"{len(components)} components ({attack_surface_count} files in attack surface), "
            f"{len(entry_pts)} entry points, {len(ctx.attack_surface)} attack surface points.",
        )

        await self.log_decision(
            ctx,
            action="architecture_complete",
            files_inspected=top_files,
            output_summary=ctx.app_summary[:500],
        )

    def _build_prompt(self, ctx: ScanContext, file_contents: dict[str, str]) -> str:
        parts = [
            "## Repository Fingerprint",
            f"Languages: {', '.join(ctx.languages)}",
            f"Frameworks: {', '.join(ctx.frameworks)}",
            f"Total files: {ctx.files_total}",
        ]

        # APK decompilation context
        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            parts.append(f"\n## IMPORTANT: Decompiled Android Application")
            parts.append(
                f"This code was decompiled from an Android {ctx.source_type.upper()} file using jadx. "
                "Key considerations:"
            )
            parts.append("- Code is decompiled Java/Kotlin, NOT original source — variable names may be obfuscated")
            parts.append("- Classes named a.b.c, single-letter variables, and goto statements are ProGuard/R8 artifacts")
            parts.append("- Focus on: AndroidManifest.xml permissions, exported components, WebView usage, "
                         "SharedPreferences, Intent handling, Content Providers, network security config")
            parts.append("- Android-specific attack surface: IPC (Intents, BroadcastReceivers), "
                         "insecure data storage, certificate validation, WebView JavaScript bridges, "
                         "deep links, backup flags, debuggable flags")
            parts.append("- Look for: hardcoded API keys, Firebase configs, insecure HTTP connections, "
                         "disabled certificate pinning, root/jailbreak detection bypasses")
            parts.append("- The app_type should be 'android_app' or 'android_library'")

        # Scanner results summary
        if ctx.scanner_hit_counts:
            parts.append("\n## Scanner Results")
            for scanner, count in ctx.scanner_hit_counts.items():
                parts.append(f"- {scanner}: {count} hits")

        # Monorepo context
        if ctx.is_monorepo and ctx.workspaces:
            parts.append(f"\n## Monorepo Structure ({len(ctx.workspaces)} workspaces)")
            for ws in ctx.workspaces[:10]:
                parts.append(f"- **{ws['name']}** ({ws['type']}) at `{ws['path']}/` — manifest: {ws['manifest']}")
            parts.append("IMPORTANT: Describe each workspace/app separately in your response. Identify which components belong to which workspace.")

        # Documentation intelligence (from READMEs, setup guides, etc.)
        if ctx.doc_intelligence:
            parts.append(f"\n## Developer Documentation Intelligence")
            parts.append(
                "The following was extracted from the project's documentation files "
                "(README, INSTALL, API docs, etc.). Use this to inform your understanding "
                "of what the app does, how it's deployed, and what to look for:"
            )
            parts.append(ctx.doc_intelligence)
            parts.append(
                "\nIMPORTANT: Documentation describes INTENT, not necessarily REALITY. "
                "Verify claims against the actual code. If docs say 'all input is validated', "
                "check whether the code actually validates it."
            )

        # Obfuscation warning
        obf = ctx.obfuscation_summary
        if obf.get("obfuscated_count", 0) > 0:
            parts.append(f"\n## Obfuscation Warning")
            parts.append(f"- {obf.get('heavily_obfuscated', 0)} files heavily obfuscated (unreadable)")
            parts.append(f"- {obf.get('moderately_obfuscated', 0)} files moderately obfuscated")
            parts.append("Focus your analysis on readable source files. Note obfuscation in your security observations.")

        # File content budget scales with model capacity
        max_chars_per_file = 4000  # Default
        if self.llm:
            available = self.llm.available_input_tokens()
            system_overhead = 2000  # System prompt tokens
            file_budget_tokens = available - system_overhead
            max_chars_per_file = max(1000, int(file_budget_tokens * 3.2 / max(len(file_contents), 1)))

        # Call graph summary for diagram generation
        if ctx.call_graph and hasattr(ctx.call_graph, 'edges') and ctx.call_graph.edges:
            parts.append(f"\n## Cross-File Call Relationships ({len(ctx.call_graph.edges)} edges)")
            parts.append("Use these to draw accurate data flow arrows in the architecture diagram:")

            # Group edges by directory pair to show component-level relationships
            dir_edges: dict[tuple[str, str], int] = {}
            for edge in ctx.call_graph.edges:
                src_dir = edge.caller_file.rsplit("/", 1)[0] if "/" in edge.caller_file else "(root)"
                dst_dir = edge.callee_file.rsplit("/", 1)[0] if "/" in edge.callee_file else "(root)"
                if src_dir != dst_dir:  # Only cross-directory edges
                    key = (src_dir, dst_dir)
                    dir_edges[key] = dir_edges.get(key, 0) + 1

            for (src, dst), count in sorted(dir_edges.items(), key=lambda x: x[1], reverse=True)[:15]:
                parts.append(f"- `{src}/` → `{dst}/` ({count} calls)")

            # Show specific high-traffic edges
            parts.append("\nKey function-level connections:")
            shown = 0
            for edge in ctx.call_graph.edges:
                if edge.caller_file != edge.callee_file and edge.confidence >= 0.7:
                    parts.append(f"- {edge.caller_file}::{edge.caller_symbol} → {edge.callee_file}::{edge.callee_symbol}")
                    shown += 1
                    if shown >= 15:
                        break

        # Import resolution summary
        if ctx.import_graph:
            external_pkgs = set()
            for resolutions in ctx.import_graph.values():
                for res in resolutions:
                    if res.is_external:
                        external_pkgs.add(res.import_module.split(".")[0].split("/")[0])
            if external_pkgs:
                parts.append(f"\n## External Dependencies ({len(external_pkgs)} packages)")
                for pkg in sorted(external_pkgs)[:20]:
                    parts.append(f"- {pkg}")
                parts.append("Include significant external services/databases in the architecture diagram.")

        parts.append("\n## Source Files")
        for path, content in file_contents.items():
            parts.append(f"\n### {path}")
            truncated = content[:max_chars_per_file]
            if len(content) > max_chars_per_file:
                truncated += f"\n[... truncated at {max_chars_per_file} chars ...]"
            parts.append(f"```\n{truncated}\n```")

        return "\n".join(parts)
