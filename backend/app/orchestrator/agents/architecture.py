"""Architecture Agent — build understanding of what the app does."""

import json
import logging

from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)

CANONICAL_DIAGRAM_METADATA = {
    "overview": {
        "title": "System Overview",
        "description": "High-level architecture showing main components and their connections",
    },
    "security": {
        "title": "Security Architecture",
        "description": "Trust boundaries, auth flows, data entry points, sensitive data stores",
    },
    "data_flow": {
        "title": "Data Flow",
        "description": "How data moves through the application from user input to storage and back",
    },
    "attack_surface": {
        "title": "Attack Surface",
        "description": "All points where an attacker could interact with the application",
    },
}

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
      "kind": "overview",
      "title": "System Overview",
      "description": "High-level architecture showing main components and their connections",
      "mermaid": "<valid mermaid flowchart TD code>"
    },
    {
      "kind": "security",
      "title": "Security Architecture",
      "description": "Trust boundaries, auth flows, data entry points, sensitive data stores",
      "mermaid": "<valid mermaid flowchart TD code>"
    },
    {
      "kind": "data_flow",
      "title": "Data Flow",
      "description": "How data moves through the application from user input to storage and back",
      "mermaid": "<valid mermaid flowchart LR code>"
    },
    {
      "kind": "attack_surface",
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


ARCHITECTURE_MODEL_SYSTEM_PROMPT = """You are a senior security researcher analysing a software application.
Your task is to understand what this application does, how it is structured, and where its security-relevant attack surface lies.

This is the first architecture pass. Produce only the factual architecture model. Do not generate Mermaid diagrams in this response.

You will be given:
- A repository fingerprint (languages, frameworks, file count)
- The top priority files with their code contents
- Discovered routes, call graph hotspots, and integration signals where available

Produce a JSON response with these fields:
{
  "app_summary": "2-4 paragraph detailed description of what this application does, what problem it solves, who its users are, and how it is deployed",
  "app_type": "web_app|api|cli|library|microservice|mobile_backend|monolith|static_site|android_app|android_library",
  "components": [{"name": "component name", "purpose": "what it does", "files": ["key files"], "criticality": "critical|high|medium|low", "in_attack_surface": true, "handles_user_input": true}],
  "layers": {
    "frontend": ["files/dirs"],
    "backend": ["files/dirs"],
    "database": ["files/dirs"],
    "config": ["files/dirs"],
    "infra": ["files/dirs"]
  },
  "entry_points": [{"file": "path", "function": "name", "type": "http_endpoint|cli_command|websocket|scheduled_task|message_handler", "method": "GET|POST|etc", "path": "/api/..."}],
  "trust_boundaries": ["list of trust boundary descriptions"],
  "data_flows": [{"from": "component/file", "to": "component/file", "data": "what flows", "sensitive": true}],
  "attack_surface": ["specific attack surface points referencing actual files and functions"],
  "auth_mechanisms": [{"type": "jwt|session|oauth|api_key|basic|none", "implementation": "where and how", "weaknesses": "any observed weaknesses"}],
  "external_integrations": ["databases, APIs, message queues, cloud services the app connects to"],
  "security_observations": ["specific security observations referencing actual code seen"]
}

Return only one JSON object. Do not include markdown fences, explanations, or reasoning text."""


DIAGRAM_SYSTEM_PROMPT = """You are a senior security architect generating Mermaid diagrams from an existing architecture model.

This is the second architecture pass. Do not re-analyse source code. Use the supplied architecture model and signals to produce diagrams only.

Produce a JSON response with this shape:
{
  "diagrams": [
    {"kind": "overview", "title": "System Overview", "description": "High-level architecture showing main components and their connections", "mermaid": "<valid mermaid flowchart TD code>"},
    {"kind": "security", "title": "Security Architecture", "description": "Trust boundaries, auth flows, data entry points, sensitive data stores", "mermaid": "<valid mermaid flowchart TD code>"},
    {"kind": "data_flow", "title": "Data Flow", "description": "How data moves through the application from user input to storage and back", "mermaid": "<valid mermaid flowchart LR code>"},
    {"kind": "attack_surface", "title": "Attack Surface", "description": "All points where an attacker could interact with the application", "mermaid": "<valid mermaid flowchart TD code>"}
  ]
}

CRITICAL MERMAID RULES:
1. Use only standard "flowchart TD" or "flowchart LR" syntax.
2. Do not use architecture-beta, C4, or experimental diagram types.
3. Node IDs must be simple alphanumeric identifiers with no spaces or punctuation.
4. Labels must avoid quotes, unescaped parentheses, ampersands, and angle brackets.
5. Every node must have an icon at the start of its label, such as fa:globe, fa:server, fa:database, fa:shield, fa:lock, fa:user, fa:bug, fa:key, fa:file, fa:code, fab:react, fab:node-js, fab:python, mdi:api, mdi:web, or mdi:security.
6. Use at least three node shapes per diagram: rectangle, stadium, cylinder, hexagon, or circle.
7. Include classDef danger, warn, safe, and store color assignments at the bottom.
8. Keep each diagram clean with roughly 8-15 nodes.
9. Do not include markdown fences or backticks inside the mermaid field.

Return only one JSON object. Do not include markdown fences, explanations, or reasoning text."""


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

        # Build the source-grounded prompt for the first, non-diagram pass.
        user_content = self._build_prompt(ctx, file_contents)

        ctx.current_task = "AI analysing architecture"
        await self.emit(ctx, "AI building application model...")

        # Use the profile's configured output cap. Do not force a larger minimum:
        # some compatible endpoints behave better when asked for only what is needed.
        output_tokens = self.llm.max_output_tokens

        result = None
        last_error = None
        max_retries = 3
        for attempt in range(max_retries + 1):
            try:
                result = await self.llm.chat_json(
                    ARCHITECTURE_MODEL_SYSTEM_PROMPT, user_content, max_tokens=output_tokens,
                )
                ctx.ai_calls_made += 1
                if result and (result.get("app_summary") or result.get("components")):
                    break
                # Empty result — retry with fewer files
                if attempt < max_retries:
                    await self.emit(ctx, "Architecture AI returned empty — retrying with reduced context...", level="warn")
                    half = len(file_contents) // 2
                    for path in list(file_contents.keys())[half:]:
                        file_contents.pop(path, None)
                    user_content = self._build_prompt(ctx, file_contents)
            except Exception as e:
                last_error = e
                if attempt < max_retries:
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

        # Diagrams are generated in a second, smaller call from the compact model.
        diagrams: list[dict] = []
        try:
            ctx.current_task = "AI generating architecture diagrams"
            await self.emit(ctx, "AI generating architecture diagrams...")
            diagrams = await self._generate_architecture_diagrams(ctx, result, output_tokens)
        except Exception as e:
            logger.exception("Architecture diagram generation failed")
            await self.emit(
                ctx,
                f"Architecture diagrams failed: {e}. Continuing with text model.",
                level="warn",
            )
            await self.log_decision(ctx, action="architecture_diagrams_failed", reasoning=str(e))

        # Update context with all extracted fields
        ctx.app_summary = result.get("app_summary", "")
        ctx.app_type = result.get("app_type", "")
        ctx.diagram_spec = diagrams[0].get("mermaid", "") if diagrams else ""

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
            f"{len(entry_pts)} entry points, {len(ctx.attack_surface)} attack surface points, "
            f"{len(diagrams)} diagrams.",
        )

        await self.log_decision(
            ctx,
            action="architecture_complete",
            files_inspected=top_files,
            output_summary=ctx.app_summary[:500],
        )

    async def _generate_architecture_diagrams(
        self,
        ctx: ScanContext,
        architecture_model: dict,
        output_tokens: int,
    ) -> list[dict]:
        diagram_user_content = self._build_diagram_prompt(ctx, architecture_model)
        max_retries = 3
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                result = await self.llm.chat_json(
                    DIAGRAM_SYSTEM_PROMPT,
                    diagram_user_content,
                    max_tokens=output_tokens,
                )
                ctx.ai_calls_made += 1
                diagrams = self._normalise_architecture_diagrams(result.get("diagrams", []))
                if diagrams:
                    return diagrams
                if attempt < max_retries:
                    await self.emit(
                        ctx,
                        "Architecture diagram AI returned empty - retrying...",
                        level="warn",
                    )
            except Exception as e:
                last_error = e
                if attempt < max_retries:
                    await self.emit(
                        ctx,
                        f"Architecture diagram attempt failed: {e}. Retrying...",
                        level="warn",
                    )

        reason = str(last_error) if last_error else "LLM returned empty diagram response"
        await self.emit(
            ctx,
            f"Architecture diagrams unavailable after retries: {reason}. Continuing without diagrams.",
            level="warn",
        )
        await self.log_decision(ctx, action="architecture_diagrams_unavailable", reasoning=reason)
        return []

    def _build_diagram_prompt(self, ctx: ScanContext, architecture_model: dict) -> str:
        compact_model = {
            "app_summary": architecture_model.get("app_summary", ""),
            "app_type": architecture_model.get("app_type", ""),
            "components": architecture_model.get("components", []),
            "layers": architecture_model.get("layers", {}),
            "entry_points": architecture_model.get("entry_points", []),
            "trust_boundaries": architecture_model.get("trust_boundaries", []),
            "data_flows": architecture_model.get("data_flows", []),
            "attack_surface": architecture_model.get("attack_surface", []),
            "auth_mechanisms": architecture_model.get("auth_mechanisms", []),
            "external_integrations": architecture_model.get("external_integrations", []),
            "security_observations": architecture_model.get("security_observations", []),
        }

        parts = [
            "## Architecture Model",
            "Use this compact source-grounded model as the sole basis for diagrams.",
            "```json",
            json.dumps(compact_model, indent=2),
            "```",
        ]

        route_inventory = self._collect_route_inventory(ctx, limit=12)
        if route_inventory:
            parts.append("\n## Route Inventory")
            for route in route_inventory:
                parts.append(f"- {route}")

        call_graph_hotspots = self._collect_call_graph_hotspots(ctx, limit=8)
        if call_graph_hotspots:
            parts.append("\n## Call Graph Hotspots")
            for hotspot in call_graph_hotspots:
                parts.append(f"- {hotspot}")

        external_touchpoints = self._collect_external_touchpoints(ctx, limit=10)
        if external_touchpoints:
            parts.append("\n## External Integration Touchpoints")
            for touchpoint in external_touchpoints:
                parts.append(f"- {touchpoint}")

        auth_touchpoints = self._collect_auth_and_config_touchpoints(ctx, limit=10)
        if auth_touchpoints:
            parts.append("\n## Auth / Middleware / Config Touchpoints")
            for touchpoint in auth_touchpoints:
                parts.append(f"- {touchpoint}")

        return "\n".join(parts)

    @classmethod
    def _normalise_architecture_diagrams(cls, diagrams: list[dict]) -> list[dict]:
        normalised: list[tuple[int, dict]] = []
        seen_keys: set[str] = set()
        for position, diagram in enumerate(diagrams or []):
            if not isinstance(diagram, dict):
                continue
            mermaid = str(diagram.get("mermaid") or "").strip()
            if not mermaid:
                continue
            kind = cls._diagram_kind(str(diagram.get("kind") or ""), str(diagram.get("title") or ""))
            metadata = CANONICAL_DIAGRAM_METADATA.get(kind or "")
            title = metadata["title"] if metadata else str(diagram.get("title") or "Architecture Overview").strip()
            description = str(diagram.get("description") or "").strip()
            if metadata and not description:
                description = metadata["description"]
            entry = {
                "title": title,
                "description": description,
                "kind": kind or str(diagram.get("kind") or "").strip() or None,
                "mermaid": mermaid,
            }
            if "highlights" in diagram and isinstance(diagram.get("highlights"), list):
                entry["highlights"] = [
                    str(item).strip()
                    for item in diagram.get("highlights", [])
                    if str(item).strip()
                ]
            key = f"kind:{entry['kind']}" if entry.get("kind") else f"title:{title.lower()}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            normalised.append((cls._diagram_sort_rank(entry.get("kind")), position, entry))

        normalised.sort(key=lambda item: (item[0], item[1]))
        return [entry for _rank, _position, entry in normalised]

    @staticmethod
    def _diagram_kind(raw_kind: str, title: str) -> str | None:
        kind = str(raw_kind or "").strip().lower().replace("-", "_").replace(" ", "_")
        if kind in CANONICAL_DIAGRAM_METADATA:
            return kind

        title_key = " ".join(str(title or "").strip().lower().split())
        title_map = {
            "system overview": "overview",
            "overview": "overview",
            "architecture overview": "overview",
            "system architecture": "overview",
            "security architecture": "security",
            "security overview": "security",
            "data flow": "data_flow",
            "dataflow": "data_flow",
            "attack surface": "attack_surface",
        }
        return title_map.get(title_key)

    @staticmethod
    def _diagram_sort_rank(kind: str | None) -> int:
        order = {
            "overview": 0,
            "security": 1,
            "data_flow": 2,
            "attack_surface": 3,
        }
        return order.get(str(kind or ""), 100)

    @staticmethod
    def _dedupe_preserve_order(values: list[str], limit: int) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            text = str(value).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            deduped.append(text)
            if len(deduped) >= limit:
                break
        return deduped

    def _collect_route_inventory(self, ctx: ScanContext, limit: int = 20) -> list[str]:
        routes: list[str] = []
        for file_path, analysis in sorted(ctx.file_analyses.items()):
            for route in getattr(analysis, "routes", []) or []:
                if not isinstance(route, dict):
                    continue
                method = str(route.get("method") or "").strip().upper()
                path = str(route.get("path") or route.get("route") or "").strip()
                line = route.get("line")
                location = f"{file_path}:{line}" if isinstance(line, int) else file_path
                headline = " ".join(part for part in (method, path) if part).strip() or "route"
                routes.append(f"{headline} ({location})")
        return self._dedupe_preserve_order(routes, limit)

    def _collect_entrypoint_signals(self, ctx: ScanContext, limit: int = 12) -> list[str]:
        signals: list[str] = []
        for file_path, analysis in sorted(ctx.file_analyses.items()):
            if getattr(analysis, "has_main", False):
                signals.append(f"Main entrypoint in {file_path}")
            route_count = len(getattr(analysis, "routes", []) or [])
            if route_count > 0:
                signals.append(f"Route hub in {file_path} ({route_count} routes)")
        return self._dedupe_preserve_order(signals, limit)

    def _collect_call_graph_hotspots(self, ctx: ScanContext, limit: int = 10) -> list[str]:
        if not ctx.call_graph or not hasattr(ctx.call_graph, "get_high_indegree_files"):
            return []
        hotspots = [
            f"{file_path} ({count} incoming calls)"
            for file_path, count in ctx.call_graph.get_high_indegree_files(limit=limit)
            if file_path
        ]
        return self._dedupe_preserve_order(hotspots, limit)

    def _collect_external_touchpoints(self, ctx: ScanContext, limit: int = 15) -> list[str]:
        module_to_files: dict[str, set[str]] = {}
        for file_path, resolutions in (ctx.import_graph or {}).items():
            for resolution in resolutions:
                if not getattr(resolution, "is_external", False):
                    continue
                module_name = str(getattr(resolution, "import_module", "") or "").strip()
                if not module_name:
                    continue
                top_level = module_name.split(".")[0].split("/")[0]
                if not top_level:
                    continue
                module_to_files.setdefault(top_level, set()).add(file_path)

        ordered = sorted(
            module_to_files.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
        touchpoints = [
            f"{module} used by {', '.join(sorted(files)[:3])}"
            for module, files in ordered
        ]
        return self._dedupe_preserve_order(touchpoints, limit)

    def _collect_auth_and_config_touchpoints(self, ctx: ScanContext, limit: int = 15) -> list[str]:
        keywords = {
            "auth": "auth",
            "login": "auth",
            "oauth": "auth",
            "jwt": "auth",
            "session": "auth",
            "permission": "authorization",
            "role": "authorization",
            "middleware": "middleware",
            "guard": "middleware",
            "config": "config",
            "settings": "config",
            "env": "config",
            "secret": "secrets",
            "credential": "secrets",
        }
        touchpoints: list[str] = []
        for file_path, analysis in sorted(ctx.file_analyses.items()):
            lower_path = file_path.lower()
            reasons: set[str] = set()
            for token, label in keywords.items():
                if token in lower_path:
                    reasons.add(label)
            for ts_import in getattr(analysis, "imports", []) or []:
                module = str(getattr(ts_import, "module", "") or "").lower()
                for token, label in keywords.items():
                    if token in module:
                        reasons.add(label)
            if reasons:
                touchpoints.append(f"{file_path} [{', '.join(sorted(reasons))}]")
        return self._dedupe_preserve_order(touchpoints, limit)

    def _build_prompt(self, ctx: ScanContext, file_contents: dict[str, str]) -> str:
        parts = [
            "## Repository Fingerprint",
            f"Languages: {', '.join(ctx.languages)}",
            f"Frameworks: {', '.join(ctx.frameworks)}",
            f"Total files: {ctx.files_total}",
        ]

        # APK decompilation context
        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            parts.append("\n## IMPORTANT: Decompiled Android Application")
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
            parts.append("\n## Developer Documentation Intelligence")
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
            parts.append("\n## Obfuscation Warning")
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

        # Call graph summary for architecture modelling
        if ctx.call_graph and hasattr(ctx.call_graph, 'edges') and ctx.call_graph.edges:
            parts.append(f"\n## Cross-File Call Relationships ({len(ctx.call_graph.edges)} edges)")
            parts.append("Use these to understand component relationships and data flows:")

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
                parts.append("Include significant external services/databases in external_integrations and data_flows.")

        route_inventory = self._collect_route_inventory(ctx)
        entrypoint_signals = self._collect_entrypoint_signals(ctx)
        if route_inventory or entrypoint_signals:
            parts.append("\n## Route Inventory / Entry Point Signals")
            parts.append(
                "Use these discovered routes and entrypoint hints to ground entry_points and attack_surface."
            )
            for route in route_inventory:
                parts.append(f"- Route: {route}")
            for signal in entrypoint_signals:
                parts.append(f"- Signal: {signal}")

        call_graph_hotspots = self._collect_call_graph_hotspots(ctx)
        if call_graph_hotspots:
            parts.append("\n## Call Graph Hotspots")
            parts.append("These files attract the most incoming call traffic and are likely architectural hubs:")
            for hotspot in call_graph_hotspots:
                parts.append(f"- {hotspot}")

        external_touchpoints = self._collect_external_touchpoints(ctx)
        if external_touchpoints:
            parts.append("\n## External Integration Touchpoints")
            parts.append("These external modules appear in the codebase and should inform integration nodes in the diagrams:")
            for touchpoint in external_touchpoints:
                parts.append(f"- {touchpoint}")

        auth_touchpoints = self._collect_auth_and_config_touchpoints(ctx)
        if auth_touchpoints:
            parts.append("\n## Auth / Middleware / Config Touchpoints")
            parts.append("These files are likely to define trust boundaries, security controls, or runtime configuration:")
            for touchpoint in auth_touchpoints:
                parts.append(f"- {touchpoint}")

        parts.append("\n## Source Files")
        for path, content in file_contents.items():
            parts.append(f"\n### {path}")
            truncated = content[:max_chars_per_file]
            if len(content) > max_chars_per_file:
                truncated += f"\n[... truncated at {max_chars_per_file} chars ...]"
            parts.append(f"```\n{truncated}\n```")

        return "\n".join(parts)
