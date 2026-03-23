"""Icon registry — loads offline SVG icons for diagram rendering.

Icons are stored as individual SVG files in data/icons/svg/.
They are loaded once and cached in memory for fast access during
diagram rendering.

Each icon is stored in a normalised form suitable for embedding
inline into larger SVG documents.
"""

import base64
import logging
import re
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

# Alias map: normalise framework/language names to icon keys.
# This covers common shortnames, hyphenated variants, and alternative names
# so that repo fingerprinting can match regardless of how a tech is referenced.
ALIASES: dict[str, str] = {
    # ── Language variants ────────────────────────────────────────
    "py": "python",
    "python3": "python",
    "js": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "jsx": "javascript",
    "c#": "csharp",
    "c-sharp": "csharp",
    "c++": "cplusplus",
    "cpp": "cplusplus",
    "objective-c": "objectivec",
    "objc": "objectivec",
    "golang": "go",
    "rb": "ruby",
    "rs": "rust",
    "kt": "kotlin",
    "sh": "gnubash",
    "bash": "gnubash",
    "shell": "gnubash",
    "zsh": "gnubash",
    "ps1": "powershell",
    "f#": "fsharp",
    "wasm": "webassembly",
    "asc": "assemblyscript",
    "sol": "solidity",
    "jl": "julia",
    "cr": "crystal",
    "ex": "elixir",
    "erl": "erlang",
    "hs": "haskell",
    "ml": "ocaml",
    "pl": "perl",
    "cs": "csharp",
    "coffee": "coffeescript",
    # ── Frontend framework variants ──────────────────────────────
    "next": "nextjs",
    "next.js": "nextjs",
    "nuxt": "nuxtjs",
    "nuxt.js": "nuxtjs",
    "vue.js": "vue",
    "vuejs": "vue",
    "angular.js": "angular",
    "angularjs": "angular",
    "svelte-kit": "svelte",
    "sveltekit": "svelte",
    "solid": "solidjs",
    "solid.js": "solidjs",
    "alpine": "alpinejs",
    "alpine.js": "alpinejs",
    "ember.js": "ember",
    "emberjs": "ember",
    "gatsby.js": "gatsby",
    "preactjs": "preact",
    "11ty": "11ty",
    "eleventy": "11ty",
    # ── CSS / Styling variants ───────────────────────────────────
    "tailwind": "tailwindcss",
    "tw": "tailwindcss",
    "material-ui": "materialui",
    "mui": "materialui",
    "chakra": "chakraui",
    "chakra-ui": "chakraui",
    "ant-design": "antdesign",
    "antd": "antdesign",
    "shadcn": "shadcnui",
    "shadcn-ui": "shadcnui",
    "styled-components": "styledcomponents",
    "scss": "sass",
    # ── Build tool variants ──────────────────────────────────────
    "rollup.js": "rollup",
    "rollupjs": "rollup",
    "parceljs": "parcel",
    "swcjs": "swc",
    "bunjs": "bun",
    "denojs": "deno",
    # ── Backend framework variants ───────────────────────────────
    "node": "nodejs",
    "node.js": "nodejs",
    "express.js": "express",
    "expressjs": "express",
    "fastify.js": "fastify",
    "nest.js": "nestjs",
    "nestjs": "nestjs",
    "adonis": "adonisjs",
    "adonis.js": "adonisjs",
    "hono.js": "hono",
    "koa.js": "koa",
    "koajs": "koa",
    "hapi.js": "hapi",
    "hapijs": "hapi",
    "react-native": "reactnative",
    "ruby-on-rails": "rails",
    "rubyonrails": "rails",
    "ror": "rails",
    "spring-boot": "springboot",
    "aspnet": "dotnet",
    "asp.net": "dotnet",
    ".net": "dotnet",
    "dotnet-core": "dotnet",
    # ── Database variants ────────────────────────────────────────
    "postgres": "postgresql",
    "pg": "postgresql",
    "psql": "postgresql",
    "mongo": "mongodb",
    "mongosh": "mongodb",
    "mssql": "mssql",
    "sql-server": "mssql",
    "sqlserver": "mssql",
    "maria": "mariadb",
    "elastic": "elasticsearch",
    "es": "elasticsearch",
    "opensearch": "elasticsearch",
    "cockroach": "cockroachdb",
    "cockroachdb": "cockroachdb",
    "dynamo": "dynamodb",
    "dynamodb": "dynamodb",
    "influx": "influxdb",
    "timescale": "timescaledb",
    "click-house": "clickhouse",
    "arango": "arangodb",
    "rethinkdb": "rethinkdb",
    # ── Cloud variants ───────────────────────────────────────────
    "amazon": "aws",
    "amazon-web-services": "aws",
    "google-cloud": "gcp",
    "google-cloud-platform": "gcp",
    "googlecloud": "gcp",
    "microsoft-azure": "azure",
    "ms-azure": "azure",
    "ibm": "ibm-cloud",
    "alibaba": "alibaba-cloud",
    "aliyun": "alibaba-cloud",
    "do": "digitalocean",
    "digital-ocean": "digitalocean",
    # ── AWS service variants ─────────────────────────────────────
    "aws-lambda": "lambda",
    "aws-s3": "s3",
    "aws-ec2": "ec2",
    "aws-ecs": "ecs",
    "aws-eks": "eks",
    "aws-rds": "rds",
    "aws-sqs": "sqs",
    "aws-sns": "sns",
    "aws-cognito": "cognito",
    "cloudwatch": "cloudwatch",
    "api-gateway": "apigateway",
    # ── Infra / Orchestration variants ───────────────────────────
    "k8s": "kubernetes",
    "kube": "kubernetes",
    "tf": "terraform",
    "hcl": "terraform",
    "opentofu": "opentofu",
    "tofu": "opentofu",
    "k3s": "kubernetes",
    "minikube": "kubernetes",
    "kind": "kubernetes",
    "docker-compose": "docker",
    "docker-swarm": "docker",
    "hashicorp-vault": "vault",
    "hashicorp-consul": "consul",
    "hashicorp-nomad": "nomad",
    "hashicorp-packer": "packer",
    "service-mesh": "istio",
    "envoy-proxy": "envoy",
    "traefik-proxy": "traefik",
    # ── CI/CD variants ───────────────────────────────────────────
    "gh": "github",
    "github-actions": "githubactions",
    "gh-actions": "githubactions",
    "gl": "gitlab",
    "gitlab-ci": "gitlab",
    "bb": "bitbucket",
    "bitbucket-pipelines": "bitbucket",
    "travis": "travisci",
    "travis-ci": "travisci",
    "circle-ci": "circleci",
    "circle": "circleci",
    "tc": "teamcity",
    "argocd": "argo",
    "argo-cd": "argo",
    "fluxcd": "flux",
    "flux-cd": "flux",
    # ── Messaging variants ───────────────────────────────────────
    "rabbit": "rabbitmq",
    "rabbit-mq": "rabbitmq",
    "amqp": "rabbitmq",
    "apache-kafka": "kafka",
    "nats.io": "nats",
    "zmq": "zeromq",
    "0mq": "zeromq",
    "apache-pulsar": "pulsar",
    "active-mq": "activemq",
    # ── Web server variants ──────────────────────────────────────
    "httpd": "apache",
    "apache-httpd": "apache",
    "apache-tomcat": "tomcat",
    "eclipse-jetty": "jetty",
    # ── Auth / Security variants ─────────────────────────────────
    "ssl": "openssl",
    "tls": "openssl",
    "jwt": "jsonwebtokens",
    "json-web-tokens": "jsonwebtokens",
    "json-web-token": "jsonwebtokens",
    "opa": "openpolicyagent",
    "open-policy-agent": "openpolicyagent",
    "wire-guard": "wireguard",
    "sonar": "sonarqube",
    "sonar-qube": "sonarqube",
    "burp": "burpsuite",
    "burp-suite": "burpsuite",
    "h1": "hackerone",
    "hacker-one": "hackerone",
    # ── Observability variants ───────────────────────────────────
    "prom": "prometheus",
    "dd": "datadog",
    "data-dog": "datadog",
    "new-relic": "newrelic",
    "elk": "elasticsearch",
    "otel": "opentelemetry",
    "open-telemetry": "opentelemetry",
    "pager-duty": "pagerduty",
    "ops-genie": "opsgenie",
    "victoria-metrics": "victoriametrics",
    # ── API / Protocol variants ──────────────────────────────────
    "gql": "graphql",
    "apollo": "apollographql",
    "apollo-graphql": "apollographql",
    "socket.io": "socketio",
    "websocket": "socketio",
    "open-api": "openapi",
    "swagger-ui": "swagger",
    "proto": "protobuf",
    "protocol-buffers": "protobuf",
    # ── Testing variants ─────────────────────────────────────────
    "testing-library": "testinglibrary",
    "rtl": "testinglibrary",
    "pw": "playwright",
    "junit5": "junit",
    "junit4": "junit",
    "code-cov": "codecov",
    # ── ML / AI variants ─────────────────────────────────────────
    # "tf" alias is already used for terraform (line 174); use full name here
    "tensorflow": "tensorflow",
    "torch": "pytorch",
    "sklearn": "scikitlearn",
    "scikit-learn": "scikitlearn",
    "hf": "huggingface",
    "hugging-face": "huggingface",
    "transformers": "huggingface",
    "llm": "openai",
    "chatgpt": "openai",
    "gpt": "openai",
    "lang-chain": "langchain",
    "ml-flow": "mlflow",
    "kube-flow": "kubeflow",
    "np": "numpy",
    "pd": "pandas",
    # ── Mobile variants ──────────────────────────────────────────
    "rn": "reactnative",
    "react native": "reactnative",
    "jetpack-compose": "jetpackcompose",
    "jetpack compose": "jetpackcompose",
    "swift-ui": "swiftui",
    "swiftui": "swiftui",
    "apache-cordova": "cordova",
    # ── Desktop variants ─────────────────────────────────────────
    "electron.js": "electron",
    "electronjs": "electron",
    # ── Game engine variants ─────────────────────────────────────
    "ue": "unrealengine",
    "ue5": "unrealengine",
    "ue4": "unrealengine",
    "unreal": "unrealengine",
    "godot-engine": "godot",
    "unity3d": "unity",
    # ── OS variants ──────────────────────────────────────────────
    "osx": "macos",
    "mac": "macos",
    "win": "windows",
    "win32": "windows",
    "win64": "windows",
    "rhel": "redhat",
    "red-hat": "redhat",
    "arch": "archlinux",
    "alpine-linux": "alpine",
    "nix": "nixos",
    "bsd": "freebsd",
    # ── Editor variants ──────────────────────────────────────────
    "vs-code": "vscode",
    "vs code": "vscode",
    "vs": "visualstudio",
    "idea": "intellij",
    "intellij-idea": "intellij",
    "nvim": "neovim",
    "sublime-text": "sublime",
    "android-studio": "androidstudio",
    "eclipse-ide": "eclipse",
    # ── CMS variants ─────────────────────────────────────────────
    "wp": "wordpress",
    "woo": "woocommerce",
    "woo-commerce": "woocommerce",
    "contentful-cms": "contentful",
    "payload-cms": "payload",
    # ── Data / Analytics variants ────────────────────────────────
    "apache-airflow": "airflow",
    "apache-spark": "spark",
    "pyspark": "spark",
    "apache-flink": "flink",
    "apache-hadoop": "hadoop",
    "power-bi": "powerbi",
    "apache-superset": "superset",
    # ── Blockchain variants ──────────────────────────────────────
    "eth": "ethereum",
    "btc": "bitcoin",
    "web3": "web3js",
    "web3.js": "web3js",
    "hardhat-eth": "hardhat",
    # ── Communication variants ───────────────────────────────────
    "tg": "telegram",
    "telegram-bot": "telegram",
    # ── Package registry variants ────────────────────────────────
    "pip": "pypi",
    "gems": "rubygems",
    "gem": "rubygems",
    "brew": "homebrew",
    "choco": "chocolatey",
    "snap": "snapcraft",
}

# In-memory cache: key -> svg_string
_icon_cache: dict[str, str] = {}
_loaded = False


def _load_icons():
    """Load all SVG icons from disk into memory."""
    global _loaded
    if _loaded:
        return

    icons_dir = settings.data_dir / "icons" / "svg"
    if not icons_dir.exists():
        logger.warning("Icons directory not found: %s", icons_dir)
        _loaded = True
        return

    count = 0
    for svg_file in icons_dir.glob("*.svg"):
        key = svg_file.stem.lower()
        try:
            svg_content = svg_file.read_text(encoding="utf-8")
            # Clean up the SVG for embedding
            svg_content = _prepare_for_embedding(svg_content, key)
            _icon_cache[key] = svg_content
            count += 1
        except Exception as e:
            logger.warning("Failed to load icon %s: %s", key, e)

    logger.info("Loaded %d icons from %s", count, icons_dir)
    _loaded = True


def _prepare_for_embedding(svg: str, key: str) -> str:
    """
    Prepare an SVG for inline embedding in a larger SVG document.
    - Remove XML declaration
    - Ensure viewBox is present
    - Add a consistent class for styling
    """
    # Remove XML declaration
    svg = re.sub(r'<\?xml[^?]*\?>\s*', '', svg)
    # Remove any existing width/height to rely on viewBox
    svg = re.sub(r'\s+width="[^"]*"', '', svg)
    svg = re.sub(r'\s+height="[^"]*"', '', svg)
    # Ensure viewBox exists
    if 'viewBox' not in svg:
        svg = svg.replace('<svg', '<svg viewBox="0 0 24 24"', 1)
    return svg


def get_icon_svg(name: str) -> str | None:
    """
    Get the SVG content for a technology icon.
    Returns None if the icon is not found.
    """
    _load_icons()
    key = name.lower().strip()
    key = ALIASES.get(key, key)
    return _icon_cache.get(key)


def get_icon_data_uri(name: str, color: str = "#e0e0e0") -> str | None:
    """
    Get an icon as a data URI suitable for use in <image> tags.
    Optionally recolors the icon (Simple Icons are single-path monochrome).
    """
    svg = get_icon_svg(name)
    if not svg:
        return None

    # Recolor: Simple Icons SVGs use a single fill color
    if color:
        # Replace existing fill
        svg = re.sub(r'fill="[^"]*"', f'fill="{color}"', svg)
        # If no fill attribute, add one to the <svg> tag
        if f'fill="{color}"' not in svg:
            svg = svg.replace('<svg', f'<svg fill="{color}"', 1)

    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def get_available_icons() -> list[str]:
    """Get a list of all available icon keys."""
    _load_icons()
    return sorted(_icon_cache.keys())


def has_icon(name: str) -> bool:
    """Check if an icon is available for a given name."""
    _load_icons()
    key = name.lower().strip()
    key = ALIASES.get(key, key)
    return key in _icon_cache


def get_icon_for_tech(tech_name: str, color: str = "#e0e0e0") -> dict | None:
    """
    Get icon info for a technology name. Returns a dict with
    svg, data_uri, and key, or None if not found.
    """
    _load_icons()
    key = tech_name.lower().strip()
    key = ALIASES.get(key, key)

    svg = _icon_cache.get(key)
    if not svg:
        return None

    return {
        "key": key,
        "svg": svg,
        "data_uri": get_icon_data_uri(key, color),
    }


def create_icon_legend_svg(
    techs: list[str],
    *,
    icon_size: int = 24,
    spacing: int = 16,
    color: str = "#e0e0e0",
    label_color: str = "#a0a0b0",
    bg_color: str = "#111128",
) -> str:
    """
    Create an SVG legend strip showing icons for detected technologies.
    Useful for embedding in report diagrams.
    """
    _load_icons()

    entries = []
    for tech in techs:
        key = tech.lower().strip()
        key = ALIASES.get(key, key)
        if key in _icon_cache:
            entries.append((tech, key))

    if not entries:
        return ""

    cols = min(len(entries), 8)
    rows = (len(entries) + cols - 1) // cols
    cell_w = icon_size + spacing + 100  # icon + gap + label
    cell_h = icon_size + spacing
    width = cols * cell_w + spacing
    height = rows * cell_h + spacing * 2

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        f'<rect width="100%" height="100%" fill="{bg_color}" rx="8"/>',
    ]

    for i, (label, key) in enumerate(entries):
        col = i % cols
        row = i // cols
        x = spacing + col * cell_w
        y = spacing + row * cell_h

        data_uri = get_icon_data_uri(key, color)
        if data_uri:
            parts.append(
                f'<image x="{x}" y="{y}" width="{icon_size}" height="{icon_size}" '
                f'href="{data_uri}"/>'
            )

        label_x = x + icon_size + 8
        label_y = y + icon_size // 2 + 4
        escaped_label = label.replace("&", "&amp;").replace("<", "&lt;")
        parts.append(
            f'<text x="{label_x}" y="{label_y}" fill="{label_color}" '
            f'font-family="Inter, sans-serif" font-size="12">{escaped_label}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)
