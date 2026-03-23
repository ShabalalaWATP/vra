#!/usr/bin/env python3
"""
Download technology SVG icons for offline diagram rendering.

Run this on a machine WITH internet access, then copy the output
directory to the air-gapped deployment at data/icons/svg/.

Sources:
  - Simple Icons (https://simpleicons.org) — CC0 1.0 / MIT
  - Devicons (https://devicon.dev) — MIT

Usage:
    python -m scripts.download_icons
    python -m scripts.download_icons --output data/icons/svg/
"""

import argparse
import json
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    print("httpx is required: pip install httpx")
    sys.exit(1)


# Simple Icons CDN base (jsdelivr mirrors the npm package)
SIMPLE_ICONS_CDN = "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons"

# Icons to download — maps our internal key to the Simple Icons slug.
# Comprehensive coverage: languages, frameworks, databases, cloud,
# CI/CD, security tools, observability, messaging, mobile, runtimes,
# OS, editors, protocols, CMS, ML, game engines, etc.
SIMPLE_ICONS: dict[str, str] = {
    # ── Languages ────────────────────────────────────────────────
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
    "rust": "rust",
    "ruby": "ruby",
    "php": "php",
    "csharp": "csharp",
    "c": "c",
    "cplusplus": "cplusplus",
    "swift": "swift",
    "kotlin": "kotlin",
    "scala": "scala",
    "dart": "dart",
    "lua": "lua",
    "r": "r",
    "perl": "perl",
    "haskell": "haskell",
    "elixir": "elixir",
    "erlang": "erlang",
    "zig": "zig",
    "clojure": "clojure",
    "fsharp": "fsharp",
    "ocaml": "ocaml",
    "fortran": "fortran",
    "julia": "julia",
    "nim": "nim",
    "crystal": "crystal",
    "groovy": "apachegroovy",
    "powershell": "powershell",
    "gnubash": "gnubash",
    "assemblyscript": "assemblyscript",
    "webassembly": "webassembly",
    "solidity": "solidity",
    "objectivec": "objectivec",
    "coffeescript": "coffeescript",
    "v": "v",
    "d": "d",
    # ── Frontend Frameworks ──────────────────────────────────────
    "react": "react",
    "vue": "vuedotjs",
    "angular": "angular",
    "svelte": "svelte",
    "nextjs": "nextdotjs",
    "nuxtjs": "nuxtdotjs",
    "gatsby": "gatsby",
    "astro": "astro",
    "remix": "remix",
    "solidjs": "solid",
    "preact": "preact",
    "lit": "lit",
    "alpinejs": "alpinedotjs",
    "htmx": "htmx",
    "ember": "emberdotjs",
    "qwik": "qwik",
    # ── CSS / Styling ────────────────────────────────────────────
    "tailwindcss": "tailwindcss",
    "html5": "html5",
    "css3": "css3",
    "sass": "sass",
    "less": "less",
    "postcss": "postcss",
    "styledcomponents": "styledcomponents",
    "bootstrap": "bootstrap",
    "materialui": "mui",
    "chakraui": "chakraui",
    "antdesign": "antdesign",
    "shadcnui": "shadcnui",
    # ── Build / Bundle ───────────────────────────────────────────
    "webpack": "webpack",
    "vite": "vite",
    "rollup": "rollupdotjs",
    "esbuild": "esbuild",
    "turbopack": "turbopack",
    "parcel": "parcel",
    "gulp": "gulp",
    "grunt": "grunt",
    "babel": "babel",
    "swc": "swc",
    "bun": "bun",
    "deno": "deno",
    "pnpm": "pnpm",
    "yarn": "yarn",
    "npm": "npm",
    # ── Backend Frameworks ───────────────────────────────────────
    "nodejs": "nodedotjs",
    "express": "express",
    "fastapi": "fastapi",
    "django": "django",
    "flask": "flask",
    "spring": "spring",
    "springboot": "springboot",
    "dotnet": "dotnet",
    "rails": "rubyonrails",
    "laravel": "laravel",
    "fastify": "fastify",
    "gin": "gin",
    "nestjs": "nestjs",
    "adonisjs": "adonisjs",
    "hono": "hono",
    "actix": "actix",
    "rocket": "rocket",
    "phoenix": "phoenixframework",
    "sinatra": "sinatra",
    "symfony": "symfony",
    "codeigniter": "codeigniter",
    "aspnet": "dotnet",
    "quarkus": "quarkus",
    "micronaut": "micronaut",
    "ktor": "ktor",
    "fiber": "fiber",
    "echo": "echo",
    "koa": "koa",
    "hapi": "hapi",
    "strapi": "strapi",
    # ── Databases ────────────────────────────────────────────────
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mongodb": "mongodb",
    "redis": "redis",
    "sqlite": "sqlite",
    "elasticsearch": "elasticsearch",
    "mariadb": "mariadb",
    "cassandra": "apachecassandra",
    "neo4j": "neo4j",
    "couchdb": "couchdb",
    "couchbase": "couchbase",
    "dynamodb": "amazondynamodb",
    "firestore": "firebase",
    "firebase": "firebase",
    "supabase": "supabase",
    "cockroachdb": "cockroachlabs",
    "influxdb": "influxdb",
    "timescaledb": "timescale",
    "clickhouse": "clickhouse",
    "mssql": "microsoftsqlserver",
    "oracle": "oracle",
    "arangodb": "arangodb",
    "dgraph": "dgraph",
    "planetscale": "planetscale",
    "neon": "neon",
    "drizzle": "drizzle",
    "prisma": "prisma",
    "typeorm": "typeorm",
    "sequelize": "sequelize",
    "hibernate": "hibernate",
    "realm": "realm",
    "vitess": "vitess",
    # ── Cloud Providers ──────────────────────────────────────────
    "aws": "amazonaws",
    "azure": "microsoftazure",
    "gcp": "googlecloud",
    "oracle-cloud": "oracle",
    "alibaba-cloud": "alibabacloud",
    "ibm-cloud": "ibmcloud",
    "linode": "linode",
    "vultr": "vultr",
    "hetzner": "hetzner",
    "ovh": "ovh",
    "digitalocean": "digitalocean",
    "scaleway": "scaleway",
    # ── AWS Services ─────────────────────────────────────────────
    "s3": "amazons3",
    "ec2": "amazonec2",
    "lambda": "awslambda",
    "ecs": "amazonecs",
    "eks": "amazoneks",
    "rds": "amazonrds",
    "sqs": "amazonsqs",
    "sns": "amazonsns",
    "apigateway": "amazonapigateway",
    "cloudwatch": "amazoncloudwatch",
    "cognito": "amazoncognito",
    # ── Azure Services ───────────────────────────────────────────
    "azurefunctions": "azurefunctions",
    "azuredevops": "azuredevops",
    "azurepipelines": "azurepipelines",
    # ── GCP Services ─────────────────────────────────────────────
    "bigquery": "googlebigquery",
    # ── Infrastructure / Orchestration ───────────────────────────
    "docker": "docker",
    "kubernetes": "kubernetes",
    "terraform": "terraform",
    "ansible": "ansible",
    "puppet": "puppet",
    "chef": "chef",
    "vagrant": "vagrant",
    "packer": "packer",
    "consul": "consul",
    "vault": "vault",
    "nomad": "nomad",
    "pulumi": "pulumi",
    "opentofu": "opentofu",
    "podman": "podman",
    "containerd": "containerd",
    "helm": "helm",
    "istio": "istio",
    "envoy": "envoyproxy",
    "linkerd": "linkerd",
    "traefik": "traefikproxy",
    "rancher": "rancher",
    "openshift": "redhatopenshift",
    "portainer": "portainer",
    "argo": "argo",
    "crossplane": "crossplane",
    "kustomize": "kustomize",
    # ── Web / Proxy / Server ─────────────────────────────────────
    "nginx": "nginx",
    "apache": "apache",
    "caddy": "caddy",
    "haproxy": "haproxy",
    "tomcat": "apachetomcat",
    "jetty": "eclipsejetty",
    "iis": "iis",
    # ── Serverless / PaaS / Hosting ──────────────────────────────
    "cloudflare": "cloudflare",
    "cloudflareworkers": "cloudflareworkers",
    "vercel": "vercel",
    "netlify": "netlify",
    "heroku": "heroku",
    "railway": "railway",
    "render": "render",
    "fly": "flydotio",
    "deta": "deta",
    "appwrite": "appwrite",
    "pocketbase": "pocketbase",
    # ── CI / CD ──────────────────────────────────────────────────
    "git": "git",
    "github": "github",
    "gitlab": "gitlab",
    "bitbucket": "bitbucket",
    "jenkins": "jenkins",
    "githubactions": "githubactions",
    "circleci": "circleci",
    "travisci": "travisci",
    "teamcity": "teamcity",
    "drone": "drone",
    "tekton": "tekton",
    "bamboo": "bamboo",
    "concourse": "concourse",
    "buildkite": "buildkite",
    "codeship": "codeship",
    "harness": "harness",
    "spinnaker": "spinnaker",
    "flux": "flux",
    "semaphore": "semaphoreci",
    "woodpecker": "woodpeckerci",
    # ── Messaging / Event Streaming ──────────────────────────────
    "rabbitmq": "rabbitmq",
    "kafka": "apachekafka",
    "nats": "nats",
    "zeromq": "zeromq",
    "mqtt": "mqtt",
    "celery": "celery",
    "pulsar": "apachepulsar",
    "activemq": "apacheactivemq",
    # ── Auth / Identity / Security ───────────────────────────────
    "auth0": "auth0",
    "okta": "okta",
    "keycloak": "keycloak",
    "letsencrypt": "letsencrypt",
    "openssl": "openssl",
    "oauth": "oauth",
    "jsonwebtokens": "jsonwebtokens",
    "openpolicyagent": "openpolicyagent",
    "snyk": "snyk",
    "sonarqube": "sonarqube",
    "trivy": "trivy",
    "owasp": "owasp",
    "1password": "1password",
    "bitwarden": "bitwarden",
    "wireguard": "wireguard",
    "crowdstrike": "crowdstrike",
    "hackerone": "hackerone",
    "burpsuite": "burpsuite",
    # ── Observability / Monitoring ───────────────────────────────
    "prometheus": "prometheus",
    "grafana": "grafana",
    "datadog": "datadog",
    "newrelic": "newrelic",
    "splunk": "splunk",
    "elastic": "elastic",
    "kibana": "kibana",
    "logstash": "logstash",
    "fluentd": "fluentd",
    "fluentbit": "fluentbit",
    "jaeger": "jaeger",
    "zipkin": "zipkin",
    "opentelemetry": "opentelemetry",
    "sentry": "sentry",
    "pagerduty": "pagerduty",
    "opsgenie": "opsgenie",
    "dynatrace": "dynatrace",
    "honeycomb": "honeycomb",
    "lightstep": "lightstep",
    "victoriametrics": "victoriametrics",
    "loki": "grafana",
    "tempo": "grafana",
    "mimir": "grafana",
    # ── API / Protocols ──────────────────────────────────────────
    "graphql": "graphql",
    "grpc": "grpc",
    "openapi": "openapiinitiative",
    "swagger": "swagger",
    "postman": "postman",
    "insomnia": "insomnia",
    "curl": "curl",
    "trpc": "trpc",
    "apollographql": "apollographql",
    "socketio": "socketdotio",
    "json": "json",
    "xml": "xml",
    "yaml": "yaml",
    "toml": "toml",
    "protobuf": "protobuf",
    # ── Testing ──────────────────────────────────────────────────
    "jest": "jest",
    "mocha": "mocha",
    "cypress": "cypress",
    "playwright": "playwright",
    "selenium": "selenium",
    "puppeteer": "puppeteer",
    "vitest": "vitest",
    "pytest": "pytest",
    "junit": "junit5",
    "testinglibrary": "testinglibrary",
    "storybook": "storybook",
    "k6": "k6",
    "locust": "locust",
    "gatling": "gatling",
    "cucumber": "cucumber",
    "codecov": "codecov",
    "coveralls": "coveralls",
    # ── Package Registries ───────────────────────────────────────
    "pypi": "pypi",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "packagist": "packagist",
    "homebrew": "homebrew",
    "chocolatey": "chocolatey",
    "winget": "windowsterminal",
    "snapcraft": "snapcraft",
    "flatpak": "flatpak",
    # ── CMS / Headless ───────────────────────────────────────────
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "ghost": "ghost",
    "contentful": "contentful",
    "sanity": "sanity",
    "directus": "directus",
    "keystonejs": "keystonejs",
    "payload": "payloadcms",
    "wagtail": "wagtail",
    "magento": "magento",
    "shopify": "shopify",
    "woocommerce": "woocommerce",
    "prestashop": "prestashop",
    "medusa": "medusa",
    # ── ML / AI ──────────────────────────────────────────────────
    "tensorflow": "tensorflow",
    "pytorch": "pytorch",
    "scikitlearn": "scikitlearn",
    "keras": "keras",
    "opencv": "opencv",
    "huggingface": "huggingface",
    "jupyter": "jupyter",
    "pandas": "pandas",
    "numpy": "numpy",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "mlflow": "mlflow",
    "kubeflow": "kubeflow",
    "onnx": "onnx",
    "openai": "openai",
    "langchain": "langchain",
    "ollama": "ollama",
    # ── Mobile ───────────────────────────────────────────────────
    "android": "android",
    "ios": "ios",
    "flutter": "flutter",
    "reactnative": "react",
    "ionic": "ionic",
    "capacitor": "capacitor",
    "expo": "expo",
    "xamarin": "xamarin",
    "maui": "dotnet",
    "swiftui": "swift",
    "jetpackcompose": "jetpackcompose",
    "cordova": "apachecordova",
    # ── Desktop ──────────────────────────────────────────────────
    "electron": "electron",
    "tauri": "tauri",
    "qt": "qt",
    "gtk": "gtk",
    "wxwidgets": "wxwidgets",
    # ── Game Engines ─────────────────────────────────────────────
    "unity": "unity",
    "unrealengine": "unrealengine",
    "godot": "godotengine",
    # ── Blockchain / Web3 ────────────────────────────────────────
    "ethereum": "ethereum",
    "bitcoin": "bitcoin",
    "polygon": "polygon",
    "chainlink": "chainlink",
    "ipfs": "ipfs",
    "web3js": "web3dotjs",
    "hardhat": "hardhat",
    # ── Operating Systems ────────────────────────────────────────
    "linux": "linux",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "fedora": "fedora",
    "centos": "centos",
    "redhat": "redhat",
    "archlinux": "archlinux",
    "alpine": "alpinelinux",
    "nixos": "nixos",
    "windows": "windows",
    "macos": "macos",
    "freebsd": "freebsd",
    # ── Editors / IDEs ───────────────────────────────────────────
    "vscode": "visualstudiocode",
    "visualstudio": "visualstudio",
    "intellij": "intellijidea",
    "neovim": "neovim",
    "vim": "vim",
    "emacs": "gnuemacs",
    "sublime": "sublimetext",
    "atom": "atom",
    "androidstudio": "androidstudio",
    "xcode": "xcode",
    "eclipse": "eclipseide",
    "rider": "rider",
    "pycharm": "pycharm",
    "webstorm": "webstorm",
    "goland": "goland",
    "clion": "clion",
    "rubymine": "rubymine",
    "phpstorm": "phpstorm",
    "datagrip": "datagrip",
    "cursor": "cursor",
    "zed": "zed",
    # ── Collaboration / Docs ─────────────────────────────────────
    "slack": "slack",
    "discord": "discord",
    "jira": "jira",
    "confluence": "confluence",
    "notion": "notion",
    "linear": "linear",
    "figma": "figma",
    "miro": "miro",
    "asana": "asana",
    "trello": "trello",
    "clickup": "clickup",
    # ── Data / ETL / Analytics ───────────────────────────────────
    "airflow": "apacheairflow",
    "spark": "apachespark",
    "flink": "apacheflink",
    "hadoop": "apachehadoop",
    "dbt": "dbt",
    "snowflake": "snowflake",
    "databricks": "databricks",
    "tableau": "tableau",
    "powerbi": "powerbi",
    "metabase": "metabase",
    "redash": "redash",
    "looker": "looker",
    "superset": "apachesuperset",
    # ── Miscellaneous ────────────────────────────────────────────
    "markdown": "markdown",
    "latex": "latex",
    "githubpages": "githubpages",
    "readthedocs": "readthedocs",
    "mkdocs": "materialformkdocs",
    "docusaurus": "docusaurus",
    "hugo": "hugo",
    "jekyll": "jekyll",
    "11ty": "eleventy",
    "pelican": "pelican",
    "wordpress": "wordpress",
    "matrix": "matrix",
    "mastodon": "mastodon",
    "bluesky": "bluesky",
    "rss": "rss",
    "tor": "torproject",
    "i2p": "i2p",
    "signal": "signal",
    "telegram": "telegram",
    "twilio": "twilio",
    "stripe": "stripe",
    "paypal": "paypal",
    "plaid": "plaid",
    "mapbox": "mapbox",
    "leaflet": "leaflet",
    "threedotjs": "threedotjs",
    "d3": "d3dotjs",
    "chartjs": "chartdotjs",
    "mermaid": "mermaid",
    "excalidraw": "excalidraw",
    "rawgraphs": "rawgraphs",
}

# Devicons CDN — supplementary icons not in Simple Icons
DEVICON_CDN = "https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons"
DEVICON_ICONS: dict[str, str] = {
    # key -> "folder/filename.svg" under DEVICON_CDN
    "apachespark": "apachespark/apachespark-original.svg",
    "azuresqldatabase": "azuresqldatabase/azuresqldatabase-original.svg",
    "bash": "bash/bash-original.svg",
    "blazor": "blazor/blazor-original.svg",
    "cmake": "cmake/cmake-original.svg",
    "composer": "composer/composer-original.svg",
    "grails": "grails/grails-original.svg",
    "handlebars": "handlebars/handlebars-original.svg",
    "matlab": "matlab/matlab-original.svg",
    "maven": "maven/maven-original.svg",
    "microsoftsqlserver": "microsoftsqlserver/microsoftsqlserver-original.svg",
    "mongoose": "mongoose/mongoose-original.svg",
    "nix": "nix/nix-original.svg",
    "objectivec": "objectivec/objectivec-plain.svg",
    "pandas": "pandas/pandas-original.svg",
    "redis": "redis/redis-original.svg",
    "sass": "sass/sass-original.svg",
    "spring": "spring/spring-original.svg",
    "ssh": "ssh/ssh-original.svg",
    "tomcat": "tomcat/tomcat-original.svg",
    "uwsgi": "uwsgi/uwsgi-original.svg",
    "vagrant": "vagrant/vagrant-original.svg",
    "wasm": "wasm/wasm-original.svg",
}


def download_simple_icon(client: httpx.Client, slug: str) -> str | None:
    """Download a single SVG icon from Simple Icons CDN."""
    url = f"{SIMPLE_ICONS_CDN}/{slug}.svg"
    try:
        resp = client.get(url)
        if resp.status_code == 200:
            return resp.text
        # Some slugs don't match exactly — try lowercase
        if resp.status_code == 404:
            url2 = f"{SIMPLE_ICONS_CDN}/{slug.lower()}.svg"
            resp2 = client.get(url2)
            if resp2.status_code == 200:
                return resp2.text
        return None
    except Exception as e:
        print(f"  Error downloading {slug}: {e}")
        return None


def download_devicon(client: httpx.Client, path: str) -> str | None:
    """Download a single SVG icon from the Devicon CDN."""
    url = f"{DEVICON_CDN}/{path}"
    try:
        resp = client.get(url)
        if resp.status_code == 200:
            return resp.text
        return None
    except Exception as e:
        print(f"  Error downloading devicon {path}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Download technology icons for offline use")
    parser.add_argument("--output", type=Path, default=Path("data/icons/svg"))
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip icons that already exist on disk")
    args = parser.parse_args()

    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    client = httpx.Client(timeout=15, follow_redirects=True)
    downloaded = 0
    skipped = 0
    failed = 0
    failed_keys: list[str] = []

    total = len(SIMPLE_ICONS) + len(DEVICON_ICONS)
    print(f"Downloading {total} icons ({len(SIMPLE_ICONS)} Simple Icons + {len(DEVICON_ICONS)} Devicons)...")
    print()

    # ── Simple Icons ─────────────────────────────────────────────
    for i, (key, slug) in enumerate(SIMPLE_ICONS.items(), 1):
        out_file = output / f"{key}.svg"
        if args.skip_existing and out_file.exists():
            skipped += 1
            continue

        svg = download_simple_icon(client, slug)
        if svg:
            out_file.write_text(svg)
            downloaded += 1
        else:
            failed += 1
            failed_keys.append(f"{key} (simple-icons/{slug})")

        # Progress every 50
        if i % 50 == 0:
            print(f"  [{i}/{len(SIMPLE_ICONS)}] Simple Icons processed...")

        # Be polite to CDN
        time.sleep(0.05)

    print(f"  Simple Icons: {downloaded} downloaded, {failed} failed, {skipped} skipped")

    # ── Devicon supplementary ────────────────────────────────────
    devicon_downloaded = 0
    devicon_failed = 0
    for key, path in DEVICON_ICONS.items():
        out_file = output / f"{key}.svg"
        if out_file.exists():
            # Don't overwrite if Simple Icons already got it
            skipped += 1
            continue

        svg = download_devicon(client, path)
        if svg:
            out_file.write_text(svg)
            devicon_downloaded += 1
            downloaded += 1
        else:
            devicon_failed += 1
            failed += 1
            failed_keys.append(f"{key} (devicon/{path})")

        time.sleep(0.05)

    print(f"  Devicons: {devicon_downloaded} downloaded, {devicon_failed} failed")

    # ── Write manifest ───────────────────────────────────────────
    all_keys = sorted(set(SIMPLE_ICONS.keys()) | set(DEVICON_ICONS.keys()))
    available_keys = sorted(
        f.stem for f in output.glob("*.svg")
    )

    manifest = {
        "sources": ["simple-icons (CC0-1.0)", "devicon (MIT)"],
        "total_requested": total,
        "total_downloaded": len(available_keys),
        "available": available_keys,
    }
    (output.parent / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # ── Summary ──────────────────────────────────────────────────
    print()
    print(f"{'='*50}")
    print(f"  Total downloaded: {downloaded}")
    print(f"  Total skipped:    {skipped}")
    print(f"  Total failed:     {failed}")
    print(f"  Icons on disk:    {len(available_keys)}")
    print(f"  Output:           {output}")
    print(f"{'='*50}")

    if failed_keys:
        print(f"\nFailed icons ({len(failed_keys)}):")
        for fk in failed_keys[:20]:
            print(f"  - {fk}")
        if len(failed_keys) > 20:
            print(f"  ... and {len(failed_keys) - 20} more")

    client.close()


if __name__ == "__main__":
    main()
