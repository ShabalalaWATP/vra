import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/api/client", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

vi.mock("@/components/ChatWindow", () => ({
  default: () => null,
}));

vi.mock("@/components/MermaidDiagram", () => ({
  MermaidDiagram: () => null,
}));

vi.mock("@/components/charts/Charts", () => ({
  SeverityDonut: () => null,
  ScannerHitsChart: () => null,
  FindingSourceChart: () => null,
  LanguageChart: () => null,
  CategoryChart: () => null,
  ConfidenceDistribution: () => null,
  DependencyRiskDonut: () => null,
  VerificationLevelChart: () => null,
}));

import {
  ArchitectureAnalysisPanel,
  AttackPathPanel,
  ExploitChainsSection,
  parseArchitecturePayload,
} from "./ReportPage";
import type { Finding } from "@/types";

function buildFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    scan_id: "scan-1",
    title: "Privilege escalation exploit chain",
    severity: "high",
    confidence: 0.88,
    category: "exploit_chain",
    description: "A missing auth check and unsafe queue consumer can be chained.",
    explanation: "The export route is exposed to low-privilege users.",
    impact: "Admin export and downstream data disclosure.",
    remediation: "Add role enforcement and queue validation.",
    code_snippet: null,
    status: "confirmed",
    cwe_ids: null,
    related_cves: null,
    exploit_difficulty: "moderate",
    exploit_prerequisites: ["authenticated low-privilege account"],
    exploit_template: null,
    attack_scenario: "Trigger export -> escalate privileges -> read resulting artifact",
    exploit_evidence: {
      difficulty: "moderate",
      target_route: "POST /api/export",
      prerequisites: ["authenticated low-privilege account"],
      validation_steps: [
        "Authenticate as a standard user.",
        "Trigger the export route with an admin scoped payload.",
        "Confirm the exported artifact contains privileged data.",
      ],
      cleanup_notes: ["Delete the generated export artifact."],
      exploit_template: "curl -X POST https://target/api/export",
      attack_scenario: "Abuse the export queue to produce an admin dataset.",
      components: ["Export API", "Queue Worker"],
      related_entry_points: ["POST /api/export in api/routes.py::export_data [http_endpoint]"],
      related_taint_flows: ["request.body api/routes.py:14 -> queue.enqueue api/export.py:48"],
    },
    evidence: [],
    file_paths: ["api/export.py"],
    created_at: "2026-04-13T10:00:00Z",
    ...overrides,
  };
}

describe("parseArchitecturePayload", () => {
  it("normalizes entry points, data flows, attack surface points, and hotspot metadata", () => {
    const payload = parseArchitecturePayload(
      JSON.stringify({
        analysis_markdown: "Architecture summary",
        components: [
          {
            name: "Export API",
            purpose: "Schedules export jobs",
            files: ["api/routes.py", "api/export.py"],
            criticality: "critical",
            in_attack_surface: true,
            handles_user_input: true,
          },
        ],
        auth_mechanisms: [
          {
            type: "jwt",
            implementation: "api/auth.py",
            weaknesses: "Export route is missing role enforcement.",
          },
        ],
        external_integrations: ["postgres", "redis"],
        trust_boundaries: ["Public API boundary"],
        security_observations: ["Export route is internet reachable."],
        component_hotspots: [
          {
            name: "Export API",
            criticality: "critical",
            finding_count: 3,
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            max_severity: "critical",
            in_attack_surface: true,
          },
        ],
        result_summary: {
          finding_count: 3,
          exploit_chain_count: 1,
        },
        entry_points: [
          {
            file: "api/routes.py",
            function: "export_data",
            method: "POST",
            path: "/api/export",
            type: "http_endpoint",
            auth: "jwt",
          },
        ],
        data_flows: [
          {
            from: "Browser",
            to: "Queue Worker",
            data: "export request payload",
            sensitive: true,
          },
        ],
        attack_surface: [
          "api/routes.py::export_data POST /api/export",
          "POST /api/export | api/routes.py -> export_data | Http Endpoint",
        ],
      }),
      null
    );

    expect(payload.entry_points).toHaveLength(1);
    expect(payload.data_flows).toHaveLength(1);
    expect(payload.attack_surface_points).toContain("api/routes.py::export_data POST /api/export");
    expect(payload.attack_surface_points).toContain(
      "POST /api/export | api/routes.py -> export_data | Http Endpoint"
    );
    expect(payload.attack_surface_points).toHaveLength(2);
    expect(payload.component_hotspots[0].max_severity).toBe("critical");
    expect(payload.components[0].handles_user_input).toBe(true);
    expect(payload.result_summary.exploit_chain_count).toBe(1);
  });
});

describe("ArchitectureAnalysisPanel", () => {
  it("renders concrete architecture sections introduced in phase 5", () => {
    const payload = parseArchitecturePayload(
      JSON.stringify({
        analysis_markdown: "Architecture summary",
        components: [
          {
            name: "Export API",
            purpose: "Schedules export jobs",
            files: ["api/routes.py", "api/export.py"],
            criticality: "critical",
            in_attack_surface: true,
            handles_user_input: true,
          },
        ],
        auth_mechanisms: [
          {
            type: "jwt",
            implementation: "api/auth.py",
            weaknesses: "Missing role enforcement on export route.",
          },
        ],
        external_integrations: ["postgres"],
        trust_boundaries: ["Public API boundary"],
        security_observations: ["Export route is internet reachable."],
        component_hotspots: [
          {
            name: "Export API",
            criticality: "critical",
            finding_count: 3,
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            max_severity: "critical",
            in_attack_surface: true,
          },
        ],
        result_summary: {
          finding_count: 3,
          exploit_chain_count: 1,
          reachable_dependency_count: 2,
        },
        entry_points: [
          {
            file: "api/routes.py",
            function: "export_data",
            method: "POST",
            path: "/api/export",
            type: "http_endpoint",
            auth: "jwt",
            notes: "Queue-backed export initiation",
          },
        ],
        data_flows: [
          {
            from: "Browser",
            to: "Queue Worker",
            data: "export request payload",
            sensitive: true,
          },
        ],
        attack_surface: ["api/routes.py::export_data POST /api/export"],
      }),
      null
    );

    render(<ArchitectureAnalysisPanel data={payload} rawArchitecture={null} />);

    expect(screen.getByText("Concrete Attack Surface")).toBeInTheDocument();
    expect(screen.getByText("Entry Points")).toBeInTheDocument();
    expect(screen.getByText("Data Flows")).toBeInTheDocument();
    expect(screen.getByText("Exploit chains")).toBeInTheDocument();
    expect(screen.getByText("Sensitive data path")).toBeInTheDocument();
    expect(screen.getByText("Missing role enforcement on export route.")).toBeInTheDocument();
    expect(screen.getAllByText("attack surface").length).toBeGreaterThan(0);
    expect(screen.getByText("user input")).toBeInTheDocument();
  });
});

describe("AttackPathPanel", () => {
  it("falls back to finding-derived surface metrics when concrete points are unavailable", () => {
    render(
      <AttackPathPanel
        attackSurfacePoints={[]}
        entryPoints={[]}
        dataFlows={[]}
        fallbackMetrics={{ auth: 3, data: 2, network: 4 }}
      />
    );

    expect(screen.getByText("Attack Paths")).toBeInTheDocument();
    expect(
      screen.getByText("Concrete routes were not mapped for this scan. Showing the finding-derived surface mix instead.")
    ).toBeInTheDocument();
    expect(screen.getByText("network")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
  });
});

describe("ExploitChainsSection", () => {
  it("renders chain anchors, steps, and exploit templates from structured evidence", () => {
    render(<ExploitChainsSection findings={[buildFinding()]} />);

    expect(screen.getByText("Exploit Chains")).toBeInTheDocument();
    expect(screen.getByText("Observed Steps")).toBeInTheDocument();
    expect(screen.getByText("Chain Anchors")).toBeInTheDocument();
    expect(screen.getByText("POST /api/export")).toBeInTheDocument();
    expect(screen.getByText("Authenticate as a standard user.")).toBeInTheDocument();
    expect(screen.getByText("curl -X POST https://target/api/export")).toBeInTheDocument();
  });
});
