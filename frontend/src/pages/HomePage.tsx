import { Link } from "react-router-dom";
import { useEffect, useRef } from "react";
import {
  ArrowRight,
  Shield,
  Brain,
  Radar,
  FileText,
  Settings,
  Zap,
  Search,
  Bug,
  ShieldCheck,
  Package,
  Lock,
} from "lucide-react";

export default function HomePage() {
  return (
    <div className="relative -mx-6 -mt-4">
      {/* Scan line animation */}
      <ScanLineOverlay />

      {/* Keyframe animations for logo */}
      <style>{`
        @keyframes logo-float {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-12px); }
        }
        @keyframes radar-pulse {
          0%, 100% { opacity: 0.4; transform: scale(1); }
          50% { opacity: 0.7; transform: scale(1.02); }
        }
        @keyframes radar-ping {
          0% { transform: scale(1); opacity: 0.3; }
          100% { transform: scale(1.5); opacity: 0; }
        }
        @keyframes sweep {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes hex-rotate {
          from { transform: rotate(0deg); }
          to { transform: rotate(-360deg); }
        }
      `}</style>

      {/* ── Hero ────────────────────────────────────────────── */}
      <section className="relative overflow-hidden px-8 pt-16 pb-28">
        {/* Background effects */}
        <div className="absolute inset-0 bg-grid opacity-20" />
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] opacity-[0.04]"
          style={{ background: "radial-gradient(circle, #00d4ff 0%, transparent 60%)" }}
        />
        <div
          className="absolute top-0 right-0 w-[500px] h-[500px] opacity-[0.03]"
          style={{ background: "radial-gradient(circle, #64ffda 0%, transparent 60%)" }}
        />

        <div className="relative max-w-4xl mx-auto text-center">
          {/* Logo with radar rings */}
          <div className="relative inline-block">
            {/* Outer glow */}
            <div
              className="absolute -inset-24 rounded-full blur-[100px] opacity-[0.1]"
              style={{ background: "radial-gradient(circle, #00d4ff 0%, #8b5cf6 40%, transparent 70%)" }}
            />
            {/* Inner glow pulse */}
            <div
              className="absolute -inset-8 rounded-full blur-[40px] opacity-[0.12]"
              style={{
                background: "radial-gradient(circle, rgba(0,212,255,0.4), transparent 60%)",
                animation: "radar-pulse 4s ease-in-out infinite",
              }}
            />

            {/* Green radar circle + sweep — subtle */}
            <div className="absolute inset-0 flex items-center justify-center" style={{ width: 420, height: 420, left: "50%", top: "50%", transform: "translate(-50%, -50%)" }}>
              {/* Single radar circle */}
              <div
                className="absolute w-[420px] h-[420px] rounded-full"
                style={{ border: "1px solid rgba(57,255,20,0.08)" }}
              />

              {/* Rotating green radar sweep — subtle */}
              <div
                className="absolute w-[420px] h-[420px] rounded-full overflow-hidden"
                style={{ animation: "sweep 5s linear infinite" }}
              >
                <div
                  className="absolute inset-0 rounded-full"
                  style={{
                    background: "conic-gradient(from 0deg, rgba(57,255,20,0.10) 0deg, rgba(57,255,20,0.03) 25deg, transparent 50deg, transparent 360deg)",
                  }}
                />
              </div>

              {/* Faint crosshairs */}
              <div className="absolute w-[420px] h-px" style={{ background: "linear-gradient(90deg, transparent 15%, rgba(57,255,20,0.03) 35%, rgba(57,255,20,0.03) 65%, transparent 85%)" }} />
              <div className="absolute h-[420px] w-px" style={{ background: "linear-gradient(180deg, transparent 15%, rgba(57,255,20,0.03) 35%, rgba(57,255,20,0.03) 65%, transparent 85%)" }} />

              {/* Center dot */}
              <div className="absolute w-1.5 h-1.5 rounded-full bg-[#39ff14]/10" />
            </div>

            {/* Logo image - floating, no box, nudged down to center in circle */}
            <img
              src="/logo.png"
              alt="VRAgent"
              className="relative w-80 h-80 object-contain z-10 drop-shadow-2xl mt-12"
              style={{
                animation: "logo-float 4s ease-in-out infinite",
                filter: "drop-shadow(0 0 30px rgba(0,212,255,0.15)) drop-shadow(0 10px 30px rgba(0,0,0,0.3))",
              }}
            />
          </div>

          {/* Title */}
          <div className="space-y-5 pt-16">
            <h1 className="text-7xl font-black tracking-tight">
              <span className="text-gradient">VRAgent</span>
            </h1>
            <p className="text-3xl text-text-secondary font-medium">
              AI-Assisted Static Vulnerability Research Platform
            </p>
            <p className="text-base text-text-muted max-w-2xl mx-auto leading-relaxed">
              Combine deterministic static analysis with multi-pass AI investigation
              to produce analyst-quality vulnerability reports. Fully offline.
              Air-gapped. No compromises.
            </p>
          </div>

          {/* CTA Buttons */}
          <div className="flex items-center justify-center gap-5 pt-10">
            <Link
              to="/scan/new"
              className="group flex items-center gap-3 px-10 py-5 rounded-xl bg-accent-primary text-bg-primary font-semibold text-lg hover:bg-accent-primary/90 transition-all shadow-lg shadow-accent-primary/20 hover:shadow-accent-primary/30"
            >
              <Zap className="w-5 h-5" />
              Begin Scan
              <ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <Link
              to="/settings"
              className="flex items-center gap-3 px-10 py-5 rounded-xl border border-border bg-bg-card text-text-primary font-medium text-lg hover:bg-bg-hover transition-all"
            >
              <Settings className="w-5 h-5 text-text-muted" />
              Configure LLM
            </Link>
          </div>

          {/* Tools strip */}
          <div className="flex items-center justify-center gap-3 pt-10 flex-wrap">
            <Badge icon={<Shield className="w-3 h-3" />} label="Semgrep" color="primary" />
            <Badge icon={<Shield className="w-3 h-3" />} label="CodeQL" color="secondary" />
            <Badge icon={<Shield className="w-3 h-3" />} label="ESLint" color="primary" />
            <Badge icon={<Shield className="w-3 h-3" />} label="Bandit" color="secondary" />
            <Badge icon={<Shield className="w-3 h-3" />} label="jadx" color="primary" />
            <Badge icon={<Shield className="w-3 h-3" />} label="Tree-sitter" color="secondary" />
            <Badge icon={<Shield className="w-3 h-3" />} label="OSV Database" color="primary" />
          </div>
        </div>
      </section>

      {/* ── How It Works ─────────────────────────────────────── */}
      <section className="px-8 pt-24 pb-16 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <SectionHeader
            label="how it works"
            title="Intelligent Security Analysis in 3 Steps"
          />

          <div className="grid grid-cols-3 gap-6 mt-10">
            <StepCard
              number="01"
              icon={<Settings className="w-6 h-6" />}
              title="Configure Your LLM"
              description="Go to Settings and add your local OpenAI-compatible endpoint. Set the base URL, API key, model name, and context window size. VRAgent works with vLLM, Ollama, llama.cpp, or any compatible server."
              link="/settings"
              linkLabel="Open Settings"
              color="#00d4ff"
            />
            <StepCard
              number="02"
              icon={<Search className="w-6 h-6" />}
              title="Upload & Configure"
              description="Select a codebase folder or upload an APK file. Choose your scan mode (Light for quick triage, Regular for thorough analysis, Heavy for deep investigation). Toggle which scanners to enable."
              link="/scan/new"
              linkLabel="New Scan"
              color="#64ffda"
            />
            <StepCard
              number="03"
              icon={<FileText className="w-6 h-6" />}
              title="Review the Report"
              description="VRAgent scans, investigates, verifies, and generates a professional report with risk scores, OWASP mapping, architecture diagrams, SBOM, and detailed finding narratives. Export to PDF or DOCX."
              link="/history"
              linkLabel="View History"
              color="#8b5cf6"
            />
          </div>
        </div>
      </section>

      {/* ── Pipeline Overview ────────────────────────────────── */}
      <section className="px-8 py-16 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <SectionHeader
            label="scan pipeline"
            title="7-Stage Agentic Analysis"
          />

          <div className="grid grid-cols-7 gap-2 mt-10">
            {[
              { icon: Search, label: "Triage", desc: "Fingerprint, scan, score", color: "#00d4ff" },
              { icon: Brain, label: "Understand", desc: "Architecture model", color: "#64ffda" },
              { icon: Package, label: "Deps", desc: "CVE matching", color: "#eab308" },
              { icon: Bug, label: "Investigate", desc: "Multi-pass hunt", color: "#f97316" },
              { icon: Radar, label: "Targeted", desc: "Follow-up scans", color: "#06b6d4" },
              { icon: ShieldCheck, label: "Verify", desc: "Challenge & PoC", color: "#8b5cf6" },
              { icon: FileText, label: "Report", desc: "Narratives & export", color: "#22c55e" },
            ].map((stage, i) => (
              <div key={stage.label} className="relative group">
                <div className="rounded-xl border border-border/50 bg-bg-card/50 p-3 text-center hover:border-border hover:bg-bg-card transition-all">
                  <div
                    className="w-10 h-10 rounded-lg mx-auto mb-2 flex items-center justify-center"
                    style={{ background: `${stage.color}12` }}
                  >
                    <stage.icon className="w-5 h-5" style={{ color: stage.color }} />
                  </div>
                  <p className="text-xs font-semibold" style={{ color: stage.color }}>{stage.label}</p>
                  <p className="text-[9px] text-text-muted mt-0.5">{stage.desc}</p>
                </div>
                {/* Connector arrow */}
                {i < 6 && (
                  <div className="absolute top-1/2 -right-2 w-2 h-px bg-border/50 z-10" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Key Capabilities ─────────────────────────────────── */}
      <section className="px-8 py-16 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <SectionHeader
            label="capabilities"
            title="What VRAgent Does"
          />

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-10">
            <CapCard icon={<Shield />} title="6 Scanners" desc="Semgrep, Bandit, ESLint, CodeQL, secrets, dep audit" color="#00d4ff" />
            <CapCard icon={<Brain />} title="7 AI Agents" desc="Triage, architecture, dependency, investigation, rules, verification, reporting" color="#64ffda" />
            <CapCard icon={<Bug />} title="20 AI Tools" desc="File reading, call graph, taint tracking, import resolution, targeted scans" color="#f97316" />
            <CapCard icon={<Radar />} title="257K+ CVEs" desc="Offline advisory database covering npm, PyPI, Maven, Go, Cargo, NuGet, and more" color="#eab308" />
            <CapCard icon={<FileText />} title="Rich Reports" desc="Risk scores, OWASP mapping, diagrams, charts, SBOM, component scorecard" color="#8b5cf6" />
            <CapCard icon={<Lock />} title="Air-Gapped" desc="No internet at runtime. All rules, icons, advisories, and fonts bundled locally" color="#22c55e" />
            <CapCard icon={<Zap />} title="APK Scanning" desc="Decompile Android APKs with jadx and scan with Android-specific AI tools" color="#ec4899" />
            <CapCard icon={<Search />} title="Doc Intelligence" desc="Reads READMEs and docs to inform the AI's investigation strategy" color="#06b6d4" />
          </div>
        </div>
      </section>

      {/* ── Getting Started Callout ──────────────────────────── */}
      <section className="px-8 py-16 border-t border-border/30">
        <div className="max-w-3xl mx-auto">
          <div className="relative rounded-2xl border border-accent-primary/20 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-accent-primary/5 via-transparent to-accent-secondary/5" />
            <div className="relative p-8 text-center space-y-4">
              <div className="w-12 h-12 rounded-xl bg-accent-primary/10 flex items-center justify-center mx-auto">
                <Settings className="w-6 h-6 text-accent-primary" />
              </div>
              <h3 className="text-xl font-bold">First Time Setup</h3>
              <p className="text-sm text-text-secondary max-w-lg mx-auto leading-relaxed">
                Before your first scan, configure your local LLM endpoint in <strong>Settings</strong>.
                VRAgent needs a local OpenAI-compatible API (e.g., vLLM, Ollama, llama.cpp server).
                Set the base URL, API key, model name, and select your context window size (128K, 200K, or 400K tokens).
                Click "Test Connection" to verify.
              </p>
              <div className="flex items-center justify-center gap-4 pt-2">
                <Link
                  to="/settings"
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-accent-primary/10 text-accent-primary font-medium text-sm hover:bg-accent-primary/20 transition-all"
                >
                  <Settings className="w-4 h-4" />
                  Configure LLM Provider
                </Link>
                <Link
                  to="/scan/new"
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-border text-text-primary font-medium text-sm hover:bg-bg-hover transition-all"
                >
                  <Zap className="w-4 h-4 text-accent-warning" />
                  Start Scanning
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer spacer */}
      <div className="h-8" />
    </div>
  );
}

/* ── Sub-components ────────────────────────────────────────────── */

function Badge({ icon, label, color }: { icon: React.ReactNode; label: string; color: string }) {
  const cls: Record<string, string> = {
    success: "text-accent-success bg-accent-success/10 border-accent-success/20",
    primary: "text-accent-primary bg-accent-primary/10 border-accent-primary/20",
    secondary: "text-accent-secondary bg-accent-secondary/10 border-accent-secondary/20",
  };
  return (
    <span className={`inline-flex items-center gap-2 px-4 py-1.5 rounded-full border text-xs font-medium uppercase tracking-wider ${cls[color]}`}>
      {icon}
      {label}
    </span>
  );
}

function SectionHeader({ label, title }: { label: string; title: string }) {
  return (
    <div className="text-center">
      <p className="text-[10px] text-accent-primary uppercase tracking-[0.2em] font-medium mb-2">{label}</p>
      <h2 className="text-2xl font-bold">{title}</h2>
    </div>
  );
}

function StepCard({
  number, icon, title, description, link, linkLabel, color,
}: {
  number: string; icon: React.ReactNode; title: string; description: string;
  link: string; linkLabel: string; color: string;
}) {
  return (
    <div className="group rounded-2xl border border-border/50 bg-bg-card/30 p-6 hover:border-border hover:bg-bg-card transition-all relative overflow-hidden">
      {/* Number watermark */}
      <span
        className="absolute top-3 right-4 text-5xl font-black opacity-[0.04] select-none"
        style={{ color }}
      >
        {number}
      </span>

      <div className="relative space-y-4">
        <div
          className="w-12 h-12 rounded-xl flex items-center justify-center"
          style={{ background: `${color}12`, color }}
        >
          {icon}
        </div>
        <h3 className="text-base font-semibold">{title}</h3>
        <p className="text-xs text-text-secondary leading-relaxed">{description}</p>
        <Link
          to={link}
          className="inline-flex items-center gap-1.5 text-xs font-medium transition-colors group-hover:text-accent-primary"
          style={{ color: `${color}cc` }}
        >
          {linkLabel}
          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" />
        </Link>
      </div>
    </div>
  );
}

function CapCard({ icon, title, desc, color }: { icon: React.ReactNode; title: string; desc: string; color: string }) {
  return (
    <div className="rounded-xl border border-border/30 bg-bg-card/20 p-4 hover:border-border/60 hover:bg-bg-card/40 transition-all">
      <div
        className="w-9 h-9 rounded-lg flex items-center justify-center mb-3"
        style={{ background: `${color}10`, color }}
      >
        <span className="w-4 h-4">{icon}</span>
      </div>
      <h4 className="text-sm font-semibold mb-1">{title}</h4>
      <p className="text-[11px] text-text-muted leading-relaxed">{desc}</p>
    </div>
  );
}

/* ── Scan line overlay ─────────────────────────────────────────── */

function ScanLineOverlay() {
  const lineRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let animationId: number;
    let position = 0;

    const animate = () => {
      if (lineRef.current) {
        const parent = lineRef.current.parentElement;
        if (parent) {
          const height = parent.scrollHeight;
          position += 0.3; // Slow speed
          if (position > height) position = 0;
          lineRef.current.style.top = `${position}px`;
        }
      }
      animationId = requestAnimationFrame(animate);
    };

    animationId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationId);
  }, []);

  return (
    <div
      ref={lineRef}
      className="fixed left-0 h-px pointer-events-none z-30"
      style={{
        width: "100vw",
        background: "linear-gradient(90deg, transparent 2%, rgba(34, 197, 94, 0.12) 10%, rgba(34, 197, 94, 0.2) 50%, rgba(34, 197, 94, 0.12) 90%, transparent 98%)",
        boxShadow: "0 0 8px rgba(34, 197, 94, 0.06)",
      }}
    />
  );
}
