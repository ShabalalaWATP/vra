import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Zap,
  Layers,
  Microscope,
  FolderOpen,
  ArrowRight,
  Bot,
  Shield,
  ScanSearch,
  CheckCircle2,
  Search,
  Key,
  Package,
  Upload,
  Smartphone,
  Loader2,
} from "lucide-react";
import { api } from "@/api/client";
import type { Project, LLMProfile, Scan } from "@/types";

const MODES = [
  {
    id: "light" as const,
    icon: Zap,
    label: "Light",
    time: "~15–30 min",
    desc: "Fast triage. Baseline scanners, deterministic scoring, AI reads top files only.",
    color: "text-accent-success",
    borderColor: "border-accent-success/30 bg-accent-success/5",
  },
  {
    id: "regular" as const,
    icon: Layers,
    label: "Regular",
    time: "~30–45 min",
    desc: "Full pipeline. Broader AI reads, multi-pass investigation, false positive reduction.",
    color: "text-accent-primary",
    borderColor: "border-accent-primary/30 bg-accent-primary/5",
  },
  {
    id: "heavy" as const,
    icon: Microscope,
    label: "Heavy",
    time: "~1–2 hours",
    desc: "Deep research. Widest file exploration, multiple verification passes, strongest evidence.",
    color: "text-accent-purple",
    borderColor: "border-accent-purple/30 bg-accent-purple/5",
  },
];

const SCANNERS = [
  { key: "semgrep", name: "Semgrep", icon: Shield, desc: "Multi-language SAST" },
  { key: "bandit", name: "Bandit", icon: Search, desc: "Python security" },
  { key: "eslint", name: "ESLint", icon: Search, desc: "JS/TS analysis" },
  { key: "codeql", name: "CodeQL", icon: Search, desc: "Deep semantic analysis" },
  { key: "secrets", name: "Secrets", icon: Key, desc: "Credential detection" },
  { key: "dependencies", name: "Dependencies", icon: Package, desc: "Advisory matching" },
];

export default function NewScanPage() {
  const navigate = useNavigate();
  const [projectId, setProjectId] = useState("");
  const [newProjectName, setNewProjectName] = useState("");
  const [repoPath, setRepoPath] = useState("");
  const [mode, setMode] = useState<"light" | "regular" | "heavy">("regular");
  const [llmProfileId, setLlmProfileId] = useState("");
  const [targetTab, setTargetTab] = useState<"path" | "apk">("path");
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState("");
  const [apkUploading, setApkUploading] = useState(false);
  const [apkError, setApkError] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [enabledScanners, setEnabledScanners] = useState<Record<string, boolean>>({
    semgrep: true,
    bandit: true,
    eslint: true,
    codeql: true,
    secrets: true,
    dependencies: true,
  });

  const { data: projects } = useQuery<Project[]>({
    queryKey: ["projects"],
    queryFn: () => api.get("/projects"),
  });

  const { data: profiles } = useQuery<LLMProfile[]>({
    queryKey: ["llm-profiles"],
    queryFn: () => api.get("/llm-profiles"),
  });

  // Auto-select the active/default LLM profile
  useEffect(() => {
    if (profiles?.length && !llmProfileId) {
      const active = profiles.find((p) => p.is_default);
      if (active) setLlmProfileId(active.id);
    }
  }, [profiles]);

  const startScan = useMutation({
    mutationFn: async () => {
      let pid = projectId;

      // APK upload path
      if (targetTab === "apk" && apkFile && !pid) {
        setApkUploading(true);
        setApkError("");
        try {
          const formData = new FormData();
          formData.append("file", apkFile);
          const resp = await fetch("/api/projects/upload-apk", {
            method: "POST",
            body: formData,
          });
          if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || "APK upload failed");
          }
          const project: Project = await resp.json();
          pid = project.id;
        } catch (e) {
          setApkError((e as Error).message);
          throw e;
        } finally {
          setApkUploading(false);
        }
      }

      // Normal path — create project from repo path
      if (!pid && newProjectName && repoPath) {
        const project = await api.post<Project>("/projects", {
          name: newProjectName,
          repo_path: repoPath,
        });
        pid = project.id;
      }

      if (!pid) throw new Error("No project selected");

      const scan = await api.post<Scan>("/scans", {
        project_id: pid,
        llm_profile_id: llmProfileId || undefined,
        mode,
        scanners: enabledScanners,
      });

      await api.post(`/scans/${scan.id}/start`);
      return scan;
    },
    onSuccess: (scan) => {
      navigate(`/scan/${scan.id}/progress`);
    },
  });

  const canStart =
    projectId ||
    (targetTab === "path" && newProjectName && repoPath) ||
    (targetTab === "apk" && apkFile);

  return (
    <div className="max-w-5xl space-y-8">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-accent-primary/10 flex items-center justify-center">
          <ScanSearch className="w-6 h-6 text-accent-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">New Scan</h1>
          <p className="text-text-secondary text-sm mt-0.5">
            Configure your vulnerability research scan
          </p>
        </div>
      </div>

      {/* ── Step 1: Target ────────────────────────────────────── */}
      <div className="card-glow border-gradient space-y-5">
        <div className="flex items-center gap-3">
          <span className="w-7 h-7 rounded-full bg-accent-primary/20 text-accent-primary text-xs font-bold flex items-center justify-center">
            1
          </span>
          <h2 className="font-semibold text-lg">Target</h2>
        </div>

        {/* Existing project selector */}
        {projects?.length ? (
          <div>
            <label className="label">Existing project</label>
            <select
              className="input"
              value={projectId}
              onChange={(e) => {
                setProjectId(e.target.value);
                if (e.target.value) {
                  const p = projects.find((p) => p.id === e.target.value);
                  if (p) setRepoPath(p.repo_path);
                }
              }}
            >
              <option value="">New project</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}{p.source_type !== "codebase" ? ` (${p.source_type.toUpperCase()})` : ""} — {p.repo_path}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        {uploadSuccess && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-accent-success/10 border border-accent-success/20">
            <CheckCircle2 className="w-4 h-4 text-accent-success shrink-0" />
            <span className="text-sm text-accent-success font-medium">{uploadSuccess}</span>
          </div>
        )}

        {/* New project — tab selector */}
        {!projectId && (
          <>
            <div className="flex gap-1 p-1 rounded-lg bg-bg-secondary/50 w-fit">
              <button
                className={`px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                  targetTab === "path"
                    ? "bg-accent-primary/15 text-accent-primary"
                    : "text-text-muted hover:text-text-secondary"
                }`}
                onClick={() => setTargetTab("path")}
              >
                <FolderOpen className="w-4 h-4" />
                Source Code Path
              </button>
              <button
                className={`px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                  targetTab === "apk"
                    ? "bg-accent-purple/15 text-accent-purple"
                    : "text-text-muted hover:text-text-secondary"
                }`}
                onClick={() => setTargetTab("apk")}
              >
                <Smartphone className="w-4 h-4" />
                Upload APK
              </button>
            </div>

            {targetTab === "path" && (
              <div className="space-y-4">
                <div className="grid grid-cols-5 gap-4">
                  <div className="col-span-2">
                    <label className="label">Project name</label>
                    <input
                      className="input"
                      placeholder="My Application"
                      value={newProjectName}
                      onChange={(e) => setNewProjectName(e.target.value)}
                    />
                  </div>
                  <div className="col-span-3">
                    <label className="label">Source code path or upload</label>
                    <div className="flex gap-2">
                      <div className="relative flex-1">
                        <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                        <input
                          className="input pl-10 font-mono text-sm"
                          placeholder="C:\repos\my-project  or  /home/user/repos/my-project"
                          value={repoPath}
                          onChange={(e) => setRepoPath(e.target.value)}
                        />
                      </div>
                      <label className={`flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-bg-secondary text-text-secondary text-sm font-medium transition-colors shrink-0 ${uploading ? "opacity-60 pointer-events-none" : "cursor-pointer hover:bg-bg-hover hover:text-text-primary"}`}>
                        {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                        {uploading ? "Uploading..." : "Browse Folder"}
                        <input
                          type="file"
                          className="hidden"
                          {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
                          onChange={async (e) => {
                            const files = e.target.files;
                            if (!files || files.length === 0) return;
                            setUploading(true);
                            try {
                              const formData = new FormData();
                              formData.append("name", newProjectName || files[0].webkitRelativePath?.split("/")[0] || "Upload");
                              for (let i = 0; i < files.length; i++) {
                                formData.append("files", files[i], files[i].webkitRelativePath || files[i].name);
                              }
                              const result = await fetch("/api/projects/upload-folder", {
                                method: "POST",
                                body: formData,
                              });
                              if (!result.ok) throw new Error(await result.text());
                              const project = await result.json();
                              setProjectId(project.id);
                              setRepoPath(project.repo_path);
                              if (!newProjectName) setNewProjectName(project.name);
                              setUploadSuccess(`Uploaded ${files.length} files successfully`);
                            } catch (err) {
                              alert("Upload failed: " + String(err));
                            } finally {
                              setUploading(false);
                            }
                          }}
                        />
                      </label>
                    </div>
                    <p className="text-xs text-text-muted mt-1.5">
                      Enter a path on this machine, or click Browse Folder to upload source files
                    </p>
                  </div>
                </div>
              </div>
            )}

            {targetTab === "apk" && (
              <div className="space-y-4">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".apk,.aab,.dex,.jar"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) {
                      setApkFile(f);
                      setApkError("");
                    }
                  }}
                />

                <button
                  onClick={() => fileInputRef.current?.click()}
                  className={`w-full py-8 rounded-xl border-2 border-dashed transition-all flex flex-col items-center gap-3 ${
                    apkFile
                      ? "border-accent-purple/40 bg-accent-purple/5"
                      : "border-border hover:border-accent-purple/30 hover:bg-accent-purple/5"
                  }`}
                >
                  {apkFile ? (
                    <>
                      <Smartphone className="w-10 h-10 text-accent-purple" />
                      <div className="text-center">
                        <p className="font-semibold text-accent-purple">{apkFile.name}</p>
                        <p className="text-xs text-text-muted mt-1">
                          {(apkFile.size / 1024 / 1024).toFixed(1)} MB — click to change
                        </p>
                      </div>
                    </>
                  ) : (
                    <>
                      <Upload className="w-10 h-10 text-text-muted" />
                      <div className="text-center">
                        <p className="text-sm font-medium text-text-secondary">
                          Click to select APK file
                        </p>
                        <p className="text-xs text-text-muted mt-1">
                          Supports .apk, .aab, .dex, .jar
                        </p>
                      </div>
                    </>
                  )}
                </button>

                {apkFile && (
                  <div className="flex items-start gap-3 p-4 rounded-lg bg-accent-purple/5 border border-accent-purple/15">
                    <Smartphone className="w-5 h-5 text-accent-purple mt-0.5 shrink-0" />
                    <div className="text-xs text-text-secondary leading-relaxed">
                      The APK will be decompiled to Java source using <strong>jadx</strong> before
                      scanning. The decompiled source undergoes the full scan pipeline including
                      Semgrep (Java/Kotlin rules), CodeQL, secrets scanning, and AI investigation.
                    </div>
                  </div>
                )}

                {apkUploading && (
                  <div className="flex items-center gap-3 p-4 rounded-lg bg-bg-secondary/50">
                    <Loader2 className="w-5 h-5 text-accent-purple animate-spin" />
                    <span className="text-sm text-text-secondary">Uploading and decompiling APK...</span>
                  </div>
                )}

                {apkError && (
                  <p className="text-sm text-accent-danger">{apkError}</p>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* ── Step 2: Scan Mode ─────────────────────────────────── */}
      <div className="card-glow border-gradient space-y-5">
        <div className="flex items-center gap-3">
          <span className="w-7 h-7 rounded-full bg-accent-primary/20 text-accent-primary text-xs font-bold flex items-center justify-center">
            2
          </span>
          <h2 className="font-semibold text-lg">Scan Depth</h2>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {MODES.map((m) => {
            const selected = mode === m.id;
            return (
              <button
                key={m.id}
                onClick={() => setMode(m.id)}
                className={`relative flex flex-col items-start gap-3 p-5 rounded-xl border transition-all duration-200 text-left ${
                  selected
                    ? `${m.borderColor} glow-ring`
                    : "border-border hover:border-border-light hover:bg-bg-hover/20"
                }`}
              >
                {m.id === "regular" && !selected && (
                  <span className="absolute top-3 right-3 text-[9px] uppercase tracking-wider text-accent-primary bg-accent-primary/10 px-2 py-0.5 rounded-full">
                    Recommended
                  </span>
                )}
                <div className="flex items-center gap-3">
                  <m.icon
                    className={`w-6 h-6 ${selected ? m.color : "text-text-muted"}`}
                  />
                  <div>
                    <p className={`font-semibold ${selected ? m.color : ""}`}>
                      {m.label}
                    </p>
                    <p className="text-[11px] text-text-muted">{m.time}</p>
                  </div>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  {m.desc}
                </p>
                {selected && (
                  <CheckCircle2 className={`absolute bottom-3 right-3 w-5 h-5 ${m.color}`} />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Step 3: AI + Scanners ─────────────────────────────── */}
      <div className="grid grid-cols-2 gap-6">
        {/* LLM Profile */}
        <div className="card-glow border-gradient space-y-4">
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-full bg-accent-primary/20 text-accent-primary text-xs font-bold flex items-center justify-center">
              3
            </span>
            <h2 className="font-semibold text-lg">AI Model</h2>
          </div>

          <div className="flex items-start gap-3 p-4 rounded-lg bg-bg-secondary/50">
            <Bot className="w-5 h-5 text-accent-purple mt-0.5 shrink-0" />
            <div className="text-xs text-text-secondary leading-relaxed">
              The AI model inspects source files directly, builds application
              understanding, investigates suspicious code paths, and verifies
              findings. Without an AI model, only scanner results are produced.
            </div>
          </div>

          <select
            className="input"
            value={llmProfileId}
            onChange={(e) => setLlmProfileId(e.target.value)}
          >
            <option value="">No AI — scanners only</option>
            {profiles?.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.model_name})
              </option>
            ))}
          </select>

          {!profiles?.length && (
            <p className="text-xs text-text-muted">
              No LLM profiles configured.{" "}
              <a
                href="/settings"
                className="text-accent-primary hover:underline"
              >
                Configure in Settings
              </a>
            </p>
          )}
        </div>

        {/* Scanners */}
        <div className="card-glow border-gradient space-y-4">
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-full bg-accent-primary/20 text-accent-primary text-xs font-bold flex items-center justify-center">
              4
            </span>
            <h2 className="font-semibold text-lg">Scanners</h2>
          </div>

          <div className="space-y-2">
            {SCANNERS.map((s) => (
              <label
                key={s.key}
                className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                  enabledScanners[s.key]
                    ? "bg-accent-primary/5 border border-accent-primary/15"
                    : "bg-bg-secondary/30 border border-transparent hover:bg-bg-hover/20"
                }`}
              >
                <input
                  type="checkbox"
                  checked={enabledScanners[s.key]}
                  onChange={(e) =>
                    setEnabledScanners((prev) => ({
                      ...prev,
                      [s.key]: e.target.checked,
                    }))
                  }
                  className="rounded border-border bg-bg-secondary accent-accent-primary"
                />
                <s.icon
                  className={`w-4 h-4 ${
                    enabledScanners[s.key]
                      ? "text-accent-primary"
                      : "text-text-muted"
                  }`}
                />
                <div className="flex-1">
                  <span className="text-sm font-medium">{s.name}</span>
                  <span className="text-xs text-text-muted ml-2">
                    {s.desc}
                  </span>
                </div>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* ── Launch ────────────────────────────────────────────── */}
      <div className="flex items-center gap-4">
        <button
          className="btn-primary flex items-center gap-3 text-lg px-8 py-3.5 shadow-lg shadow-accent-primary/20"
          disabled={startScan.isPending || !canStart}
          onClick={() => startScan.mutate()}
        >
          {startScan.isPending ? (
            <>
              <div className="w-5 h-5 border-2 border-bg-primary/30 border-t-bg-primary rounded-full animate-spin" />
              Launching...
            </>
          ) : (
            <>
              <ScanSearch className="w-5 h-5" />
              Start Scan
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>

        {startScan.isError && (
          <p className="text-accent-danger text-sm">
            {(startScan.error as Error).message}
          </p>
        )}

        {!canStart && (
          <p className="text-text-muted text-sm">
            Select a project or enter a name and source path to continue
          </p>
        )}
      </div>
    </div>
  );
}
