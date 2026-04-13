import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, TestTube, Check, X, Loader2, RefreshCw, ChevronDown, Pencil } from "lucide-react";
import { api } from "@/api/client";
import type { LLMProfile } from "@/types";

interface LLMTestResult {
  success: boolean;
  model_name: string | null;
  response_time_ms: number | null;
  error: string | null;
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"llm" | "scanners" | "general">(
    "llm"
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-text-secondary text-sm mt-1">
          Configure LLM endpoints, scanners, and preferences
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 w-fit">
        {(["llm", "scanners", "general"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab
                ? "bg-bg-card text-text-primary"
                : "text-text-muted hover:text-text-primary"
            }`}
          >
            {tab === "llm"
              ? "LLM Profiles"
              : tab === "scanners"
              ? "Scanners"
              : "General"}
          </button>
        ))}
      </div>

      {activeTab === "llm" && <LLMProfilesTab />}
      {activeTab === "scanners" && <ScannersTab />}
      {activeTab === "general" && <GeneralTab />}
    </div>
  );
}

function LLMProfilesTab() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    base_url: "",
    api_key: "",
    model_name: "",
    cert_path: "",
    timeout_seconds: 120,
    context_window: 131072,
    max_output_tokens: 4096,
    use_max_completion_tokens: false,
    concurrency: 2,
    is_default: false,
  });
  const [testResult, setTestResult] = useState<Record<string, LLMTestResult>>(
    {}
  );

  const { data: profiles } = useQuery<LLMProfile[]>({
    queryKey: ["llm-profiles"],
    queryFn: () => api.get("/llm-profiles"),
  });

  const resetForm = () => {
    setForm({
      name: "",
      base_url: "",
      api_key: "",
      model_name: "",
      cert_path: "",
      timeout_seconds: 120,
      context_window: 131072,
      max_output_tokens: 4096,
      use_max_completion_tokens: false,
      concurrency: 2,
      is_default: false,
    });
    setEditingId(null);
    setShowForm(false);
  };

  const createProfile = useMutation({
    mutationFn: (data: typeof form) => api.post("/llm-profiles", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["llm-profiles"] });
      resetForm();
    },
  });

  const updateProfile = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) => {
      // Only send non-empty fields for update (don't overwrite API key with empty)
      const payload: Record<string, unknown> = { ...data };
      if (!payload.api_key) delete payload.api_key;
      if (!payload.cert_path) delete payload.cert_path;
      return api.patch(`/llm-profiles/${id}`, payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["llm-profiles"] });
      resetForm();
    },
  });

  const deleteProfile = useMutation({
    mutationFn: (id: string) => api.delete(`/llm-profiles/${id}`),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["llm-profiles"] }),
  });

  const setActiveProfile = useMutation({
    mutationFn: (id: string) =>
      api.patch(`/llm-profiles/${id}`, { is_default: true }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["llm-profiles"] }),
  });

  const testConnection = async (id: string) => {
    setTestResult((prev) => ({
      ...prev,
      [id]: { success: false, model_name: null, response_time_ms: null, error: "Testing..." },
    }));
    try {
      const result = await api.post<LLMTestResult>(
        `/llm-profiles/${id}/test`
      );
      setTestResult((prev) => ({ ...prev, [id]: result }));
    } catch (e) {
      setTestResult((prev) => ({
        ...prev,
        [id]: {
          success: false,
          model_name: null,
          response_time_ms: null,
          error: String(e),
        },
      }));
    }
  };

  return (
    <div className="space-y-6">
      {/* Existing Profiles */}
      {profiles?.map((p) => (
        <div
          key={p.id}
          className={`card relative overflow-hidden transition-all ${
            p.is_default
              ? "border-accent-success/30 shadow-lg shadow-accent-success/5"
              : "opacity-75 hover:opacity-100"
          }`}
        >
          {/* Active indicator */}
          {p.is_default && (
            <div className="absolute left-0 top-0 bottom-0 w-1 bg-accent-success" />
          )}

          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <h3 className="font-semibold">{p.name}</h3>
              {p.is_default ? (
                <span className="text-[10px] uppercase tracking-wider text-accent-success bg-accent-success/10 px-2 py-0.5 rounded-full font-medium flex items-center gap-1">
                  <Check className="w-3 h-3" />
                  Active
                </span>
              ) : (
                <button
                  className="text-[10px] uppercase tracking-wider text-text-muted bg-bg-secondary px-2 py-0.5 rounded-full font-medium hover:text-accent-primary hover:bg-accent-primary/10 transition-colors"
                  onClick={() => setActiveProfile.mutate(p.id)}
                >
                  Set Active
                </button>
              )}
            </div>
            <div className="flex gap-2">
              <button
                className="btn-secondary text-sm flex items-center gap-1"
                onClick={() => testConnection(p.id)}
              >
                <TestTube className="w-3 h-3" />
                Test
              </button>
              <button
                className="btn-secondary text-sm flex items-center gap-1"
                onClick={() => {
                  setEditingId(p.id);
                  setForm({
                    name: p.name,
                    base_url: p.base_url,
                    api_key: "",
                    model_name: p.model_name,
                    cert_path: "",
                    timeout_seconds: p.timeout_seconds || 120,
                    context_window: p.context_window || 131072,
                    max_output_tokens: p.max_output_tokens || 4096,
                    use_max_completion_tokens: p.use_max_completion_tokens || false,
                    concurrency: p.concurrency || 2,
                    is_default: p.is_default,
                  });
                  // Scroll to form
                  document.getElementById("profile-form")?.scrollIntoView({ behavior: "smooth" });
                }}
              >
                <Pencil className="w-3 h-3" />
                Edit
              </button>
              <button
                className="btn-danger text-sm flex items-center gap-1"
                onClick={() => {
                  if (confirm("Delete this LLM profile?")) {
                    deleteProfile.mutate(p.id);
                  }
                }}
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2 text-sm">
            <div>
              <span className="text-text-muted">URL:</span>{" "}
              <span className="font-mono text-xs">{p.base_url}</span>
            </div>
            <div>
              <span className="text-text-muted">Model:</span> {p.model_name}
            </div>
            <div>
              <span className="text-text-muted">Context:</span>{" "}
              <span className="font-mono text-accent-primary">
                {p.context_window >= 1000 ? `${Math.round(p.context_window / 1024)}K` : p.context_window}
              </span>
            </div>
            <div>
              <span className="text-text-muted">Max Output:</span>{" "}
              {p.max_output_tokens.toLocaleString()}
            </div>
            <div>
              <span className="text-text-muted">Timeout:</span>{" "}
              {p.timeout_seconds}s
            </div>
            <div>
              <span className="text-text-muted">Token Field:</span>{" "}
              <span className="font-mono text-xs">
                {p.use_max_completion_tokens ? "max_completion_tokens" : "max_tokens"}
              </span>
            </div>
          </div>
          {testResult[p.id] && (
            <div
              className={`mt-3 flex items-center gap-2 text-sm ${
                testResult[p.id].success
                  ? "text-accent-success"
                  : testResult[p.id].error === "Testing..."
                  ? "text-text-muted"
                  : "text-accent-danger"
              }`}
            >
              {testResult[p.id].error === "Testing..." ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : testResult[p.id].success ? (
                <Check className="w-4 h-4" />
              ) : (
                <X className="w-4 h-4" />
              )}
              {testResult[p.id].success
                ? `Connected (${testResult[p.id].response_time_ms}ms)`
                : testResult[p.id].error}
            </div>
          )}
        </div>
      ))}

      {/* Add New */}
      {!showForm && !editingId ? (
        <button
          className="btn-secondary flex items-center gap-2"
          onClick={() => { resetForm(); setShowForm(true); }}
        >
          <Plus className="w-4 h-4" />
          Add LLM Profile
        </button>
      ) : (
        <div id="profile-form" className="card space-y-4">
          <h3 className="font-semibold">{editingId ? "Edit LLM Profile" : "New LLM Profile"}</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">Name</label>
              <input
                className="input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Local LLM"
              />
            </div>
            <div>
              <label className="label">Model Name</label>
              <ModelSelector
                baseUrl={form.base_url}
                apiKey={form.api_key}
                certPath={form.cert_path}
                value={form.model_name}
                onChange={(v) => setForm({ ...form, model_name: v })}
              />
            </div>
            <div className="col-span-2">
              <label className="label">Base URL</label>
              <input
                className="input font-mono"
                value={form.base_url}
                onChange={(e) =>
                  setForm({ ...form, base_url: e.target.value })
                }
                placeholder="http://localhost:11434"
              />
            </div>
            <div>
              <label className="label">API Key (optional)</label>
              <input
                className="input"
                type="password"
                value={form.api_key}
                onChange={(e) =>
                  setForm({ ...form, api_key: e.target.value })
                }
              />
            </div>
            <div>
              <label className="label">Certificate Path (optional)</label>
              <input
                className="input font-mono text-sm"
                value={form.cert_path}
                onChange={(e) =>
                  setForm({ ...form, cert_path: e.target.value })
                }
              />
            </div>
            <div>
              <label className="label">Context Window</label>
              <select
                className="input"
                value={form.context_window}
                onChange={(e) =>
                  setForm({ ...form, context_window: +e.target.value })
                }
              >
                <option value={4096}>4K tokens</option>
                <option value={8192}>8K tokens</option>
                <option value={16384}>16K tokens</option>
                <option value={32768}>32K tokens</option>
                <option value={65536}>64K tokens</option>
                <option value={131072}>128K tokens (recommended)</option>
                <option value={200000}>200K tokens</option>
                <option value={400000}>400K tokens</option>
                <option value={500000}>500K tokens</option>
                <option value={600000}>600K tokens</option>
                <option value={700000}>700K tokens</option>
                <option value={800000}>800K tokens</option>
                <option value={900000}>900K tokens</option>
                <option value={1000000}>1M tokens</option>
              </select>
              <p className="text-xs text-text-muted mt-1">
                Total input + output capacity. Must match the model you are running.
              </p>
            </div>
            <div>
              <label className="label">Max Output Tokens</label>
              <input
                className="input"
                type="number"
                min={256}
                max={32768}
                value={form.max_output_tokens}
                onChange={(e) =>
                  setForm({ ...form, max_output_tokens: +e.target.value })
                }
              />
              <p className="text-xs text-text-muted mt-1">
                Max tokens per AI response. 4096 is typical.
              </p>
            </div>
            <div>
              <label className="label">Timeout (seconds)</label>
              <input
                className="input"
                type="number"
                value={form.timeout_seconds}
                onChange={(e) =>
                  setForm({ ...form, timeout_seconds: +e.target.value })
                }
              />
            </div>
            <div>
              <label className="label">Concurrency</label>
              <input
                className="input"
                type="number"
                min={1}
                max={16}
                value={form.concurrency}
                onChange={(e) =>
                  setForm({ ...form, concurrency: +e.target.value })
                }
              />
            </div>
            <div className="flex items-center gap-2 pt-2">
              <input
                type="checkbox"
                id="use_max_completion"
                checked={form.use_max_completion_tokens}
                onChange={(e) =>
                  setForm({ ...form, use_max_completion_tokens: e.target.checked })
                }
                className="rounded border-border"
              />
              <label htmlFor="use_max_completion" className="text-sm">
                Use <code className="text-xs bg-bg-secondary px-1 rounded">max_completion_tokens</code> instead of <code className="text-xs bg-bg-secondary px-1 rounded">max_tokens</code>
              </label>
            </div>
            <div className="flex items-center gap-2 pt-2">
              <input
                type="checkbox"
                checked={form.is_default}
                onChange={(e) =>
                  setForm({ ...form, is_default: e.target.checked })
                }
              />
              <label className="text-sm">Set as default</label>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              className="btn-primary"
              onClick={() => {
                if (editingId) {
                  updateProfile.mutate({ id: editingId, data: form });
                } else {
                  createProfile.mutate(form);
                }
              }}
            >
              {editingId ? "Update Profile" : "Save Profile"}
            </button>
            <button className="btn-secondary" onClick={resetForm}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ScannersTab() {
  const { data: tools } = useQuery<{
    tools: Record<string, { available: boolean; path: string | null }>;
  }>({
    queryKey: ["tools"],
    queryFn: () => api.get("/health/tools"),
  });

  return (
    <div className="card">
      <h3 className="font-semibold mb-4">Scanner Availability</h3>
      <div className="space-y-3">
        {tools &&
          Object.entries(tools.tools).map(([name, info]) => (
            <div
              key={name}
              className="flex items-center justify-between py-2 border-b border-border/50"
            >
              <div>
                <span className="font-medium capitalize">{name}</span>
                {info.path && (
                  <span className="text-xs font-mono text-text-muted ml-3">
                    {info.path}
                  </span>
                )}
              </div>
              <span
                className={`badge ${
                  info.available ? "badge-low" : "badge-critical"
                }`}
              >
                {info.available ? "Available" : "Not Found"}
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}

function GeneralTab() {
  return (
    <div className="card">
      <h3 className="font-semibold mb-4">General Settings</h3>
      <p className="text-sm text-text-muted">
        Additional configuration options will be available in future versions.
      </p>
    </div>
  );
}

/* ── Model Selector with auto-discovery ────────────────────────── */

interface DiscoveredModel {
  id: string;
  owned_by?: string;
}

function ModelSelector({
  baseUrl,
  apiKey,
  certPath,
  value,
  onChange,
}: {
  baseUrl: string;
  apiKey: string;
  certPath: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const [models, setModels] = useState<DiscoveredModel[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [manualMode, setManualMode] = useState(false);
  const [fetched, setFetched] = useState(false);

  const fetchModels = useCallback(async () => {
    if (!baseUrl) {
      setError("Enter a Base URL first");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await api.post<{ models: DiscoveredModel[]; error?: string }>(
        "/llm-profiles/discover-models",
        { base_url: baseUrl, api_key: apiKey, cert_path: certPath }
      );

      if (result.error) {
        setError(result.error);
        setModels([]);
      } else if (result.models.length === 0) {
        setError("No models found. Use manual entry.");
        setModels([]);
      } else {
        setModels(result.models);
        setFetched(true);
        // Auto-select first model if none selected
        if (!value && result.models.length > 0) {
          onChange(result.models[0].id);
        }
      }
    } catch (e) {
      setError("Failed to connect. Use manual entry.");
      setModels([]);
    } finally {
      setLoading(false);
    }
  }, [baseUrl, apiKey, certPath, value, onChange]);

  if (manualMode) {
    return (
      <div className="space-y-1.5">
        <div className="flex gap-2">
          <input
            className="input flex-1"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="e.g. meta-llama/Llama-3.1-70B-Instruct"
          />
          <button
            type="button"
            onClick={() => setManualMode(false)}
            className="px-2.5 py-2 rounded-lg border border-border bg-bg-secondary text-text-muted hover:text-text-primary hover:bg-bg-hover transition-colors"
            title="Switch to auto-discover"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
        <p className="text-[10px] text-text-muted">
          Manual mode — type the exact model name/ID your endpoint serves.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      <div className="flex gap-2">
        {fetched && models.length > 0 ? (
          /* Dropdown of discovered models */
          <div className="relative flex-1">
            <select
              className="input w-full appearance-none pr-8"
              value={value}
              onChange={(e) => onChange(e.target.value)}
            >
              <option value="">Select a model...</option>
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.id}
                  {m.owned_by ? ` (${m.owned_by})` : ""}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
          </div>
        ) : (
          /* Fetch button */
          <button
            type="button"
            onClick={fetchModels}
            disabled={loading || !baseUrl}
            className={`input flex-1 text-left flex items-center gap-2 ${
              !baseUrl ? "opacity-50 cursor-not-allowed" : "cursor-pointer hover:bg-bg-hover"
            }`}
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-accent-primary" />
                <span className="text-text-muted text-sm">Discovering models...</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4 text-accent-primary" />
                <span className="text-sm">
                  {baseUrl ? "Click to discover available models" : "Enter Base URL first"}
                </span>
              </>
            )}
          </button>
        )}

        {/* Refresh button (when models are loaded) */}
        {fetched && models.length > 0 && (
          <button
            type="button"
            onClick={fetchModels}
            disabled={loading}
            className="px-2.5 py-2 rounded-lg border border-border bg-bg-secondary text-text-muted hover:text-accent-primary hover:bg-bg-hover transition-colors"
            title="Refresh model list"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        )}

        {/* Manual mode toggle */}
        <button
          type="button"
          onClick={() => setManualMode(true)}
          className="px-2.5 py-2 rounded-lg border border-border bg-bg-secondary text-text-muted hover:text-text-primary hover:bg-bg-hover transition-colors"
          title="Switch to manual entry"
        >
          <Pencil className="w-4 h-4" />
        </button>
      </div>

      {/* Status messages */}
      {error && (
        <p className="text-[10px] text-accent-warning flex items-center gap-1">
          <X className="w-3 h-3" />
          {error}
          <button
            type="button"
            onClick={() => setManualMode(true)}
            className="underline ml-1 text-accent-primary"
          >
            Use manual entry
          </button>
        </p>
      )}
      {fetched && models.length > 0 && (
        <p className="text-[10px] text-accent-success">
          {models.length} model{models.length !== 1 ? "s" : ""} available
        </p>
      )}
      {!fetched && !error && (
        <p className="text-[10px] text-text-muted">
          Auto-discovers models via <code className="text-[9px] bg-bg-secondary px-1 rounded">GET /v1/models</code>.
          Click the pencil icon for manual entry if auto-discover doesn't work.
        </p>
      )}
    </div>
  );
}
