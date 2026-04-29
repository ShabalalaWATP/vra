import { useState } from "react";

interface LLMFormData {
  name: string;
  base_url: string;
  api_key: string;
  model_name: string;
  cert_path: string;
  timeout_seconds: number;
  max_tokens: number;
  concurrency: number;
  is_default: boolean;
}

interface LLMProfileFormProps {
  initial?: Partial<LLMFormData>;
  onSubmit: (data: LLMFormData) => void;
  onCancel: () => void;
  loading?: boolean;
}

const DEFAULTS: LLMFormData = {
  name: "",
  base_url: "",
  api_key: "",
  model_name: "",
  cert_path: "",
  timeout_seconds: 500,
  max_tokens: 4096,
  concurrency: 2,
  is_default: false,
};

export default function LLMProfileForm({
  initial,
  onSubmit,
  onCancel,
  loading,
}: LLMProfileFormProps) {
  const [form, setForm] = useState<LLMFormData>({ ...DEFAULTS, ...initial });

  const update = (field: keyof LLMFormData, value: string | number | boolean) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="label">Profile Name</label>
          <input
            className="input"
            value={form.name}
            onChange={(e) => update("name", e.target.value)}
            placeholder="Local Ollama"
          />
        </div>
        <div>
          <label className="label">Model Name</label>
          <input
            className="input"
            value={form.model_name}
            onChange={(e) => update("model_name", e.target.value)}
            placeholder="llama3.1:70b"
          />
        </div>
        <div className="col-span-2">
          <label className="label">Base URL</label>
          <input
            className="input font-mono text-sm"
            value={form.base_url}
            onChange={(e) => update("base_url", e.target.value)}
            placeholder="http://localhost:11434/v1"
          />
          <p className="text-xs text-text-muted mt-1">
            OpenAI-compatible endpoint. Must include /v1 if required by your server.
          </p>
        </div>
        <div>
          <label className="label">API Key (optional)</label>
          <input
            className="input"
            type="password"
            value={form.api_key}
            onChange={(e) => update("api_key", e.target.value)}
            placeholder="Leave blank if not required"
          />
        </div>
        <div>
          <label className="label">TLS Certificate Path (optional)</label>
          <input
            className="input font-mono text-sm"
            value={form.cert_path}
            onChange={(e) => update("cert_path", e.target.value)}
            placeholder="/path/to/ca-bundle.crt"
          />
        </div>
        <div>
          <label className="label">Timeout (seconds)</label>
          <input
            className="input"
            type="number"
            min={10}
            max={600}
            value={form.timeout_seconds}
            onChange={(e) => update("timeout_seconds", Number(e.target.value))}
          />
        </div>
        <div>
          <label className="label">Max Tokens</label>
          <input
            className="input"
            type="number"
            min={1}
            max={128000}
            value={form.max_tokens}
            onChange={(e) => update("max_tokens", Number(e.target.value))}
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
            onChange={(e) => update("concurrency", Number(e.target.value))}
          />
          <p className="text-xs text-text-muted mt-1">
            Max parallel requests to the LLM endpoint
          </p>
        </div>
        <div className="flex items-center gap-2 pt-6">
          <input
            type="checkbox"
            id="is_default"
            checked={form.is_default}
            onChange={(e) => update("is_default", e.target.checked)}
            className="rounded border-border"
          />
          <label htmlFor="is_default" className="text-sm">
            Set as default profile
          </label>
        </div>
      </div>

      <div className="flex gap-3 pt-2">
        <button
          className="btn-primary"
          disabled={loading || !form.name || !form.base_url || !form.model_name}
          onClick={() => onSubmit(form)}
        >
          {loading ? "Saving..." : "Save Profile"}
        </button>
        <button className="btn-secondary" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
