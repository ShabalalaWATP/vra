const BASE = "/api";

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(
    path: string,
    body?: unknown,
    opts?: { params?: Record<string, string> }
  ) => {
    let url = path;
    if (opts?.params) {
      const qs = new URLSearchParams(
        Object.entries(opts.params).filter(([, v]) => v !== "")
      ).toString();
      if (qs) url += `?${qs}`;
    }
    return request<T>(url, {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    });
  },
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  delete: (path: string) =>
    request<void>(path, { method: "DELETE" }),
};
