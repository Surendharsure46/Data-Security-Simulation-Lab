// Thin fetch wrapper. The bearer token lives in memory and (best effort) sessionStorage;
// it is never placed in URLs. All errors surface the server's safe message.

export class ApiError extends Error {
  status: number;
  details?: { field: string; message: string }[];
  constructor(status: number, message: string, details?: { field: string; message: string }[]) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const TOKEN_KEY = "threatready.token";
let token: string | null = null;
try {
  token = sessionStorage.getItem(TOKEN_KEY);
} catch {
  token = null;
}

export function setToken(t: string | null) {
  token = t;
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: keep in memory only */
  }
}

export function hasToken() {
  return token !== null;
}

let onUnauthorized: () => void = () => undefined;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function request<T>(method: string, path: string, body?: unknown, raw = false): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "Cannot reach the Threatready server. Is the backend running on port 8000?");
  }
  if (res.status === 401 && !path.startsWith("/api/auth/login")) {
    setToken(null);
    onUnauthorized();
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    let details;
    try {
      const j = await res.json();
      msg = typeof j.detail === "string" ? j.detail : msg;
      details = j.errors;
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, msg, details);
  }
  if (raw) return (await res.text()) as T;
  const ct = res.headers.get("content-type") ?? "";
  return (ct.includes("application/json") ? await res.json() : await res.text()) as T;
}

export const api = {
  get: <T = any>(p: string) => request<T>("GET", p),
  post: <T = any>(p: string, b: unknown = {}) => request<T>("POST", p, b),
  put: <T = any>(p: string, b: unknown) => request<T>("PUT", p, b),
  patch: <T = any>(p: string, b: unknown) => request<T>("PATCH", p, b),
  del: <T = any>(p: string) => request<T>("DELETE", p),
  text: (p: string) => request<string>("GET", p, undefined, true),
};

export async function download(path: string, filename: string) {
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(path, { headers });
  if (!res.ok) throw new ApiError(res.status, "Download failed");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.details?.length) return `${e.message}: ${e.details.map((d) => `${d.field || "input"} — ${d.message}`).join("; ")}`;
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}
