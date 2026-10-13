// All calls go to same-origin /api (Vite proxy in dev, Nginx in Docker). No secrets live here.
const BASE = import.meta.env.VITE_API_BASE || "";

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, options);
  } catch {
    throw new Error("Cannot reach the SecureLens API. Is the backend running?");
  }
  const type = res.headers.get("content-type") || "";
  if (!res.ok) {
    const body = type.includes("json") ? await res.json().catch(() => null) : null;
    throw new Error(body?.error?.message || `Request failed (HTTP ${res.status})`);
  }
  return res;
}

export const getHealth = async () => (await request("/api/health")).json();

export async function scanFile(file) {
  const form = new FormData();
  form.append("file", file);
  return (await request("/api/scan", { method: "POST", body: form })).json();
}

export async function analyzeFindings(language, findings) {
  const res = await request("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ language, findings }),
  });
  return res.json();
}

export async function downloadReport(format, scan, analyses) {
  const res = await request(`/api/report?format=${format}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan, analyses }),
  });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `securelens-${scan.filename.replace(/\.[^.]+$/, "")}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
