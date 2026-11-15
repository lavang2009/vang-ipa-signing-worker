function normalizeOrigin(value) {
  try {
    const raw = String(value || "").trim();
    if (!raw) return "";
    const parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol)) return "";
    if (parsed.username || parsed.password || parsed.hostname.includes("*")) return "";
    // An origin has no path, query, or fragment. A single trailing slash is
    // accepted because URL represents the root path that way.
    if (parsed.pathname !== "/" || parsed.search || parsed.hash) return "";
    return parsed.origin;
  } catch {
    return "";
  }
}

export function parseAllowedOrigins(value) {
  return new Set(
    String(value || "")
      .split(/[;,\n]/)
      .map(normalizeOrigin)
      .filter(Boolean),
  );
}

function addVaryOrigin(res) {
  const current = typeof res.getHeader === "function" ? res.getHeader("Vary") : undefined;
  const values = String(current || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === "origin")) values.push("Origin");
  res.setHeader("Vary", values.join(", "));
}

export function applyCors(req, res, allowedOrigins) {
  addVaryOrigin(res);
  const requestOrigin = req.headers?.origin;

  // Non-browser service-to-service requests and CLI health checks have no Origin.
  if (!requestOrigin) return true;

  const origin = normalizeOrigin(requestOrigin);
  if (!origin || !allowedOrigins.has(origin)) return false;

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
  res.setHeader("Access-Control-Expose-Headers", "Content-Disposition, X-Signing-Engine");
  res.setHeader("Access-Control-Max-Age", "86400");
  return true;
}


// The two production storefront origins are trusted explicitly so a missing or
// incomplete Vercel ALLOWED_ORIGINS value cannot break the www/apex domain pair.
// Additional exact origins (for approved preview/staging domains) may be supplied
// through ALLOWED_ORIGINS. Wildcards and URL paths remain rejected by the parser.
export const DEFAULT_PRODUCTION_ORIGINS = Object.freeze([
  "https://luavang.store",
  "https://www.luavang.store",
]);

export function buildAllowedOrigins(configuredValue) {
  return new Set([
    ...DEFAULT_PRODUCTION_ORIGINS,
    ...parseAllowedOrigins(configuredValue),
  ]);
}
