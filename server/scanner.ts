import dns from "node:dns/promises";
import net from "node:net";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  category: "transport" | "headers" | "cookies" | "markup" | "availability";
  evidence: string;
  remediation: string;
  confidence: Confidence;
};

export type ScanReport = {
  target: string;
  finalUrl: string;
  statusCode: number;
  durationMs: number;
  scannedAt: string;
  findings: Finding[];
  limited: boolean;
};

const MAX_BODY_BYTES = 512_000;
const FETCH_TIMEOUT_MS = 7_000;
const MAX_REDIRECTS = 1;
const WINDOW_MS = 60_000;
const MAX_SCANS_PER_WINDOW = 3;
const requestWindows = new Map<string, number[]>();

function isPrivateIp(address: string) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b] = address.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (family === 6) {
    const normalized = address.toLowerCase();
    return normalized === "::1" || normalized.startsWith("fe80:") || normalized.startsWith("fc") || normalized.startsWith("fd");
  }
  return true;
}

export async function validateTarget(raw: string) {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error("Enter a complete website URL, including https://.");
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Only http:// and https:// targets are supported.");
  if (url.username || url.password) throw new Error("Credentials in target URLs are not allowed.");
  if (url.port && !['80', '443'].includes(url.port)) throw new Error("Only standard web ports are supported.");
  if (url.hostname === "localhost" || url.hostname.endsWith(".localhost") || url.hostname.endsWith(".local")) {
    throw new Error("Local and private network targets are not allowed.");
  }
  const addresses = await dns.lookup(url.hostname, { all: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateIp(address))) {
    throw new Error("This target resolves to a private or local network address and was blocked.");
  }
  url.hash = "";
  url.pathname = url.pathname || "/";
  return url;
}

export function consumeRateLimit(clientKey: string) {
  const now = Date.now();
  const recent = (requestWindows.get(clientKey) ?? []).filter(timestamp => now - timestamp < WINDOW_MS);
  if (recent.length >= MAX_SCANS_PER_WINDOW) return false;
  recent.push(now);
  requestWindows.set(clientKey, recent);
  return true;
}

function finding(partial: Omit<Finding, "id"> & { id: string }): Finding {
  return partial;
}

function header(headers: Headers, name: string) {
  return headers.get(name)?.trim() || "";
}

function checkHeaders(url: URL, headers: Headers): Finding[] {
  const findings: Finding[] = [];
  const checks = [
    { key: "content-security-policy", id: "hdr-csp", title: "Content Security Policy is missing", severity: "medium" as Severity, category: "headers" as const, remediation: "Define a narrowly scoped Content-Security-Policy and iterate in report-only mode before enforcement." },
    { key: "x-content-type-options", id: "hdr-nosniff", title: "MIME sniffing protection is missing", severity: "low" as Severity, category: "headers" as const, remediation: "Send X-Content-Type-Options: nosniff on HTML and sensitive responses." },
    { key: "referrer-policy", id: "hdr-referrer", title: "Referrer-Policy is missing", severity: "low" as Severity, category: "headers" as const, remediation: "Set a privacy-preserving policy such as strict-origin-when-cross-origin." },
    { key: "permissions-policy", id: "hdr-permissions", title: "Permissions Policy is missing", severity: "low" as Severity, category: "headers" as const, remediation: "Declare only the browser capabilities the site needs with Permissions-Policy." },
    { key: "x-frame-options", id: "hdr-frame", title: "Clickjacking protection is not explicit", severity: "medium" as Severity, category: "headers" as const, remediation: "Use CSP frame-ancestors and/or X-Frame-Options to control framing." },
  ];
  for (const check of checks) {
    if (!header(headers, check.key)) {
      findings.push(finding({ ...check, evidence: `GET ${url.origin} did not include ${check.key}.`, confidence: "high" }));
    }
  }
  if (url.protocol === "https:" && !header(headers, "strict-transport-security")) {
    findings.push(finding({ id: "tls-hsts", title: "HSTS is not advertised", severity: "medium", category: "transport", evidence: "The HTTPS response did not include Strict-Transport-Security.", remediation: "After confirming HTTPS is universal, add Strict-Transport-Security with an appropriate max-age and consider includeSubDomains.", confidence: "high" }));
  }
  return findings;
}

function checkCookies(headers: Headers): Finding[] {
  const cookieHeaders = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  const combined = cookieHeaders.length ? cookieHeaders : (headers.get("set-cookie") ? [headers.get("set-cookie")!] : []);
  const findings: Finding[] = [];
  combined.forEach((cookie, index) => {
    const name = cookie.split("=", 1)[0] || `cookie ${index + 1}`;
    const lower = cookie.toLowerCase();
    const missing = [!lower.includes("secure") && "Secure", !lower.includes("httponly") && "HttpOnly", !lower.includes("samesite") && "SameSite"].filter(Boolean);
    if (missing.length) findings.push(finding({ id: `cookie-${index}`, title: `${name} is missing cookie hardening`, severity: "medium", category: "cookies", evidence: `${name} does not visibly set: ${missing.join(", ")}.`, remediation: `Set ${missing.join(", ")} on session and sensitive cookies where compatible with the application.`, confidence: "high" }));
  });
  return findings;
}

function checkMarkup(url: URL, html: string): Finding[] {
  const findings: Finding[] = [];
  const passwordForm = /<input[^>]+type=["']password["']/i.test(html);
  if (passwordForm && url.protocol !== "https:") {
    findings.push(finding({ id: "markup-password-http", title: "Password input is served over HTTP", severity: "high", category: "markup", evidence: "The page contains a password input but the final URL is not HTTPS.", remediation: "Serve authentication pages exclusively over HTTPS and redirect HTTP to HTTPS before rendering forms.", confidence: "high" }));
  }
  const mixedContent = /(?:src|href)=["']http:\/\//i.test(html) && url.protocol === "https:";
  if (mixedContent) findings.push(finding({ id: "markup-mixed-content", title: "Possible mixed-content references found", severity: "medium", category: "markup", evidence: "The HTML contains at least one http:// resource reference on an HTTPS page.", remediation: "Use HTTPS URLs or protocol-relative-safe asset delivery, and review every external dependency.", confidence: "medium" }));
  if (!/<meta[^>]+name=["']referrer["']/i.test(html) && !/<meta[^>]+http-equiv=["']Content-Security-Policy["']/i.test(html)) {
    findings.push(finding({ id: "markup-meta", title: "No page-level referrer or CSP meta policy detected", severity: "info", category: "markup", evidence: "The initial HTML did not include a referrer meta tag or CSP meta fallback.", remediation: "Prefer response headers; use page-level metadata only when the deployment architecture requires it.", confidence: "medium" }));
  }
  return findings;
}

export async function runPassiveScan(rawTarget: string): Promise<ScanReport> {
  const target = await validateTarget(rawTarget);
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(target, { method: "GET", redirect: "manual", signal: controller.signal, headers: { "user-agent": "SiteGuard-Auditor/1.0 (+authorized-passive-check)" } });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (location) {
        const redirected = await validateTarget(new URL(location, target).toString());
        response = await fetch(redirected, { method: "GET", redirect: "manual", signal: controller.signal, headers: { "user-agent": "SiteGuard-Auditor/1.0 (+authorized-passive-check)" } });
      }
    }
  } finally {
    clearTimeout(timeout);
  }
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("text/html") ? (await response.text()).slice(0, MAX_BODY_BYTES) : "";
  const findings = [...checkHeaders(target, response.headers), ...checkCookies(response.headers), ...checkMarkup(target, body)];
  if (response.status >= 400) findings.push(finding({ id: "availability-status", title: "Target returned an error status", severity: response.status >= 500 ? "medium" : "low", category: "availability", evidence: "The initial response returned HTTP " + response.status + ".", remediation: "Confirm the response is intentional and does not expose diagnostic detail or break expected security controls.", confidence: "high" }));
  return { target: target.toString(), finalUrl: response.url || target.toString(), statusCode: response.status, durationMs: Date.now() - started, scannedAt: new Date().toISOString(), findings, limited: false };
}
