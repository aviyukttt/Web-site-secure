import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { trpc } from "@/lib/trpc";
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleHelp,
  Download,
  ExternalLink,
  FileText,
  Fingerprint,
  Gauge,
  Github,
  Globe2,
  Info,
  KeyRound,
  LockKeyhole,
  Play,
  Radar,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  Timer,
  X,
  Zap,
} from "lucide-react";
import type { Finding, ScanReport, Severity, Confidence } from "../../../server/scanner";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
const demoReport: ScanReport = {
  target: "https://acme-demo.example",
  finalUrl: "https://acme-demo.example/",
  statusCode: 200,
  durationMs: 842,
  scannedAt: "2026-10-29T08:12:18.000Z",
  limited: false,
  findings: [
    { id: "demo-csp", title: "Content Security Policy is missing", severity: "medium", category: "headers", evidence: "GET https://acme-demo.example did not include content-security-policy.", remediation: "Define a narrowly scoped Content-Security-Policy and iterate in report-only mode before enforcement.", confidence: "high" },
    { id: "demo-hsts", title: "HSTS is not advertised", severity: "medium", category: "transport", evidence: "The HTTPS response did not include Strict-Transport-Security.", remediation: "After confirming HTTPS is universal, add Strict-Transport-Security with an appropriate max-age.", confidence: "high" },
    { id: "demo-cookie", title: "session_id is missing cookie hardening", severity: "medium", category: "cookies", evidence: "session_id does not visibly set: SameSite.", remediation: "Set Secure, HttpOnly, and SameSite on session and sensitive cookies where compatible.", confidence: "high" },
    { id: "demo-frame", title: "Clickjacking protection is not explicit", severity: "medium", category: "headers", evidence: "GET https://acme-demo.example did not include x-frame-options.", remediation: "Use CSP frame-ancestors and/or X-Frame-Options to control framing.", confidence: "high" },
    { id: "demo-nosniff", title: "MIME sniffing protection is missing", severity: "low", category: "headers", evidence: "GET https://acme-demo.example did not include x-content-type-options.", remediation: "Send X-Content-Type-Options: nosniff on HTML and sensitive responses.", confidence: "high" },
    { id: "demo-meta", title: "No page-level referrer or CSP meta policy detected", severity: "info", category: "markup", evidence: "The initial HTML did not include a referrer meta tag or CSP meta fallback.", remediation: "Prefer response headers; use page-level metadata only when the deployment architecture requires it.", confidence: "medium" },
  ],
};

function scoreFor(findings: Finding[]) {
  return Math.max(0, Math.round(100 - findings.reduce((total, item) => total + ({ critical: 28, high: 18, medium: 9, low: 3, info: 0 }[item.severity]), 0)));
}

function formatTime(date: string) {
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(date));
}

function severityLabel(severity: Severity) {
  return severity === "info" ? "Info" : severity[0].toUpperCase() + severity.slice(1);
}

function downloadReport(report: ScanReport, format: "json" | "md") {
  const filename = `siteguard-${new URL(report.target).hostname}-${new Date(report.scannedAt).toISOString().slice(0, 10)}`;
  const content = format === "json" ? JSON.stringify(report, null, 2) : [
    `# SiteGuard report — ${report.target}`,
    `\nScanned: ${formatTime(report.scannedAt)} · HTTP ${report.statusCode} · ${report.durationMs}ms`,
    `\n> This is a bounded passive posture check. It is not a complete vulnerability assessment.`,
    ...report.findings.map((item, index) => `\n## ${index + 1}. ${item.title}\n\n- Severity: ${severityLabel(item.severity)}\n- Category: ${item.category}\n- Confidence: ${item.confidence}\n- Evidence: ${item.evidence}\n- Remediation: ${item.remediation}`),
  ].join("\n");
  const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/markdown" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${filename}.${format}`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function StatusPill({ severity }: { severity: Severity }) {
  return <span className={`severity-pill severity-${severity}`}><span className="severity-dot" />{severityLabel(severity)}</span>;
}

function StatCard({ label, value, tone, icon: Icon }: { label: string; value: number | string; tone: string; icon: typeof Shield }) {
  return <div className="stat-card"><div className={`stat-icon ${tone}`}><Icon size={16} /></div><div><div className="stat-value">{value}</div><div className="stat-label">{label}</div></div></div>;
}

export default function Home() {
  const [target, setTarget] = useState("https://acme-demo.example");
  const [authorized, setAuthorized] = useState(false);
  const [report, setReport] = useState<ScanReport>(demoReport);
  const [mode, setMode] = useState<"demo" | "live">("demo");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState<"all" | Confidence>("all");
  const [notice, setNotice] = useState("Demo report loaded — no network request was made.");
  const [progressStep, setProgressStep] = useState(0);
  const scanMutation = trpc.scan.run.useMutation({
    onSuccess: (nextReport) => {
      setReport(nextReport);
      setMode("live");
      setNotice("Passive assessment complete. Review evidence before prioritizing fixes.");
    },
    onError: (error) => setNotice(error.message),
  });

  useEffect(() => {
    if (!scanMutation.isPending) return;
    const interval = window.setInterval(() => setProgressStep(value => (value + 1) % 3), 900);
    return () => window.clearInterval(interval);
  }, [scanMutation.isPending]);

  const counts = useMemo(() => severityOrder.reduce<Record<Severity, number>>((acc, severity) => ({ ...acc, [severity]: report.findings.filter(item => item.severity === severity).length }), { critical: 0, high: 0, medium: 0, low: 0, info: 0 }), [report]);
  const categories = useMemo(() => Array.from(new Set(report.findings.map(item => item.category))), [report]);
  const filteredFindings = useMemo(() => report.findings.filter(item => (severityFilter === "all" || item.severity === severityFilter) && (categoryFilter === "all" || item.category === categoryFilter) && (confidenceFilter === "all" || item.confidence === confidenceFilter)), [report, severityFilter, categoryFilter, confidenceFilter]);
  const score = scoreFor(report.findings);
  const isBusy = scanMutation.isPending;

  function runScan() {
    if (!authorized) {
      setNotice("Confirm that you own or are authorized to assess this target before starting a live scan.");
      return;
    }
    setProgressStep(0);
    setNotice("Validating target and preparing a bounded passive request…");
    scanMutation.mutate({ target, authorized: true });
  }

  function loadDemo() {
    setReport(demoReport);
    setMode("demo");
    setTarget(demoReport.target);
    setNotice("Demo report loaded — no network request was made.");
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={20} strokeWidth={2.4} /></div><div><div className="brand-name">SITE<span>GUARD</span></div><div className="brand-caption">auditor / v1.0</div></div></div>
      <div className="rail-label">Workspace</div>
      <nav className="side-nav">
        <a className="side-link active" href="#overview"><Gauge size={17} /><span>Overview</span><span className="nav-count">01</span></a>
        <a className="side-link" href="#findings"><Radar size={17} /><span>Findings</span><span className="nav-count">{report.findings.length.toString().padStart(2, "0")}</span></a>
        <a className="side-link" href="#method"><FileText size={17} /><span>Methodology</span></a>
      </nav>
      <div className="sidebar-bottom">
        <div className="rail-label">Project</div>
        <a className="side-link" href="https://github.com" target="_blank" rel="noreferrer"><Github size={17} /><span>Open source</span><ExternalLink size={13} className="external-icon" /></a>
        <div className="safe-card"><div className="safe-card-icon"><LockKeyhole size={15} /></div><div><strong>Safe by default</strong><p>Passive checks only. No exploit traffic.</p></div></div>
        <div className="version"><span className="online-dot" /> scanner status <strong>operational</strong></div>
      </div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div className="breadcrumb"><span>WORKSPACE</span><span className="crumb-slash">/</span><strong>OVERVIEW</strong></div><div className="top-actions"><span className="scope-badge"><span className="online-dot" /> authorized mode</span><button className="icon-button" title="Help"><CircleHelp size={17} /></button><div className="avatar">SG</div></div></header>

      <section className="page-heading" id="overview"><div><div className="eyebrow"><span className="signal-line" /> SECURITY POSTURE / FIRST PASS</div><h1>Find the signals.<br /><em>Fix the surface.</em></h1><p className="heading-copy">A transparent, non-destructive website posture check for the people responsible for keeping a site trustworthy.</p></div><div className="heading-meta"><div className="meta-label">LAST ASSESSMENT</div><div className="meta-value mono">{formatTime(report.scannedAt)}</div><div className="meta-label meta-gap">ASSESSMENT MODE</div><div className="meta-value"><span className={`mode-dot ${mode}`} /> {mode === "demo" ? "DEMO / NO NETWORK" : "LIVE / PASSIVE"}</div></div></section>

      <section className="scan-card"><div className="scan-card-top"><div><div className="section-kicker"><Zap size={14} /> NEW ASSESSMENT</div><h2>Check a website you are responsible for.</h2></div><div className="bounded-note"><span className="mini-shield"><Shield size={13} /></span> bounded to public HTTP signals</div></div><div className="scan-form"><div className="url-field"><Globe2 size={18} /><input value={target} onChange={event => setTarget(event.target.value)} aria-label="Website URL" placeholder="https://your-site.com" /><button className="clear-url" onClick={() => setTarget("")} aria-label="Clear URL"><X size={15} /></button></div><button className="scan-button" disabled={isBusy} onClick={runScan}>{isBusy ? <><RefreshCw size={16} className="spin" /> Assessing</> : <><Play size={15} fill="currentColor" /> Run passive scan</>}</button></div><label className="authorization-row"><input type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked)} /><span className="custom-check">{authorized && <Check size={12} />}</span><span>I confirm I own this website or have explicit authorization to assess it.</span><span className="required">required for live scan</span></label><div className={`scan-notice ${notice.includes("complete") || notice.includes("Demo") ? "positive" : notice.includes("Confirm") || notice.includes("limit") || notice.includes("blocked") ? "warning" : ""}`}><Info size={14} /><span>{notice}</span></div>{isBusy && <div className="progress-strip"><span className="progress-fill" style={{ width: `${(progressStep + 1) * 33}%` }} /><div className="progress-labels"><span className={progressStep >= 0 ? "active" : ""}>validate target</span><span className={progressStep >= 1 ? "active" : ""}>inspect signals</span><span className={progressStep >= 2 ? "active" : ""}>shape report</span></div></div>}<div className="demo-row"><span><Sparkles size={14} /> Want to explore first?</span><button onClick={loadDemo}>Load the safe demo report <ArrowUpRight size={14} /></button></div></section>

      <section className="summary-grid"><div className="score-card"><div className="score-ring" style={{ "--score": `${score * 3.6}deg` } as CSSProperties}><div><span className="score-number">{score}</span><span className="score-denom">/100</span></div></div><div><div className="score-kicker">POSTURE SCORE</div><h3>{score >= 80 ? "Good baseline" : score >= 60 ? "Needs attention" : "Priority review"}</h3><p>Weighted from {report.findings.length} observable signal{report.findings.length === 1 ? "" : "s"}.</p></div><button className="round-help" title="How score is calculated"><CircleHelp size={15} /></button></div><StatCard label="Critical / high" value={counts.critical + counts.high} tone="red" icon={AlertTriangle} /><StatCard label="Medium" value={counts.medium} tone="amber" icon={Shield} /><StatCard label="Informational" value={counts.info + counts.low} tone="blue" icon={Info} /></section>

      <section className="findings-section" id="findings"><div className="section-header"><div><div className="eyebrow"><span className="signal-line" /> OBSERVATIONS</div><h2>Findings <span className="muted-count">{filteredFindings.length.toString().padStart(2, "0")}</span></h2></div><div className="report-actions"><button className="outline-button" onClick={() => downloadReport(report, "md")}><Download size={14} /> Markdown</button><button className="outline-button" onClick={() => downloadReport(report, "json")}><Download size={14} /> JSON</button></div></div><div className="filter-bar"><div className="filter-intro"><Fingerprint size={15} /><span>Filter report</span></div><label>severity<select value={severityFilter} onChange={event => setSeverityFilter(event.target.value as "all" | Severity)}><option value="all">All severities</option>{severityOrder.map(item => <option key={item} value={item}>{severityLabel(item)} ({counts[item]})</option>)}</select><ChevronDown size={13} /></label><label>category<select value={categoryFilter} onChange={event => setCategoryFilter(event.target.value)}><option value="all">All categories</option>{categories.map(item => <option key={item} value={item}>{item}</option>)}</select><ChevronDown size={13} /></label><label>confidence<select value={confidenceFilter} onChange={event => setConfidenceFilter(event.target.value as "all" | Confidence)}><option value="all">All confidence</option><option value="high">High confidence</option><option value="medium">Medium confidence</option><option value="low">Low confidence</option></select><ChevronDown size={13} /></label></div><div className="finding-list">{filteredFindings.map((item, index) => <article className="finding-row" key={item.id}><div className="finding-index">{String(index + 1).padStart(2, "0")}</div><div className="finding-main"><div className="finding-title-line"><h3>{item.title}</h3><StatusPill severity={item.severity} /></div><div className="finding-tags"><span>{item.category}</span><span><span className={`confidence-dot confidence-${item.confidence}`} /> {item.confidence} confidence</span></div><div className="evidence"><Terminal size={13} /><code>{item.evidence}</code></div></div><div className="finding-action"><button title="View remediation"><ArrowUpRight size={16} /></button></div></article>)}{filteredFindings.length === 0 && <div className="empty-state"><Check size={20} /><h3>No findings match these filters.</h3><p>Reset a filter to view the full report.</p></div>}</div></section>

      <section className="method-section" id="method"><div className="method-copy"><div className="eyebrow"><span className="signal-line" /> WHAT THIS TOOL DOES</div><h2>A posture check,<br /><em>not a promise of invincibility.</em></h2><p>SiteGuard inspects a deliberately small surface: transport, security headers, cookie attributes, and a few page-level signals. It never submits forms, tries credentials, launches payloads, or crawls beyond the initial response.</p><a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer" className="text-link">Read the methodology notes <ExternalLink size={14} /></a></div><div className="method-list"><div><span className="method-number">01</span><div><strong>Validate</strong><p>Reject private networks, credentials, unusual ports, and unsafe destinations.</p></div></div><div><span className="method-number">02</span><div><strong>Observe</strong><p>Fetch one public response with a short timeout and a strict response budget.</p></div></div><div><span className="method-number">03</span><div><strong>Explain</strong><p>Show evidence, confidence, and a practical next step for every signal.</p></div></div></div></section>

      <footer className="footer"><div className="footer-brand"><div className="brand-mark small"><ShieldCheck size={15} /></div><span>SITEGUARD / OPEN SOURCE</span></div><span>Built for responsible disclosure · v1.0.0</span><a href="https://github.com" target="_blank" rel="noreferrer">View on GitHub <Github size={14} /></a></footer>
    </main>
  </div>;
}
