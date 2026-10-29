# SiteGuard Auditor — implementation plan

## Product scope

SiteGuard Auditor is a public, open-source defensive tool for authorized website owners and security teams. It accepts a URL only after an explicit authorization confirmation, runs a bounded passive assessment of publicly available HTTP responses and page markup, and presents structured findings. It does not claim to find every vulnerability and does not send exploit payloads, brute-force credentials, crawl deeply, evade detection, or modify targets.

## Implementation approach

- Frontend: React + TypeScript + Tailwind, built as a single responsive dashboard route.
- Backend: Express + tRPC public `scan.run` procedure for a constrained passive scan. It validates HTTP(S) URLs, rejects localhost/private/link-local/loopback targets, applies an in-memory per-IP rate limit, follows at most one redirect, fetches only the homepage with a short timeout, and inspects response headers, cookies, basic HTML signals, and transport.
- Reporting: frontend normalizes scan results into findings with severity, category, evidence, remediation, confidence, and timestamp. Reports export as JSON or Markdown without server-side persistence.
- Demo mode: deterministic seeded findings show the full experience without contacting a live website.
- Route manifest: `/manus-routes.json` declares the home dashboard and `/404`.

## Design direction

Three low-probability directions considered:
1. Terminal-noir observability console (0.07): dense, monochrome, command-line-first.
2. **Signal & Shield editorial dashboard (0.06, selected):** dark ink canvas with vivid lime signal accents, quiet cards, and a disciplined security-report hierarchy.
3. Soft SaaS compliance portal (0.08): pale surfaces, rounded modules, friendly gradients.

### Selected system: Signal & Shield editorial dashboard

- Design movement: editorial information design fused with incident-response consoles.
- Core principles: evidence before drama; strong hierarchy; calm, legible density; safe-by-default interactions.
- Color philosophy: near-black ink makes findings feel deliberate; acid lime is reserved for verified action and positive posture; amber, orange, and red encode urgency without turning the UI into alarm theater.
- Layout paradigm: asymmetric left rail plus a wide working canvas; a hero scan card anchors the page while evidence and filters flow below it.
- Signature elements: lime vertical signal rule, oversized monospaced score numerals, and small uppercase status labels with hairline dividers.
- Interaction philosophy: every action explains what it will do; live scans require an authorization checkbox; demo mode is always available.
- Animation: subtle progress shimmer during scans, score count-up on completion, and restrained row reveal; no decorative motion on security findings.
- Typography: Inter for UI and display; IBM Plex Mono fallback for scores, timestamps, URLs, and evidence snippets.
- Brand essence: “A transparent first pass for people who are responsible for the site.” Personality: precise, candid, protective.
- Brand voice: “Find the signals. Fix the surface.” / “A posture check, not a promise of invincibility.”
- Wordmark: SITEGUARD in a compact wordmark with a lime signal tick replacing the crossbar of the A.
- Signature brand color: `#C9F36B` signal lime.

## Project structure

- `client/src/pages/Home.tsx`: dashboard composition, demo/live state, filters, report export.
- `client/src/index.css`: design tokens, responsive layout, cards, tables, and motion.
- `server/scanner.ts`: target validation, safe fetch, header/cookie/markup checks, and report types.
- `server/routers.ts`: public tRPC `scan.run` endpoint.
- `public/manus-routes.json`: route declarations for the dashboard.
- `README.md`: safe-use statement, local setup, and contribution notes.

## Safety boundaries

The backend blocks private and local network destinations, limits response size, uses a short timeout, does not execute target scripts, does not submit forms, and does not attempt authentication. The UI and README repeatedly state that users must own or be authorized to assess targets and that automated checks are not a complete penetration test.
