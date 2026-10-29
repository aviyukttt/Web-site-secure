# SiteGuard Auditor

SiteGuard Auditor is an open-source, defensive website posture checker for site owners and authorized security teams. It runs a bounded passive assessment of a public HTTP response and page markup, then turns the observable signals into a readable report.

> **Authorized use only.** Only scan websites you own or have explicit permission to assess. This project is not a penetration-testing framework and cannot find every vulnerability. It intentionally avoids exploit payloads, credential attacks, brute force, stealth, destructive actions, and deep crawling.

## Checks in this first release

The first release checks HTTPS transport and redirect posture, security headers, cookie attributes, and basic HTML signals such as password forms served over non-HTTPS and mixed-content references. Results are informational posture findings, not proof of exploitability. Validate important issues with a qualified professional and the target's own logs and configuration.

## Run locally

```bash
pnpm install
pnpm dev
```

Then open the local preview URL. Demo mode works without any network request. Live scans are deliberately rate-limited and reject private or local network destinations.

## Contributing

Please keep changes aligned with safe, non-destructive, authorized assessment. Add tests for parser and validation changes, document new checks, and never add exploit payloads or credential-handling code.
