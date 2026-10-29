# SiteGuard Auditor — delivery checklist

## Safe authorized-use guardrails
- [ ] Require a valid HTTP(S) URL and an explicit confirmation that the user owns or is authorized to assess the target before a live scan can begin.
- [ ] Clearly state that no scanner can identify every vulnerability; do not include exploit payloads, credential attacks, brute force, stealth, or destructive behavior.
- [ ] Enforce bounded, non-destructive checks with target validation, response limits, timeout, redirect limits, and rate limiting.

## Auditor workflow
- [ ] Let a user run a deterministic demo scan without contacting a live site.
- [ ] Let an authorized user run a constrained passive scan and show queued, running, completed, failed, and limited feedback.
- [ ] Present findings with severity, category, evidence, remediation guidance, confidence, and timestamps.
- [ ] Provide severity/category/confidence filters and an at-a-glance score summary.
- [ ] Export completed reports as JSON and Markdown.

## Open-source handoff
- [ ] Add route manifest and project documentation with setup, safe-use, and contribution guidance.
- [ ] Verify TypeScript diagnostics, production build, health endpoint, and live preview.
- [ ] Save a checkpoint to the canonical repository and publish only after a successful build.
