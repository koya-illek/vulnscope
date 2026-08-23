# Production Iteration 4 Plan (2026-08-22)

Iteration 4 of 8 on `production/iteration-4` (base `ox-round3-baseline`). Three
prior rounds fixed the review findings from `/home/koya/ox-reviews-2026-08-22/vuln-scanner.md`.
This round is a fresh review of the post-round-3 tree, live checks against
https://scan.illek.ie, and a small set of evidence-backed fixes. Deliberately
small: the remaining defect list is short and cosmetic churn is a failure mode.

## Audience, job, primary path

Unchanged from rounds 1-3: site owners and reviewers run an authorised,
unauthenticated exposure check of one public URL and share an expiring,
evidence-backed report. Primary path: enter URL, confirm authorisation,
watch progress, read/share the report. Trust boundary: public bearer-link
reports; outbound probes fail closed behind one shared budget.

## Confirmed findings (this round)

1. **Ghost/Joomla fingerprinting matches prose** (`api/src/fingerprint.ts`).
   Ghost detection tests the bare word `ghost` anywhere in the HTML
   (`/ghost|<meta...Ghost/i`) and Joomla tests bare `joomla`. "Ghost" is a
   common English word and "Joomla" appears in ordinary tech prose, so pages
   with neither CMS are labelled `CMS: Ghost` / `CMS: Joomla` in the report's
   Technology fingerprint section. Same bug class as the round-2 WordPress
   fix, minus the expensive probe phase: today the impact is wrong data in a
   public report, which is a data-honesty defect for an evidence-first tool.
2. **Dead fetch-metadata plumbing** (`api/src/outbound.ts`). Every successful
   `safeFetch` response records `{finalUrl, redirectChain}` into a module-level
   WeakMap exposed via `getFetchMetadata()`. Nothing in `src`, `test`, or `web`
   ever calls it. Written 40+ times per scan, never read.
3. **Undefined CSS token `var(--panel)`** (`web/styles.css:633`). The
   developer-access cards use `background: var(--panel)`, but no `--panel`
   token exists (`--surface`, `--surface-2`, `--bg` do). The declaration is
   invalid at computed-value time, so those cards render transparent instead
   of the intended surface fill, unlike every other panel on the page.
4. **Production lags this branch** (operations, not code). Live
   https://scan.illek.ie serves a pre-round-2 build: single deferred script,
   no `Cross-Origin-Opener-Policy` header, pre-contrast-pass CSS. Expected:
   deploys are out of scope for iterations. Recorded as a release note so the
   next deploy ships rounds 1-4 together.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Require structural markers for Joomla and Ghost CMS detection (generator meta tag or asset paths), matching the round-2 WordPress rule | `api/src/fingerprint.ts`, `api/test/fingerprint.test.ts` | Reports stop claiming Ghost/Joomla on pages that merely mention them | Low: detection only feeds the fingerprint display; no probe phases depend on it |
| 2 | Delete `responseMetadata` WeakMap and `getFetchMetadata()` export plus the write site | `api/src/outbound.ts` | None (dead code removal) | Minimal: verified zero references |
| 3 | Replace `var(--panel)` with `var(--surface)` | `web/styles.css` | Developer-access cards regain their surface background at all widths | Minimal |
| 4 | No doc sync needed: ARCHITECTURE.md does not document CMS-detection internals or the removed helper | - | - | - |

## Verification

- `npm run typecheck`, `npm test` in `api/` (baseline before changes: clean, 20 files, 167 tests).
- New regression tests: prose-only Joomla/Ghost pages are not detected; generator meta tags are.
- Token-resolution sweep over CSS+JS custom properties returns no missing tokens after fix 3.
- `node --check` on web JS files.
- `scripts/audit-html.mjs` against the canonical live URL.
- Lighthouse on the live canonical URL (read-only) with the caveat that it measures the deployed build, not this branch.
- Headless Chromium screenshots of the local page at 390, 768, and 1440 CSS pixels; keyboard/focus/reduced-motion states re-checked by markup inspection (no interactive browser automation installed).

## Explicit non-goals (carried forward with unchanged rationale)

- Turnstile/WAF abuse backstop: outside repo control; requires Cloudflare dashboard access.
- DNS TOCTOU between DoH validation and fetch connection: inherent to Workers; documented accepted residual risk in THREAT_MODEL.md.
- Observability head sampling rate: keep 1.0 until volume justifies lowering.
- `VulnScanner` service-string rename in `/api/health` and the UA product token: breaking change for consumers; stable across all rounds.
- Redeployment of https://scan.illek.ie: not permitted this iteration; tracked as release operations.
