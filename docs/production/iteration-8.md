# Production iteration 8 plan

Branch: `production/iteration-8` (base `production/iteration-7`, clean at start,
same tip as iteration 7: `fcd78f1`). Live reference: https://scan.illek.ie
(read-only checks only; no deploy).

## Audience, job, primary path

Unchanged from iteration 7: site owners, developers, MSP analysts, and REST/MCP
agents need a bounded, evidence-backed view of a public website's unauthenticated
external exposure. Primary path: enter URL, confirm authorisation, watch
progress, read/share the graded report. Trust boundary: target-controlled
content is attacker input; reports are public bearer links; every finding in a
shareable report must be earned by evidence. Current release risks: production
still serves a pre-round-2 build (no COOP header, pre-contrast CSS — deployment
lag noted since iteration 4); abuse backstop remains dashboard-side.

## Confirmed findings (reproduced before fixing)

1. **Subdomain-takeover section misrepresents coverage in shared reports.**
   Reproduced by executing the exact `displayReport` branch from `web/app.js`:
   - A scan that ran takeover checks and measured zero results stores
     `takeover: []`; opened through its share link on a fresh browser the
     section is hidden entirely (`checkTakeoverCheckbox.checked` is false and
     `report.takeover.length` is 0). Measured work disappears from the
     dedicated panel (the coverage table still mentions it, inconsistently
     with the paths panel, which explains measured-empty states).
   - Worse: a viewer who ticks "Check subdomain takeover" in the form and then
     loads any saved report where takeover was *not enabled* gets
     "No subdomains with vulnerable CNAME patterns found." — a false claim that
     the check ran, driven by the viewer's own checkbox instead of the
     report's provenance (`coverage.takeover.status === "skipped"`).
   Visibility must come from the report's coverage record, and empty panels
   must distinguish measured/partial/failed/unavailable/skipped exactly like
   `exposedPathsState()` already does for paths.
2. **WordPress debug-log check accuses soft-404 pages.** Reproduced with a
   mocked `/wp-content/debug.log` response: a 200 HTML fallback page whose body
   merely contains the word "Error" produces a public medium-severity finding
   "WordPress Debug Log Exposed (~1 lines)". The marker set (`PHP`, `Warning`,
   `Error`, `Stack trace`) matches ordinary theme/plugin error copy. Same
   single-weak-marker false-positive class eliminated for CMS fingerprints in
   rounds 2/4/5; this one publishes accusations in a shareable report.
3. **Dead plumbing: `CookieAuditResult.issues` is always empty.** `parseCookie`
   creates the array, nothing appends, findings carry their own evidence, and
   `cookieRows()` derives issue counts from the boolean attributes anyway. The
   schema dimension is unreachable from the backend.
4. **Fingerprint language detection performs a no-op dance for nginx**: pushes
   `"C"` for nginx servers, then filters `"C"` out before returning. Net effect
   zero; reads as if nginx contributes a language.
5. **`inspectSsl` carries an unused `_fetchResponse` parameter** voided at the
   top of the function — leftover from the removed TLS-metadata design.
6. **Progress live region is broader than needed.** `#progress-panel` carries
   `aria-live="polite"` over the title, the six-node route, *and* the six-item
   steps list, so screen readers get churn from visual duplication on every
   stage event. The route is already `aria-hidden`; the steps list is a visual
   duplicate of the title announcements.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Add `takeoverState(rows, coverage)` to the presentation contract mirroring `exposedPathsState`: visibility derives from `coverage.takeover` (shown for requested/attempted work, hidden only when skipped/not recorded) and empty panels get truthful measured/partial/failed/unavailable/skipped messages. `displayReport`/`renderTakeover` consume it; the form checkbox no longer drives report display. Regression tests for all five states plus rows-present. | `web/report-view.js`, `web/app.js`, `api/test/report-view.test.js` | Shared reports stop hiding measured takeover work and stop claiming checks that never ran. | Low: display logic only |
| 2 | Require WordPress debug-log-specific evidence before reporting exposure: a dated WP log line (`[dd-Mon-yyyy …] PHP …`) or an explicit `PHP Warning:`/`PHP Notice:`/`PHP Fatal error:`/`PHP Parse error:`/`PHP Deprecated:` marker. Generic "Error"/"Warning" words no longer qualify. Regression tests: fallback page with "Error" finds nothing; real-format log still detected. | `api/src/wordpress.ts`, `api/test/wordpress.test.ts` | Removes a false public accusation class on WordPress sites whose debug.log path returns a themed 200 page. | Low: stricter gate on an existing finding |
| 3 | Delete the always-empty `issues` field end to end (`CookieAuditResult`, `parseCookie`, `cookieRows` issueCount/issueText, cookies render span) and update the presentation test fixture. Older stored reports carrying `issues: []` remain valid on read (field ignored). | `api/src/types.ts`, `api/src/cookies.ts`, `web/report-view.js`, `web/app.js`, `api/test/report-view.test.js` | No behaviour change; smaller contract. | Low |
| 4 | Remove the nginx `"C"` placeholder/filter dance and the unused `inspectSsl` response parameter (call sites updated). | `api/src/fingerprint.ts`, `api/src/ssl.ts`, `api/src/analyzer.ts` | None direct; simpler code. | Low |
| 5 | Move the progress `aria-live` region from the whole panel to `#progress-title` so assistive tech hears the stage message once instead of the duplicated step list; assert the contract in the public-shell test. | `web/index.html`, `api/test/public-shell.test.js` | Less screen-reader noise during scans. | Low |

## Explicit non-goals

- Turnstile/WAF abuse backstop: Cloudflare dashboard access, outside repo.
- DNS TOCTOU residual risk: platform-inherent, documented in THREAT_MODEL.md.
- Observability head sampling change: no volume signal to justify it.
- `VulnScanner` service-string/UA rename: breaking change for consumers.
- Deployment of https://scan.illek.ie: outside iteration scope (production
  still serves the pre-round-2 build as of today's live checks).
- Root-level historical docs (PRODUCT_REVIEW.md etc.): unchanged rationale.
- Retaining optional scope checkboxes across `reset()`: deliberate preference
  persistence; with change 1 the display no longer depends on them.
- Client-side parsing of non-stream JSON errors from `/api/scans/stream`: traced
  all reachable paths; the shipped web client cannot trigger the pre-stream
  validation failures (body shape/size/content-type and origin checks are all
  satisfied by construction), so the generic HTTP-status fallback stays.
- Dependency upgrades: workers-types/wrangler updated last round; no runtime
  dependency beyond tldts; nothing pending with security relevance.

## Verification

- Reproduction tests red before fixes 1–2 where unit-testable (fix 1 via new
  `takeoverState` contract tests against the current missing function; fix 2
  demonstrated pre-fix with the mocked fallback page above).
- `cd api && npm run typecheck && npm test`.
- Browser matrix at 390/768/1440: landing + synthetic report renders including
  a skipped-takeover report (section hidden regardless of checkbox) and a
  measured-empty takeover report (visible truthful message); keyboard, reduced
  motion, no horizontal overflow; axe-core on landing + report.
- `node scripts/audit-html.mjs https://scan.illek.ie/`.
- Lighthouse against the local build of this branch.
- Live read-only spot checks (health, unknown report 404, HTTP→HTTPS 308,
  self-scan NDJSON boundary).
