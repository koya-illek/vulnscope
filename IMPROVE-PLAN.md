# VulnScope improvement plan — Round 3 (2026-08-22)

Fresh review of the post-round-2 tree. Rounds 1 and 2 fixed the original
findings list (severity recalibration, hash guard, CORS repricing, path-tier
rotation, concurrency race, contrast, focus-visible, stream hardening, and so
on). This round covers what survived those passes or was introduced since.
Not a git repo, so changes land in place. Verification: `cd api && npm run
typecheck` and `npm test`, plus `node --check` on edited web files.

## Technical

### T1. Wire up `MCP_DAILY_LIMIT`; delete dead `REPORT_DAILY_LIMIT`
- What: wrangler.toml declares `MCP_DAILY_LIMIT = "200"` and
  `REPORT_DAILY_LIMIT = "120"`, and `Env` types them, but neither is enforced
  anywhere in code. MCP scans silently draw from the same per-IP "scan" bucket
  as the web form (`DAILY_SCAN_LIMIT = 50`), so the advertised 200-request MCP
  budget does not exist and an agent can exhaust a shared IP's web quota.
  `REPORT_DAILY_LIMIT` contradicts ARCHITECTURE.md ("Valid report reads … do
  not write durable quota state") and is pure dead config.
- Where: `api/src/index.ts` (`createScan`, `enforceRateLimit`), the MCP branch
  in `fetch`, `api/src/types.ts`, `api/wrangler.toml`,
  `api/test/rate-limit-accounting.test.ts`.
- Why: deployed config advertises limits that don't exist; that is exactly the
  doc-vs-code drift this project otherwise works hard to avoid. Separate MCP
  scoping also stops agents and browsers competing for one bucket.
- How: give `createScan` an optional quota override `{ scope, limit, label }`
  (default scan/DAILY_SCAN_LIMIT); pass `{ scope: "mcp", limit:
  MCP_DAILY_LIMIT }` from the `scan_website` MCP path. Remove
  REPORT_DAILY_LIMIT from toml/types/fixture. Add a test asserting an MCP scan
  charges the mcp scope key, not the scan scope key.

### T2. Sanitize hostname in export filenames
- What: `vulnscope-${report.hostname}-${report.id}.json` interpolates the raw
  stored hostname into a Content-Disposition header server-side
  (`api/src/index.ts:138`) and a download attribute client-side
  (`web/app.js:545`). New reports have validated hostnames; migrated legacy
  schema-1 rows are not revalidated field-by-field.
- Where: `api/src/index.ts`, `web/app.js`.
- Why: cheap defense-in-depth against header injection/garbage filenames from
  corrupt or tampered rows.
- How: strip everything outside `[A-Za-z0-9.-]` from the hostname before
  interpolation, both sides.

### T3. Only assign http(s) hrefs to the report target link
- What: `displayReport()` sets `#report-url.href = requestedUrl` straight from
  stored report data. Legacy rows skip per-field validation on read.
- Where: `web/app.js:252-254`.
- Why: a corrupt or tampered `requestedUrl` of scheme `javascript:` would
  become a clickable link on a publicly shareable page.
- How: set href only when `/^https?:\/\//i` matches; otherwise drop the href
  and keep the URL as inert text.

### T4. Fix flashButton double-click leaving "Copied" stuck
- What: clicking "Copy share link" twice during the 1.4 s flash captures
  "Copied" as the new original text, and the two timers then restore out of
  order, leaving the button permanently reading "Copied".
- Where: `web/app.js:573-577`.
- Why: real, reproducible UI bug on a primary action.
- How: keep the original label captured once per flash, cancel any pending
  timer before starting a new flash, and ignore clicks while flashing.

### T5. Friendly message for network-level failures
- What: an offline or aborted fetch throws TypeError("Failed to fetch") whose
  raw browser text lands verbatim in the error panel.
- Where: `web/app.js` (`runScan`, `loadReport` catch paths).
- Why: error states are designed surfaces; a stack-flavored browser string is
  not actionable copy.
- How: map non-Error/network failures to "Network request failed. Check your
  connection and try again." while preserving server-provided messages.

## UI / UX

### U1. Move focus to the report heading after a scan or load; into the error panel on failure
- What: when a scan finishes, the progress panel is replaced by the report and
  scrolling happens, but focus stays behind on the re-enabled submit button.
  Keyboard and screen-reader users get no cue that context changed. Errors use
  role="alert" (announced) but focus never enters the panel, so dismissal is a
  hunt with Tab.
- Where: `web/index.html` (tabindex="-1" hooks), `web/app.js` (focus calls),
  `web/styles.css` (outline for programmatic focus).
- Why: Illek standards require announced async status changes and visible,
  logical focus placement after view swaps.
- How: add tabindex="-1" to #report-host and #error-panel; call .focus()
  (with preventScroll, scrolling already handled) after display/error;
  style :focus-visible so it stays visible.

### U2. 44px touch targets for filters and report actions
- What: severity filter chips are 36px tall and secondary/icon buttons 42px,
  below the 44px minimum used everywhere else after round 2.
- Where: `web/styles.css` (`.filter`, `.secondary-button`, `.icon-button`).
- Why: WCAG 2.5.8 / Illek standards touch-target floor; filters are the main
  report interaction on mobile.
- How: raise min-height/min-width to 44px; adjust padding so the visual rhythm
  holds.

### U3. Give ungraded reports their own badge tone
- What: INCOMPLETE renders letter "N/G" but the badge class is computed from
  the grade string, producing `grade-n/g` which no CSS rule matches, so the
  N/G letter glows accent orange exactly like a healthy A/B grade.
- Where: `web/report-view.js` (`gradePresentation`), `web/app.js`
  (`renderGrade`), `web/styles.css`.
- Why: an ungraded report should not borrow the visual authority of a graded
  one; honesty-first product, honesty-first styling.
- How: return a `tone` slug ("incomplete"/"unavailable"/grade) from
  gradePresentation, use it for the class, and style those tones muted.

### U4. Full target URL reachable via title tooltip
- What: `#report-url` is ellipsised at 700px max-width with no way to see the
  full value visually (screen readers get the text node).
- Where: `web/app.js` displayReport.
- How: set title attribute to the requested URL.

## Other

### O1. Comment grammar in cors.ts
- "lets a attacker site" → "lets an attacker's site" (`api/src/cors.ts:48`).
  Trivial, touched file anyway in T1's neighbourhood.

### O2. Docs sync
- ARCHITECTURE.md: note the separate MCP scan quota scope next to the storage/
  quota bullet if limits are described; remove any REPORT_DAILY_LIMIT mention.
- Keep THREAT_MODEL.md untouched unless it names the removed var.

## Skipped this round (with reasons)
- Secret-scan CPU cost over large bundles (regex fan-out on up to 8×512 KiB):
  changing budgets alters detection behaviour and tests for no observed
  failure; left as-is.
- Rate limiting report reads (would contradict documented read-free design and
  risk locking out shared-link viewers behind NAT); instead the dead
  REPORT_DAILY_LIMIT var is deleted honestly (T1).
- Light theme, COEP/CORP headers, JSON-LD offers property: deliberate design
  choices or no concrete win.
