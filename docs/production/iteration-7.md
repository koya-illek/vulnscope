# Production iteration 7 plan

Branch: `production/iteration-7` (base `production/iteration-6`, clean at start).
Live reference: https://scan.illek.ie (read-only checks only; no deploy).

## Audience, job, primary path

VulnScope serves site owners, developers, MSP analysts, and REST/MCP agents
that need a bounded, evidence-backed view of a public website's unauthenticated
external exposure. Primary path: enter URL, confirm authorisation, watch
progress, read/share the graded report. Trust boundary: target-controlled
content is attacker input; outbound scanning is budgeted and fail-closed;
reports are public bearer links. Current release risks: production still serves
a pre-round-2 build (deployment lag noted since iteration 4); abuse backstop
(WAF/Turnstile) remains dashboard-side.

## Confirmed findings (reproduced before fixing)

1. **Takeover coverage lies after certificate-transparency provider HTTP
   failures.** `checkSubdomainTakeover` returns `[]` when crt.sh answers with a
   non-2xx status (`if (!crtResponse.ok) return results`) or when its JSON is
   malformed, both inside a swallowing try/catch. Neither path touches phase
   statistics, so `phaseCoverage` sees zero counters and writes
   `coverage.takeover = measured`. A scan during a crt.sh incident therefore
   publishes "Subdomain takeover checks completed for 0 subdomain(s)" plus a
   clean coverage row, contradicting ARCHITECTURE.md's failure model ("An
   individual optional phase failure is preserved in the coverage model") and
   the data-honesty contract that underpins grading. Reproduced with a mocked
   502 from crt.sh: pre-fix coverage.takeover.status is "measured"
   (test/takeover-coverage.test.ts fails). Transport failures were already
   honest (infrastructureFetch counts them as failed).
2. **Progress UI lights stages out of order and leaves phases unmapped.**
   Backend emission order is validated/dns/fetch/ssl, headers/cookies,
   fingerprint, paths, cors/secrets/wordpress/methods/takeover, complete.
   `STAGE_MAP` maps fingerprint to node 3 and headers to node 1, so the live
   route jumps RECON → FINGERPRINT → HEADERS → PATHS; secrets, wordpress, and
   methods map to nothing. The labelled pipeline order misrepresents what runs
   when.
3. **Mobile URL input triggers iOS auto-zoom.** At ≤620px the input font-size
   drops to 14px; Safari focuses-zoom any input under 16px, jolting the layout
   during the primary action on 390px phones.
4. **MCP tool errors lack REST parity for internal faults.** The MCP execute
   callback surfaces raw `error.message` for every thrown error. Unexpected
   internal faults (D1 errors, runtime bugs) reach agent callers verbatim and
   are never logged server-side, while the REST path logs and returns a generic
   message. Observability gap plus minor information disclosure.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Propagate crt.sh non-2xx and malformed-JSON failures out of `checkSubdomainTakeover`; the existing analyzer catch records failed takeover coverage with the provider reason. Legitimate empty CT results stay `measured`. | `api/src/analyzer.ts`, new `api/test/takeover-coverage.test.ts` | Reports no longer claim completed takeover checks after a CT outage; coverage rows say failed and grade accordingly. | Low: failure wording only; per-subdomain logic untouched |
| 2 | Reorder progress nodes to the real pipeline (RECON, HEADERS, FINGERPRINT, PATHS, CORS, REPORT) and extend `STAGE_MAP` so secrets/wordpress/methods advance the CORS node. | `web/index.html`, `web/app.js` | Progress indicators move monotonically and truthfully. | Low |
| 3 | Raise mobile input font-size to 16px. | `web/styles.css` | No focus zoom on iOS at phone widths. | Low |
| 4 | Sanitise MCP scan-tool errors: known caller-facing classes keep their messages; anything else logs `console.error("scan_failed_mcp", ...)` and throws a generic message. Exported helper for tests. | `api/src/index.ts`, `api/test/mcp.test.ts` | Agents get REST-equivalent error semantics; internal faults are observable. | Low |
| 5 | Update safe dev dependencies (`@cloudflare/workers-types` minor, `wrangler` 4.123→4.125 minor). Skip TypeScript 7 / vitest 4 majors: not worth API-migration risk in a readiness pass. | `api/package.json`, lockfile | None direct. | Low |

## Explicit non-goals

- Turnstile/WAF abuse backstop: Cloudflare dashboard access, outside repo.
- DNS TOCTOU residual risk: platform-inherent, documented in THREAT_MODEL.md.
- Observability head sampling change: no volume signal to justify it.
- VulnScanner service-string/UA rename: breaking change for consumers.
- Deployment of https://scan.illek.ie: outside iteration scope.
- Root-level historical docs (PRODUCT_REVIEW.md etc.): unchanged rationale.
- `phaseCoverage` zero-attempt semantics beyond takeover: traced every phase;
  cors/methods/paths/wordpress always attempt ≥1 request or record skips
  before they can fail validation (main-host addresses are cached after the
  DNS phase), and secrets/takeover legitimately measure zero. Only the
  provider-failure path above is reachable dishonesty.

## Verification

- Reproduction test red before fix 1, green after; full suite green.
- `cd api && npm run typecheck && npm test`.
- Browser matrix at 390/768/1440: landing + synthetic report render, keyboard,
  reduced motion, no horizontal overflow; axe-core on landing + report.
- `node scripts/audit-html.mjs https://scan.illek.ie/`.
- Lighthouse against the local build of this branch.
- Live read-only spot checks (health, unknown report 404, HTTP→HTTPS 308).
