# Production iteration 9 plan

Branch: `production/iteration-8` (continuing; clean at start, tip `d81779a`).
Live reference: https://scan.illek.ie (read-only checks only; no deploy).

## Scope of this round

A fresh deep review of the iteration-8 tree: full source read of every
`api/src` module and the web client, live checks against production (health,
static headers, NDJSON scan stream, MCP tools/list, 404 contracts), a local
`wrangler dev --local` session for end-to-end probing, and the existing check
suite as baseline (typecheck clean, 189 tests green).

## Confirmed findings (reproduced before fixing)

1. **Local development was impossible end to end.** `wrangler dev` emulates
   the `scan.illek.ie` custom-domain host over plain HTTP and rewrites request
   URLs, `Origin` headers, and redirect `Location`s to it. Three separate
   defects compounded:
   - The unconditional HTTP→HTTPS entry redirect in `api/src/index.ts` saw
     `http://scan.illek.ie/...`, found a non-local hostname, and returned 308
     to an HTTPS URL that workerd translated back to plain HTTP — an infinite
     loop for every local request, asset or API.
   - The localhost CORS allowlist entry could never match because browsers'
     origins arrive rewritten to `http://scan.illek.ie`; every API call from
     the locally served page was rejected with 403 "Origin not allowed".
   - `web/config.js` hardcoded `API_BASE: "https://scan.illek.ie"`, so even
     with the server fixed, the page sent every scan cross-origin from any
     other serving origin.
   Reproduced with curl against `wrangler dev`: health/root/POST all 308-looped;
   debug logging showed `request.url = http://scan.illek.ie/api/health` and the
   rewritten `Origin`.
2. **DNSSEC RRSIG records bloated stored DNS evidence.** DNS queries send
   `do=true` to obtain the AD flag; on signed zones resolvers attach an RRSIG
   (type 46) signature record to every answer. These base64 blobs were mapped
   into each report's `answers` arrays — kilobytes of noise per query in every
   stored and shared report. Reproduced in a live scan of `example.com`
   (`dns answer types: A,46,AAAA,NS`).
3. **Budget-starved takeover rows implied verified negatives.** When the
   request budget ran out mid-takeover (or both resolvers failed), per-subdomain
   DNS queries returned empty results and each row fell through to evidence
   "No takeover indicators found" — presenting unexecuted checks as clean
   results in a publicly shareable report. Same false-honesty class the project
   eliminated for takeover coverage generally in iteration 8.
4. **Corrupt report rows surfaced scan-failure copy on a read endpoint.**
   `loadReport` JSON.parse errors fell into the generic 500 path answering a
   GET /api/scans/:id with "The scan could not be completed. Please try again."
   Shape-invalid rows already read as 404 via `upgradeStoredReport`;
   syntax-invalid rows took a worse route.

## Changes made

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Gate the HTTPS entry redirect on `ENVIRONMENT !== "development"`; ship `api/.dev.vars` (development environment + emulated-origin allowlist) so `wrangler dev` works out of the box; document the emulation behaviour where it bites. Regression test for dev-mode plain HTTP. | `api/src/index.ts`, `api/.dev.vars`, `api/wrangler.toml`, `api/test/redirects.test.ts`, README local-dev section | Local development restored: page, form, scans, reports all work at http://localhost:8788. Production guard untouched (var absent → redirect stays). | Low |
| 2 | Filter type 46 (RRSIG) answers at mapping time; DNSSEC evidence remains via `authenticatedData`. Regression test with a signed-zone answer payload. | `api/src/dns.ts`, `api/test/dns.test.ts` | Every report stops carrying kilobytes of signature blobs; no information loss. | Low |
| 3 | Takeover rows whose resolver state is incomplete now record "DNS verification was incomplete" with the underlying error instead of the clean-result fallback; confirmed NXDOMAIN dangling-record hints unchanged. Tests for both paths. | `api/src/analyzer.ts`, `api/test/takeover-coverage.test.ts` | Shared reports stop claiming checks that never ran. | Low |
| 4 | Syntax-corrupt report rows return null → 404 like shape-invalid rows. | `api/src/index.ts` | Honest read-endpoint contract. | Trivial |
| 5 | `API_BASE` becomes relative same-origin. | `web/config.js` | Page and API share one origin in every environment; removes a cross-origin 403 class. | Low |

## Verification

- `cd api && npm run typecheck && npm test` (193 tests green after changes).
- Local E2E against `wrangler dev --local`: health, static assets, CORS
  round-trip, HEAD /, unknown-report 404, invalid-input 400, self-scan NDJSON
  boundary, private-target block, full probePaths+takeover scan, report
  retrieval + export headers, recent-scan cache hit, MCP initialize/tools/list,
  scheduled trigger.
- Production read-only spot checks before/after: HTTP→HTTPS 308, security
  headers incl. CSP from `_headers`, health, API index, openapi.yaml,
  robots/sitemap, unknown-path 404, MCP tools/list, full NDJSON scan stream.

## Explicit non-goals

- crt.sh availability: currently returning 502s externally; coverage records
  honest failed/unavailable state by design. A bounded retry is a possible
  future tweak but masks outages and adds latency; not done.
- Rate-limit headers on successful responses: 429 already carries the full
  RateLimit draft headers; threading counts through createScan for a nice-to-have
  was judged churn.
- Frontend DNS query-failure rendering (dead `status >= 400` condition): DNS
  status codes are not HTTP codes, but the affected state (some resolver queries
  failing while addresses resolved) is already surfaced truthfully in the
  coverage table.
- MCP outputSchema strictness vs legacy migrated reports carrying extra fields:
  harmless for current clients.
- Deployment of https://scan.illek.ie: outside scope; publishing stays with the
  human.
