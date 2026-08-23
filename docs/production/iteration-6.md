# Production Iteration 6 Plan (2026-08-22)

Iteration 6 of 8 on `production/iteration-6` (base `production/iteration-5`, clean
at start). Five prior rounds fixed the findings recorded in
`/home/koya/ox-reviews-2026-08-22/vuln-scanner.md`; iteration 5 concluded the
local defect list was empty. This round is a fresh senior review of all 17
`api/src` modules, the web frontend, schemas, wrangler vars, and docs, plus a
full verification pass. It found one new root-cause defect that prior rounds
missed because no test exercised a DNS answer containing a CNAME record and no
prior live check scanned an external redirecting target.

## Audience, job, primary path

Unchanged from rounds 1-5: site owners, developers, MSP analysts, and agents run
an authorised, unauthenticated exposure check of one public URL and share an
expiring, evidence-backed report. Primary path: enter URL, confirm authorisation,
watch NDJSON progress, read/share the report. Trust boundary: public bearer-link
reports; every outbound probe fails closed behind one shared budget.

## Confirmed findings (this round)

1. **`resolvePublicHost` rejects any host whose DNS answer contains a CNAME
   record** (`api/src/outbound.ts:440-453`). The function collects
   `answer.data` from *every* record in the A and AAAA DoH answers and then
   requires each collected string to pass `isPublicIp`. Both production
   resolvers (verified live against cloudflare-dns.com and dns.google for
   `www.wikipedia.org`) include the CNAME record itself (type 5) in the JSON
   `Answer` array alongside the address records, so a CNAME target hostname such
   as `dyna.wikimedia.org.` enters the candidate list, fails `isPublicIp`, and
   the resolver throws `OutboundPolicyError("The outbound hostname resolved to
   no confirmed public address.")`.
   Reproduced before fixing by executing `createOutboundContext().resolveHost`
   against mocked DoH responses containing a CNAME+A chain (fails on
   `production/iteration-5`; vitest output captured in the iteration log).
   User impact: `safeFetch` calls `assertPublicHost(..., revalidate = true)` on
   **every redirect hop**, so scanning any target that redirects to a
   CNAME-resolved hostname — including a plain http→https hop on the same
   CNAME-bearing hostname, and apex→www redirects — marks the main fetch failed
   and grades the report INCOMPLETE/failed. The same code path silently breaks
   takeover HTTP probes of resolvable subdomains (subdomains typically resolve
   through CNAMEs). The initial main fetch escapes only because
   `analyzer.ts:113` seeds `outbound.addresses` from answers already filtered to
   A/AAAA types (`addressAnswers`), which is exactly the shape this function
   should have used. Severity: high correctness/reliability defect in the core
   scan path; security posture unaffected (the bug fails closed).
2. **No further code defects found.** Line-level re-review of all 17 `api/src`
   modules, the frontend render paths (all interpolation still routes through
   `escapeHtml`), openapi.yaml/mcp-copilot.yaml, `_headers`, robots, sitemap,
   wrangler vars, schema.sql, and README/ARCHITECTURE/THREAT_MODEL found no new
   correctness, security, privacy, abuse-resistance, accessibility,
   performance, SEO/metadata, or observability issues beyond finding 1 and the
   items already tracked as skipped with rationale in earlier rounds.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Filter DoH answers by record type before IP validation in `resolvePublicHost`: keep `type === "A"` data from the A query and `type === "AAAA"` data from the AAAA query, exactly like `addressAnswers` in the analyzer. Fresh per-hop resolution is preserved, so the DNS-rebinding revalidation defence is unchanged; a CNAME-only answer still yields zero addresses and still fails closed. | `api/src/outbound.ts` | Scans of targets behind www/apex or CDN CNAME redirects complete instead of failing with "resolved to no confirmed public address"; takeover probes of resolvable subdomains can actually reach HTTP. | Low: strictly narrows the candidate set to address records; NXDOMAIN, empty answers, private/reserved addresses, and resolver failures keep failing closed. |
| 2 | Regression tests: (a) unit test that `resolveHost` returns the A records from a CNAME+A DoH answer; (b) end-to-end `safeFetch` redirect test whose second hop requires fresh DoH resolution of a CNAME-bearing host; (c) fail-closed guard kept: a CNAME-only answer (no address records) must still throw. | `api/test/outbound.test.ts` | Locks the fix against regression. | None |

## Explicit non-goals (carried forward with unchanged rationale)

- Turnstile/WAF abuse backstop: outside repo control; requires Cloudflare
  dashboard access.
- DNS TOCTOU between DoH validation and fetch connection: inherent to Workers;
  documented accepted residual risk in THREAT_MODEL.md.
- Observability head sampling rate: keep 1.0 until volume justifies lowering.
- `VulnScanner` service-string rename in `/api/health` and the UA product
  token: breaking change for consumers; stable across all rounds.
- Redeployment of https://scan.illek.ie: not permitted this iteration;
  tracked as release operations. Production still serves the pre-round-2
  build, so the next deploy ships rounds 1-6 together.

## Verification

- Reproduction first: `resolveHost` on a CNAME+A fixture must fail pre-fix and
  pass post-fix.
- `cd api && npm run typecheck` and `npm test` (baseline before changes:
  clean, 20 files, 174 tests).
- New regression tests listed above must pass; full suite must stay green.
- Live read-only confirmation that both production resolvers return CNAME
  records inside `Answer` (already done during review, repeated if needed).
- `node --check` on web JS files (unchanged this round; regression guard).
- Browser render + keyboard/a11y spot suite at 390/768/1440 px on the local
  page build (regression guard; no UI changes intended).
- `scripts/audit-html.mjs` against the canonical live URL; Lighthouse against
  the local build of this branch.
- Live read-only spot checks: `/api/health`, `/api/v2`, unknown report 404,
  HTTP→HTTPS 308, security headers.
