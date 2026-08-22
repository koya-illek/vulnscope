# VulnScope implementation report

Date: 2026-08-15

## Outcome

The approved VulnScope safety and evidence work is implemented in this repo.
The service remains an unauthenticated, limited-testing beta. No deployment,
remote D1 mutation, DNS mutation, or unrelated repository change was made.

## Implemented

- Added one fail-closed outbound policy for target fetches, redirects, scripts,
  WordPress checks, CORS, methods, and takeover HTTP checks. It validates HTTP
  and HTTPS only, rejects credentials and non-standard ports, checks public A
  and AAAA answers, rechecks redirect hops, limits redirect depth, enforces a
  same-host boundary by default, and records a redacted redirect chain.
- Added request-wide controls: 46 outbound requests, six concurrent target
  connections, a 25-second deadline, a two MiB aggregate response-body budget,
  bounded phase bodies, truncation accounting, and phase error accounting.
  Body reservations remain safe when phase reads run concurrently.
- Made sensitive path probing opt-in and takeover probing opt-in. Path probes
  use a bounded catalogue, content-type checks, multi-marker or structured
  matching, improved soft-404 handling, and explicit truncation evidence.
- Removed the empty `.dockerenv` match. Takeover checks now filter CT names to
  the target registrable domain, query A and AAAA, distinguish resolver states,
  require provider-specific HTTP signatures for a high-confidence finding, and
  expose confidence and resolver state.
- Removed cookie values from findings. Stored requested, script, redirect, and
  URL-bearing evidence is redacted for query, fragment, credential, and
  reporting-endpoint material. Legacy report URLs receive the same treatment.
  Report and export responses are private and `no-store`; bearer-link warning,
  expiry, ID, creation, and budget metadata are visible in the report UI.
- Added explicit phase statuses and counters for measured, failed, unavailable,
  skipped, and partial work. Requested failed or partial optional phases block
  a clean grade. Progress events now carry a phase and monotonic percentage.
- Bounded REST and MCP request bodies before JSON parsing, validated JSON-RPC
  IDs and arguments, kept MCP output as JSON-RPC, and aligned the REST stream
  contract with newline-delimited JSON. OpenAPI and Copilot descriptions now
  describe the implemented transport and exact coverage and outbound shapes.
- Removed quota writes from valid report reads and MCP negotiation, discovery,
  and notifications. Scan quota charging happens after route, content type,
  body, JSON, and URL validation. Rate-limit failures include limit, remaining,
  reset, and retry headers.
- Improved header semantics, CT-only certificate language, evidence display,
  path evidence rows, takeover confidence display, filter reset, focus-visible
  styles, dialog labels, touch-sized controls, and report privacy copy.
- Added [THREAT_MODEL.md](./THREAT_MODEL.md), deployment budget variables, and
  implementation regression coverage for outbound redirects and rebinding,
  body limits, cookie and query redaction, quota side effects, coverage grades,
  and WordPress author-query redaction.

## Verification

All commands below were run after the final source changes.

- `cd api && npm test`: 16 test files passed, 138 tests passed.
- `cd api && npm run typecheck`: passed.
- `cd api && npx wrangler deploy --dry-run --outdir /tmp/vulnscope-worker-dry-run-final`:
  passed. Wrangler read 10 assets, reported the D1 and assets bindings, and
  exited without deployment. Final bundle: 305.71 KiB upload, 83.29 KiB gzip.
- `node --check web/app.js && node --check web/report-view.js`: passed.
- No browser automation or live production smoke was run in this repo because
  it contains no Playwright/browser test harness and deployment was explicitly
  out of scope. The dry-run did not contact or mutate the production service.
- OpenAPI and Copilot YAML were reviewed for transport and schema alignment.
  A YAML parser dependency is not present in this repo, so parser/import
  validation remains an external gate.

## Remaining external or lower-priority gates

- Keep the open beta limited while monitoring abuse. Mandatory API keys,
  ownership challenges, per-key quotas, and a dedicated abuse-reporting flow
  remain deferred by the approved open-testing decision.
- Production validation remains to be run separately: HTTPS redirect, health,
  REST and NDJSON smoke, MCP initialize/tools/list, report expiry, cache
  headers, D1 retention cleanup, and live private-target redirect fixtures.
- YAML parser/import contract tests, full browser checks at desktop and 390px,
  and CI integration are still external gates. The repo has no git metadata, so
  source revision tags and repository provenance cannot be added here.
- CVE feeds, authenticated views, inline-script expansion, browser execution,
  report history, monitoring, ownership workflows, and broader path coverage
  remain deferred until the evidence boundary and analyst demand justify them.
- Successful-response remaining-quota headers and a separate abuse-throttle
  policy can be refined in a follow-up without changing the current safety
  boundary.

## Files touched

Only files in `/home/koya/vuln-scanner` were touched:

- `README.md`
- `IMPLEMENTATION_REPORT.md`
- `THREAT_MODEL.md`
- `api/src/analyzer.ts`
- `api/src/cookies.ts`
- `api/src/cors.ts`
- `api/src/dns.ts`
- `api/src/headers-audit.ts`
- `api/src/index.ts`
- `api/src/mcp.ts`
- `api/src/methods.ts`
- `api/src/outbound.ts`
- `api/src/paths.ts`
- `api/src/scorer.ts`
- `api/src/secrets.ts`
- `api/src/security.ts`
- `api/src/ssl.ts`
- `api/src/types.ts`
- `api/src/wordpress.ts`
- `api/test/coverage-status.test.ts`
- `api/test/outbound.test.ts`
- `api/test/rate-limit-accounting.test.ts`
- `api/test/wordpress.test.ts`
- `api/wrangler.toml`
- `web/app.js`
- `web/index.html`
- `web/mcp-copilot.yaml`
- `web/openapi.yaml`
- `web/report-view.js`
- `web/styles.css`
