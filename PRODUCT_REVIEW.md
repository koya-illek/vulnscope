# VulnScope product review

Review date: 2026-08-14  
Repository: `/home/koya/vuln-scanner`  
Production: <https://scan.illek.ie>

This is a review of the repository, the deployed site and its public API/MCP surfaces. No product code, configuration, deployment, DNS or remote D1 data was changed. I did not run a production scan because a scan writes a report, consumes rate-limit state and makes outbound probes. A deliberately harmless missing-report request and MCP initialization did demonstrate that the deployment writes rate-limit state for those paths; that behavior is called out below.

## Executive verdict

VulnScope is a polished, unusually focused technical beta. Its strongest idea is a low-friction external exposure snapshot that can be consumed by a human or an AI agent, with a bounded unauthenticated probe set and explicit coverage language. The custom-domain deployment is healthy, the static UI is responsive, the REST and MCP entry points are live, and the local test suite is green.

It is not ready to be marketed as a dependable vulnerability scanner. The safety boundary is incomplete around redirects and target-controlled JavaScript URLs. Public reports can expose raw `Set-Cookie` values and signed query strings. The default probe budget can exceed a Workers Free invocation limit, while several expensive or unbounded probes have no phase timeout or consistent body limit. Failed optional checks are commonly reported as measured, so a clean grade can mean “the check did not run.” The path and takeover heuristics can produce serious false positives. These are trust and security issues, rather than cosmetic polish items.

My verdict is: keep the product direction, pause feature expansion, and make the scanner boundary, evidence semantics, privacy model and agent contracts reliable. With those changes, VulnScope could occupy a useful niche as an “external exposure evidence report for humans and agents.” Without them, the product risks giving an attractive but overconfident answer to exactly the users who need security evidence to be precise.

## Evidence and tests run

### Local source and configuration

- The Worker entry point is `api/src/index.ts`, with analyzer modules for DNS, CT, headers, cookies, paths, CORS, secrets, WordPress and methods. Static assets are served from `web/` through the Worker.
- `api/wrangler.toml` uses the custom route `scan.illek.ie`, `workers_dev = false`, `preview_urls = false`, an assets binding, a D1 binding and a daily cron. There are no `pages.dev` or `workers.dev` deployment targets in the production configuration.
- The configured production variables advertise 14-day retention, a daily scan limit of 50, an MCP daily limit of 200 and a report daily limit of 120. The account plan was not assumed.
- The directory has no `.git` metadata. `git status --short --branch` therefore fails with “not a git repository,” so source provenance cannot be checked locally.

### Tests and build checks

- `npm test` in `api`: 13 test files, 129 tests passed.
- `npm run typecheck`: passed.
- `npm audit --audit-level=moderate` and the production-only audit: zero reported vulnerabilities.
- `npx wrangler deploy --dry-run`: passed. The bundle was 274.92 KiB before gzip, 76.24 KiB gzip, with D1 and assets bindings present.
- `web/openapi.yaml` and `web/mcp-copilot.yaml` parse as YAML.
- Local and live hashes for `index.html` and the OpenAPI and MCP connector files matched during review.
- The test suite is primarily unit and fixture based. It does not exercise a real redirect-to-private target, DNS rebinding, a large response, real D1 lifecycle behavior, a full Worker invocation budget, or a production-like scan.

### Live production

- `https://scan.illek.ie/` returned HTTP 200. HTTP redirects to HTTPS with 308.
- The live response had HSTS with preload, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a restrictive Permissions Policy and a strict Referrer Policy.
- `/api`, `/api/`, `/api/v2` and `/api/health` returned the documented metadata or health JSON. Health reported version `2.0.0`, production environment and rate-limit protection.
- An evil-origin CORS preflight returned HTTP 403. The configured site and localhost development origin were accepted.
- `/mcp` and `/mcp/v2` accepted JSON-RPC initialization and returned protocol version `2025-11-25`, server `vulnscope` version `2.0.0`. GET returned 405 with an Allow header.
- The live deployment history contained several entries with `Source Unknown`, no message and no release tag. This makes rollback and incident attribution weaker than they should be.
- Desktop 1440px and mobile 390px browser checks found no horizontal overflow. A mocked report route rendered at both widths. The live mobile layout stacked correctly, although several mono labels and filters are small and low contrast.
- No live scan was run. A GET for `/api/scans/nope` returned 404, but the route had already consumed report rate-limit state. MCP initialization similarly consumes MCP rate-limit state. This is evidence of a stateful read/handshake path, not a production scan result.

Cloudflare documents 50 subrequests per invocation on Workers Free, 10,000 on Paid, six simultaneous outgoing connections and a 128 MB Worker memory limit. See [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/). Those limits matter directly to the default scan design.

## Findings

Severity reflects product risk and evidence confidence. Code references are relative to the repository and line numbers refer to the reviewed source snapshot.

### Critical

#### C1. Public reports can disclose session or tracking secrets

`api/src/cookies.ts:18-53` puts the complete raw `Set-Cookie` header into finding evidence. That includes cookie values, not only the name and flags. Reports are deliberately public by ID, are cached with `Cache-Control: public, max-age=60` in `api/src/index.ts:126-139`, and are retained for up to 14 days. A target can therefore cause a public report to contain a session token, CSRF token, signed state value or other sensitive cookie.

The secret scanner also stores the complete JavaScript bundle URL in `api/src/secrets.ts:55` and `api/src/analyzer.ts:497-523`. Query strings often contain signed URLs or access tokens. The requested target URL is redacted by `redactUrlForStorage`, but bundle source URLs are not.

Immediate remedy: never store cookie values; retain only names, attributes and a redacted evidence token. Strip query and fragment components from every stored script source, and consider making reports private by default with an explicit, short-lived share token. Review Cloudflare observability and cache logs for the same data.

#### C2. Redirect and subresource fetches do not preserve the SSRF boundary

`api/src/security.ts` validates the initial URL and `api/src/analyzer.ts:76-84` checks its DNS answer, but the main request at `api/src/analyzer.ts:91-115` uses `redirect: "follow"`. The final destination is not resolved, checked or recorded. A public target can redirect the Worker to a private address, a loopback address, a cloud metadata address or another host with a different trust boundary.

The same issue occurs in the target-controlled JavaScript bundle fetches at `api/src/analyzer.ts:497-523`, where absolute `http` and `https` sources are accepted and redirects are followed. WordPress checks in `api/src/wordpress.ts` also use default-follow fetches in several paths. Takeover checks make requests to names obtained from `crt.sh` without sufficiently constraining them to the target's registrable domain.

The OpenAPI description at `web/openapi.yaml:17-22` claims that unsafe redirect targets are blocked. That claim is stronger than the implementation. This is the most important technical defect because the product presents itself as safe-by-default while its own target-controlled response can widen the outbound request boundary.

Immediate remedy: centralize all outbound requests in a `safeFetch` policy. Use manual redirects, cap hops, resolve and validate every hop, reject private and special-use IPs including IPv6, prevent cross-host navigation unless explicitly allowed, and record the final URL and redirect chain. Apply the same policy to scripts, WordPress, takeover and CORS probes. Add integration tests with redirects to loopback, RFC1918, link-local, IPv6 special-use and DNS-rebinding fixtures.

### High

#### H1. The default scan can exceed the Workers Free subrequest budget

The default sensitive-path list contains 65 entries (`api/src/paths.ts:5-81`). Before optional WordPress and takeover work, a scan can use DNS lookups, the main request, CT, 65 path requests, CORS requests, method probes and up to 10 JavaScript bundle fetches. A conservative count is about 86 outbound subrequests, before retries or redirects. On Workers Free, that exceeds the documented 50-subrequest limit. The 65 path probes also launch concurrently even though Workers documents six simultaneous outgoing connections.

The optional takeover path can add up to 10 certificate names, multiple DNS queries and HTTP requests. Its UI copy says it adds about 10 seconds, but the worst-case work is materially larger. There is no explicit analyzer-wide deadline or resource budget.

Immediate remedy: calculate a hard per-scan budget, make the expensive catalogue and takeover checks explicitly opt-in or paid-tier work, schedule fetches with bounded concurrency, cap redirects and retries, and fail with a clear partial result when the budget is exhausted. Document the account-plan assumption in the deployment configuration.

#### H2. Failed checks are often marked measured, allowing overconfident grades

Several optional probes swallow errors and still emit coverage as measured. Examples include CORS (`api/src/cors.ts:82-110`), methods (`api/src/methods.ts`), secrets and JavaScript bundles (`api/src/analyzer.ts:193-203`, `492-529`), WordPress and takeover checks. Path probe errors are swallowed at `api/src/paths.ts:181-183`. The report is marked partial only for a narrow set of blocking gaps at `api/src/analyzer.ts:243-275`, mainly the main fetch and headers. A requested phase can fail completely while the overall grade remains A or the status remains complete.

This conflicts with the product's “evidence-backed” promise. “No finding” and “not tested” must be separate states.

Immediate remedy: give every phase `success`, `failed`, `unavailable`, `skipped` or `partial` status, include attempts and failure reasons, and make report status and grade depend on requested coverage. Show a prominent coverage warning on the report and in MCP output.

#### H3. Sensitive-path heuristics have a deterministic false-positive bug

`api/src/paths.ts:57` contains `/.dockerenv` with an empty signature. Matching uses `bodyLower.includes(signature)` in `probeSinglePath`; an empty string always matches. Any qualifying HTTP 200 response can therefore be reported as exposed `.dockerenv`, with empty matched-signature evidence. Other signatures are dangerously weak single tokens such as `key` or `SECRET`, and a one-token match is enough because `SIGNATURE_MATCH_THRESHOLD` is 1.

The probe only compares a short body with a homepage soft-404 heuristic. It does not require a relevant content type, a strong multi-token signature or a stable response fingerprint. This can produce critical or high findings on normal application pages.

Immediate remedy: remove empty signatures, require multiple independent markers or exact structured formats, add content-type and length checks, improve soft-404 detection and create a regression corpus of real false positives. A sensitive path should never become critical from a generic word alone.

#### H4. Dangling CNAME logic can produce false critical takeover findings

`api/src/analyzer.ts:365-419` treats a CNAME with no A answers as a vulnerable takeover, while ignoring AAAA answers, resolver failures and provider-specific ownership states. It also does not adequately constrain names extracted from certificate transparency data to the target's registrable domain. A DNS configuration can therefore produce a critical finding even when the host is live over IPv6 or the DNS query was incomplete.

Immediate remedy: distinguish NXDOMAIN, NODATA, SERVFAIL and timeout; check A and AAAA; validate the registrable-domain boundary; require a provider-specific signature and an independently confirmed unclaimed service before using critical severity. Otherwise report “possible dangling DNS” with low confidence.

#### H5. MCP request size is checked after buffering the whole body

`api/src/mcp.ts:4,114-120` defines a 16 KiB limit but calls `request.arrayBuffer()` before checking it. A large unauthenticated request can therefore be buffered up to the platform request limit before rejection. This is an avoidable memory and abuse risk on a public endpoint.

Immediate remedy: reject from `Content-Length` when available and read through a capped stream. Apply the same limit and timeout to every public JSON endpoint.

#### H6. The public unauthenticated scanner has weak abuse and consent controls

The UI's unauthenticated checkbox is informational. `/api/scans` and MCP accept scans without proof of control, and the daily limits are IP-scoped D1 counters. IP rotation makes those limits easy to evade, while every scan can generate a significant outbound request load against an arbitrary public target. There is no API key, ownership token, abuse-reporting flow or visible acceptable-use boundary in the API contract.

This may be an intentional open beta, but it is a material operational and legal risk. “Unauthenticated” should describe the target, not remove ownership and abuse controls around use of the service.

Immediate remedy: add an explicit beta access mechanism, per-key quotas and abuse reporting, or make the open surface much smaller. Enforce the same consent/limit policy in REST and MCP, rather than relying on a UI checkbox.

### Medium

#### M1. OpenAPI and implementation disagree about streaming

`web/openapi.yaml:45-55` advertises `text/event-stream`, while the implementation at `api/src/index.ts:252-284` returns `application/x-ndjson; charset=utf-8`. The MCP connector similarly advertises JSON and event-stream output, while `api/src/mcp.ts` returns a completed JSON-RPC response and does not expose progress events. Several schemas are loose objects with `additionalProperties: true`, which makes agent integration less reliable.

Either implement a real event stream with documented events and reconnect behavior, or describe the synchronous/NDJSON contract accurately. Add contract tests that import the OpenAPI and MCP definitions and exercise each declared content type.

#### M2. Progress reporting is inaccurate and can regress

`web/app.js:21-29` maps only a small set of aggregate stages. The analyzer emits fingerprint work before headers (`api/src/analyzer.ts:128-141`), while the UI maps those events to stages that can move from 3 back to 1. DNS, CT, cookies, secrets, WordPress and methods are omitted from the visible progress model. The result is attractive progress feedback that does not describe the actual work.

Use phase IDs emitted by the backend, preserve monotonic progress, and render skipped, failed and unavailable phases distinctly.

#### M3. Several response bodies are not consistently bounded

The main response and path probes have explicit limits, but takeover responses, CT handling, TRACE response text and multiple WordPress fetches use unbounded `text()` calls. Cloudflare documents a 128 MB Worker memory limit. A public target can return a very large response and increase memory pressure or terminate a scan.

Create one bounded body reader with content-length checks, truncation metadata and a maximum per phase. Do not silently convert truncation or read failures into measured coverage.

#### M4. Header and DNS findings are shallow in ways that affect trust

`api/src/headers-audit.ts` accepts any present X-Frame-Options and any value containing `nosniff`, misses wildcard forms such as `https://*` in CSP, and treats the deprecated absence of `X-XSS-Protection` as an informational observation. HSTS validation does not enforce a useful `max-age` or includeSubDomains policy. DNSSEC is effectively true if any queried record carries the authenticated-data bit, rather than specifically establishing the target's relevant records. Only Cloudflare DoH is used in the current inspection path even though a Google endpoint constant exists.

These should be expressed as precise observations with standards-aware severity. Remove deprecated noise from the grade.

#### M5. Secret scanning has incomplete scope and duplicate results

`api/src/analyzer.ts:497-523` scans only up to 10 external script URLs and ignores inline scripts. Bundles are capped at 512 KB without a clear truncation finding. `api/src/secrets.ts` has overlapping patterns, so a single Google-style key can receive duplicate findings. Generic patterns increase false positives, while query-bearing source URLs leak context as described in C1.

Make scope and truncation explicit, deduplicate by normalized evidence, scan inline content only with a deliberate size limit, and use confidence labels rather than treating every regex hit as a credential.

#### M6. Rate-limit accounting has surprising write side effects

`api/src/index.ts:120-121` applies the report limit to every GET beginning `/api/scans/` before validating the report ID. Invalid report IDs consume quota. `api/src/index.ts:57` applies MCP limits before method and JSON-RPC validation, so unsupported or malformed requests consume quota as well. Responses do not provide a useful remaining count or reset timestamp, and `Retry-After: 3600` is a fixed approximation.

Validate route and method before charging a counter, separate abuse throttling from successful work quotas, and return standards-based reset information. Avoid counting health, metadata and protocol negotiation unless that is an intentional abuse policy.

#### M7. Accessibility and narrow-screen readability need another pass

The desktop and 390px layouts have no horizontal overflow, and the skip link works. The native methodology dialog has a heading but no `aria-labelledby` or `aria-describedby` binding in `web/index.html:248-260`. Inputs reset their outline in `web/styles.css:137-145`, with no custom `:focus-visible` treatment; the observed default focus outline is black on the dark surface. Report filters and footer controls use small mono text and compact hit areas. These issues make keyboard navigation and the dense mobile report harder to use than the visual polish suggests.

Give the dialog an accessible name and description, add a high-contrast focus-visible style, preserve visible focus on the URL field, and bring all interactive controls to comfortable touch targets. Keep the successful no-overflow responsive behavior.

#### M8. Report UX hides evidence and can retain stale filter state

`web/app.js:374-408` renders exposed paths mainly as path, status and severity, omitting the evidence that would let a reviewer validate a low or informational observation. `reset()` at `web/app.js:465-474` does not reset `state.activeFilter`, so a new scan can inherit a previous severity filter and hide findings. The report ID, creation time and expiry are not prominent in the report view, despite public share links and 14-day retention.

Show per-phase status, concise evidence and truncation indicators, reset all view state for a new scan, and expose report identity and expiry beside the share/export controls.

#### M9. Deployment and maintenance provenance are weak

The source folder has no local Git metadata. Wrangler deployment history entries are tagless and show unknown source and no release message. The README is only a short endpoint list and does not document migrations, rate limits, threat model, plan assumptions, privacy boundaries, local D1 setup, or release procedure. The passing tests do not cover the most important safety regressions.

Restore repository and release provenance, add CI gates for typecheck/tests/OpenAPI/MCP contract checks, create staging configuration, and add integration fixtures for redirects, body limits, D1 retention and error coverage.

#### M10. The product's visible claim is broader than its evidence model

The hero calls the result a scan for exposed files, security headers, certificate evidence, CORS and takeover risk. CT data is historical and does not prove the active certificate (`api/src/ssl.ts` explicitly says this), there is no CVE or current software inventory feed, no browser execution or authenticated view, and no exploit validation. The result is a useful recon snapshot, but “vulnerability scanner” implies more coverage than the implementation can support.

Rename or qualify the promise around external exposure and evidence. Keep the CT limitation visible in the report, as that is one of the product's better trust decisions.

### Low

#### L1. Localhost production CORS allowance should be deliberate

`ALLOWED_ORIGINS` includes `http://localhost:8788`. This is useful for local development but should be separated into a development environment so the production policy is easier to audit.

#### L2. The source contains dead or noisy surface area

The `authorityKeyIdentifier` field is always null in the reviewed SSL output, and hidden `.eyebrow` markup remains in the UI while its CSS sets `display: none`. These do not affect security, but removing dead fields and unused presentation vocabulary would make the product easier to maintain. The deprecated X-XSS-Protection observation is also noisy and should not influence a user-facing grade.

#### L3. API security headers are less complete than document headers

HTML received the strong CSP and framing policy. JSON API responses received the general security headers but no CSP, which is usually acceptable for JSON but should be an explicit response policy. Add response tests so future route changes cannot accidentally serve HTML with a weaker policy.

#### L4. Small product details reduce perceived finish

There is no obvious favicon or social preview treatment in the reviewed static page. These are low value compared with the scanner fixes and should wait until trust and accessibility work is complete.

## Product and market assessment

### What is genuinely good

- The product is technical rather than a generic sales dashboard. It focuses on a bounded external surface and uses GET, OPTIONS and TRACE rather than exploit payloads or destructive methods.
- The Cloudflare edge vantage is useful for checking what a public service presents from outside its network.
- A shareable report ID, JSON export, REST endpoint and MCP endpoint make the output composable.
- The UI communicates a few important limits: unauthenticated scope, private/local target blocking, optional expensive checks, and the distinction between HTTP evidence and CT/TLS evidence.
- The deployment is lean and avoids the forbidden platform hosts. The static asset footprint and dry-run bundle are small.
- The strongest potential differentiation is “evidence snapshots designed for agents,” especially if every observation has a precise source, phase status, confidence and expiry.

### Where it sits in the market

The adjacent space is crowded: Mozilla Observatory and SecurityHeaders cover HTTP posture, SSL Labs covers TLS, urlscan covers public web observations, OWASP ZAP and Nuclei cover deeper testing, and commercial attack-surface products provide inventory, history and ownership workflows. VulnScope does not currently win on breadth, CVE intelligence, authenticated testing, browser behavior, asset inventory or remediation workflow.

It can win on a narrower promise: a safe, fast, public external exposure preflight with a stable machine-readable evidence contract. MCP support is a useful distribution advantage, but only if its schemas and streaming claims are correct. Open access is useful for trials, but public unauthenticated scanning without ownership and abuse controls is a liability rather than a differentiator.

### Features to keep, add or remove

Keep the bounded probe philosophy, CT-as-separate-evidence presentation, JSON export, shareable report concept and agent access.

Add safeFetch enforcement, privacy redaction, phase-level confidence/status, budget controls, ownership/abuse controls, exact API contracts, scan history for an owner, and a small regression corpus of known targets and false positives.

De-emphasize or make explicitly optional the sensitive-path catalogue, WordPress heuristics and takeover check until they have better evidence semantics and resource limits. Do not call CT-only observations active certificate validation. Do not imply CVE or exploitability coverage that is not present.

## Recommended implementation plan, ordered by impact and effort

1. **P0, high impact and high effort: repair the outbound safety boundary.** Build one manual-redirect, bounded, public-IP-checked fetch layer. Validate every redirect and target-controlled subresource, enforce same-host or explicit registrable-domain policy, cap hops and record the final chain. Add integration tests for private redirects, IPv6, DNS rebinding, cross-host script URLs and takeover names.

2. **P0, high impact and medium effort: make reports safe to publish.** Remove cookie values and query-bearing source URLs from evidence. Revisit public caching, use private/no-store reports by default or explicit bearer share tokens, add deletion/expiry controls and update the privacy page. Audit logs and analytics for target-provided sensitive content.

3. **P0, high impact and medium effort: enforce a real resource budget.** Bound every body read, add per-phase and overall deadlines, limit concurrency to a deliberate value, count subrequests and make the default path set fit the documented Workers plan. Gate takeover and other expensive checks with a clear partial result.

4. **P1, high impact and medium effort: correct evidence semantics.** Represent phase success, failure, unavailable, skipped and partial states. Make grade and overall status coverage-aware. Fix the empty `.dockerenv` signature, weak token matching, soft-404 handling and takeover DNS state model. Add confidence and truncation fields.

5. **P1, medium-high impact and medium effort: make REST, OpenAPI, MCP and Copilot contracts exact.** Align NDJSON versus SSE, publish complete schemas, mark the read-only tool correctly, stream progress only if it is implemented, cap MCP request reads before buffering and add contract/import tests.

6. **P1, high impact and medium effort: control open-service abuse.** Add API keys, an allowlist or ownership/consent token, per-key quotas, abuse reporting and meaningful rate-limit headers. Charge counters only after valid route and request validation. Apply one policy across browser, REST and MCP.

7. **P1, medium impact and low-medium effort: finish accessibility and report UX.** Add dialog labels, focus-visible styles, touch-sized controls, a filter reset, report ID/expiry, evidence snippets and phase failure visibility. Replace the inaccurate progress map with backend phase IDs.

8. **P2, medium impact and ongoing effort: expand coverage only after the boundary is trusted.** Add current standards or CVE sources only when provenance and update behavior are clear. Consider inline scripts, multi-origin CORS and an authenticated mode as separate, consented products. Build a regression corpus before adding more signatures.

9. **P2, medium impact and low effort: restore engineering provenance.** Put the source in Git, tag deployments, separate staging and production variables, document D1 migrations and limits, and make CI run typecheck, tests, contract validation, dry-run deployment and browser checks.

## Explicit do-not-implement list

- Do not add exploit payloads, injection tests, authentication bypasses, form submission or destructive HTTP methods.
- Do not broaden this into arbitrary crawling, port scanning, metadata probing or credential collection while it remains open and unauthenticated.
- Do not add a larger sensitive-path catalogue before fixing safeFetch, subrequest budgets, body limits and false-positive evidence.
- Do not claim active TLS validation, certificate expiry, CVE coverage or exploitability from CT, headers and regex heuristics alone.
- Do not store user credentials, session cookies, API keys or raw response bodies in public reports.
- Do not add a generic dashboard, lead funnel or CRM layer. The technical agent-ready workflow is the product's credible center.
- Do not label a dangling CNAME critical without AAAA, resolver-state, provider-signature and ownership evidence.
- Do not add more connector formats until the existing OpenAPI, NDJSON and MCP contracts are accurate and tested.
- Do not default expensive takeover and path probes, or keep an open beta without a credible abuse and consent boundary.

## Bottom line

VulnScope has a clear technical character and a viable narrow product thesis. The current implementation is a strong prototype and a useful internal tool, but the public security claims outpace the safety and evidence guarantees. Fix the outbound request policy, public-report privacy, resource accounting and coverage semantics before adding breadth. Those fixes would make the existing product more valuable and more defensible than another collection of shallow security checks.
