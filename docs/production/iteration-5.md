# Production Iteration 5 Plan (2026-08-22)

Iteration 5 of 8 on `production/iteration-5` (base `production/iteration-4`, clean
at start). Four prior rounds fixed the findings from
`/home/koya/ox-reviews-2026-08-22/vuln-scanner.md`. This round is a fresh senior
review of the whole tree (`api/src` 17 files, web frontend, docs, schemas),
read-only live checks against https://scan.illek.ie, and evidence-backed fixes.
Deliberately small: cosmetic churn and speculative features are failure modes.

## Audience, job, primary path

Unchanged from rounds 1-4: site owners, developers, MSP analysts, and agents run
an authorised, unauthenticated exposure check of one public URL and share an
expiring, evidence-backed report. Primary path: enter URL, confirm authorisation,
watch NDJSON progress, read/share the report. Trust boundary: public bearer-link
reports; outbound probes fail closed behind one shared budget.

## Confirmed findings (this round)

1. **Framework/CMS prose false positives remain for Gatsby, Angular,
   Squarespace, and Wix** (`api/src/fingerprint.ts`). Rounds 2 and 4 required
   structural markers for WordPress, Joomla, and Ghost because bare words
   mislabel pages that merely mention them. Four detections kept the old
   pattern and reproduce the same defect today, confirmed by executing
   `fingerprint()` on prose-only fixtures:
   - A page about the novel "The Great Gatsby" reports `Framework: Gatsby`
     (the regex tests bare `gatsby`).
   - A blog article discussing Angular reports `Framework: Angular` (bare
     `angular`).
   - A Squarespace review article reports `CMS: Squarespace` (bare
     `squarespace`; the second alternative made the structural one redundant).
   - Any article linking to `wix.com` reports `CMS: Wix` (bare `wix.com`).
   All four feed the public report's Technology fingerprint section. Nothing
   keys probe phases off these detections (only `cms.name === "WordPress"`
   does), so impact is wrong data in a public evidence-backed report: a
   data-honesty defect, same severity class as the round-4 Joomla/Ghost fix.
2. **No further code defects found.** Line-level re-review of all 17 `api/src`
   modules, the frontend, OpenAPI/MCP schemas, wrangler vars, headers, robots,
   sitemap, and docs found no new correctness, security, privacy, abuse,
   accessibility, or metadata issues beyond those already recorded. Live
   checks (health, v2 directory, 404 contract, HTTP→HTTPS 308, security
   headers) behave as implemented. Production still serves the pre-round-2
   build (no deferred config/report-view scripts, no COOP header): unchanged
   release-ops note from iteration 4; deploying stays out of scope.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Require structural markers for Gatsby, Angular, Squarespace, and Wix detections, completing the round-2/round-4 rule: Angular needs `ng-version=`, `_ngcontent`, or `ng-app`; Gatsby needs `___gatsby`, `/page-data/`, or `gatsby-image-wrapper`; Squarespace needs its asset CDN hostnames (`static1.squarespace.com`, `squarespace-cdn.com`, `assets.squarespace.com`); Wix needs `wixstatic` or `static.parastorage.com` | `api/src/fingerprint.ts`, `api/test/fingerprint.test.ts` | Reports stop claiming frameworks/CMSes on pages that merely mention them or link to them; real deployments keep being detected via build-output markers | Low: detection feeds display only; no probe phases depend on framework/CMS names except WordPress, which keeps its existing rule |
| 2 | No doc sync needed: ARCHITECTURE.md, THREAT_MODEL.md, openapi.yaml, and the methodology dialog describe fingerprinting generically ("HTML markers") and stay accurate | - | - | - |

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
  build, so the next deploy ships rounds 1-5 together.

## Verification

- `cd api && npm run typecheck` and `npm test` (baseline before changes: clean,
  20 files, 170 tests).
- New regression tests: prose-only Gatsby/Angular/Squarespace/Wix pages are not
  detected; each technology is detected from its structural markers.
- Executing `fingerprint()` on the prose fixtures must return null detections
  after the fix (reproduced positive before the fix).
- `node --check` on web JS files (unchanged this round; regression guard).
- Browser render + keyboard/a11y spot suite at 390/768/1440 px on the local
  page (regression guard; no UI changes intended).
- `scripts/audit-html.mjs` against the canonical live URL.
