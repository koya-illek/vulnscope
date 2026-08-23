# VulnScope threat model

VulnScope is an open beta for bounded external exposure evidence. It is not an exploit framework, a port scanner, or proof that a target is secure.

## Assets and trust boundaries

- The target URL and every response are attacker-controlled input.
- Public report JSON, D1 retention records, cache entries, and browser views must not contain bearer cookies, signed query strings, or raw response bodies.
- The Worker runtime and D1 database are trusted service components. The public caller is not authenticated during the approved testing period.
- DNS and certificate-transparency providers are evidence sources, not authoritative proof of ownership or active TLS state.

## Main threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Redirect to loopback, private, reserved, or metadata address | `safeFetch` uses manual redirects, validates every hop, checks public DNS answers, revalidates redirect hops, and caps redirects | A provider can change DNS after the final check; a future transport must preserve the same policy |
| DNS rebinding | Per-hop DNS revalidation and rejection of mixed public/private answers | Resolver disagreement can produce unavailable coverage |
| Cross-host script or takeover navigation | Same-host is the default; explicit cross-host access is limited to the same registrable domain and still requires public DNS | CDN scripts outside the target domain are intentionally skipped |
| Large response or concurrent probe abuse | 46-request hard budget, six concurrent outbound connections, a scan-wide outbound deadline that caps each request timeout, bounded body readers, and phase partial status | IP quotas are bypassable by rotation while the beta remains open |
| Offline guessing of quota identifiers after D1 disclosure | Daily quota keys use a managed-secret HMAC over the scope, date, and source IP | Operators must protect and deliberately rotate the Worker secret; rotation resets active daily counters |
| False CORS severity from unrelated response headers | GET and OPTIONS headers remain separate; credentialed reflection and wildcard-policy checks require ACAO and ACAC on the same response | CORS observations do not prove that a sensitive endpoint returns readable data |
| Public report secret disclosure | Cookie values are removed, script source queries are stripped, URL-bearing header evidence is redacted, and reports use private no-store caching | Existing reports created before this release require retention expiry or manual review |
| Sensitive-path false positives | Empty signatures removed, multi-marker matching, structured key formats, content-type checks, and soft-404 comparison | Heuristics remain observations and need corpus expansion before broader catalogues |
| Takeover false positives | A and AAAA checks, resolver-state distinction, registrable-domain filtering, provider signatures, and non-critical confidence | Provider ownership cannot be proven from CT and HTTP alone |
| Agent contract confusion | REST documents synchronous JSON and NDJSON separately; MCP returns JSON-RPC and bounded input; phase status is explicit | Older clients may still assume the former SSE description |

## Non-goals

VulnScope does not submit forms, send exploit payloads, authenticate, crawl arbitrary links, scan ports, collect credentials, or make destructive HTTP requests. It does not claim CVE coverage, active certificate validation, exploitability, or an overall safe verdict.

## Operational gates

Keep the service open only for limited testing while the quotas and budgets are monitored. A production release should add abuse reporting and stronger caller quotas before materially increasing probe breadth. Browser, authenticated, historical, and CVE coverage require separate consent and evidence designs.
