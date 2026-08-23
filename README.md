# VulnScope

VulnScope performs bounded, unauthenticated reconnaissance of authorised
public websites without exploiting vulnerabilities, submitting forms, or
bypassing authentication.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete component, data-flow,
storage, probe-budget, deployment, and third-party service design.

The public beta applies one outbound policy to the initial URL, redirects,
scripts, WordPress checks, CORS probes, methods, and takeover evidence. A scan
allows at most 46 outbound requests, six concurrent outbound connections, a
25-second outbound-work deadline, and bounded response bodies. Sensitive path
and takeover phases are opt-in and report partial coverage when the safe
budget is exhausted.
Reports are opaque bearer links: anyone with the report ID can read an
unexpired report, so share links only with approved reviewers. Reports expire
after the configured retention period, are served with private no-store
caching, and remove cookie values plus query and fragment components from
stored URL evidence. Read [THREAT_MODEL.md](./THREAT_MODEL.md) before
operating a deployment.

Daily quota identifiers use a scope-specific HMAC and never store the source
IP address. Before the first production deployment, generate a random secret
of at least 32 bytes and store it with
`cd api && npx wrangler secret put RATE_LIMIT_HMAC_KEY`. Do not put the
production value in `wrangler.toml` or `.dev.vars`.

## Agent integrations

```text
GET  https://scan.illek.ie/api/v2
POST https://scan.illek.ie/api/v2/scan
POST https://scan.illek.ie/mcp
POST https://scan.illek.ie/mcp/v2
```

The MCP endpoints implement stateless JSON-RPC over HTTP with protocol
version `2025-11-25` and publish `scan_website` plus
`get_vulnscope_report`. REST scan progress uses newline-delimited JSON
(`application/x-ndjson`). Copilot Studio can import
`https://scan.illek.ie/mcp-copilot.yaml`; OpenAPI agents can import
`https://scan.illek.ie/openapi.yaml`.

## Release checks

From `api/`, run `npm run verify:release`. It covers TypeScript, unit and
contract tests, browser JavaScript syntax, the dependency audit, and a
Cloudflare deployment dry run. The repository CI runs the same command for
every push and pull request.

After deployment, run `npm run smoke:production`. It checks the public shell,
security headers, health and API metadata, HTTP-to-HTTPS redirect, and MCP
initialisation and CORS without creating a scan or writing a report. The
separate `npm run smoke:production:scan` command creates a real target scan and
stores a production report. Run that mutating check only with release-owner
approval.

## Local development

From `api/`, run `npx wrangler dev --local` and open
`http://localhost:8788`. The session runs in the development environment via
`api/.dev.vars`, which disables the production HTTP→HTTPS entry redirect that
would otherwise loop forever under `wrangler dev`'s custom-domain emulation
and allowlists the emulated origin so the page can call the API same-origin.
Production values in `wrangler.toml` are unaffected.
