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
production value in `wrangler.toml` or `.dev.vars`. Validation failures and
recent-scan cache hits are uncharged, and a scan aborted by a VulnScope
resolver outage is refunded so the invited retry is free.

## Agent integrations

```text
GET  https://scan.illek.ie/api/v2
POST https://scan.illek.ie/api/v2/scan
POST https://scan.illek.ie/mcp
POST https://scan.illek.ie/mcp/v2
```

The MCP endpoints implement stateless JSON-RPC over HTTP, negotiate
`2025-11-25` (echoing a client-pinned `2025-06-18` when requested), and
publish `scan_website` plus `get_vulnscope_report`. REST scan progress uses
newline-delimited JSON (`application/x-ndjson`). Copilot Studio can import
`https://scan.illek.ie/mcp-copilot.yaml`; OpenAPI agents can import
`https://scan.illek.ie/openapi.yaml`.

### Quickstart

```sh
# Create a scan (201 with the full report; charges the daily web quota)
curl -sS -X POST https://scan.illek.ie/api/v2/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "example.com", "probePaths": false, "checkTakeover": false}'

# The same scan with newline-delimited progress events
curl -sS -X POST https://scan.illek.ie/api/scans/stream \
  -H 'Content-Type: application/json' \
  -d '{"url": "example.com"}'

# Read or export an unexpired report by its 16-character ID
curl -sS https://scan.illek.ie/api/scans/<reportId>
curl -sSOJ https://scan.illek.ie/api/scans/<reportId>/export
# The same export as a Markdown document for tickets and review docs
curl -sSOJ "https://scan.illek.ie/api/scans/<reportId>/export?format=markdown"
# Poll without re-downloading: revalidate the ETag from the previous 200
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'If-None-Match: "<etag-from-previous-response>"' \
  https://scan.illek.ie/api/scans/<reportId>

# MCP: initialize, then call a tool (stateless; no session handshake needed)
curl -sS -X POST https://scan.illek.ie/mcp/v2 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}'
curl -sS -X POST https://scan.illek.ie/mcp/v2 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_website","arguments":{"url":"example.com"}}}'
```

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
