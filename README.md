# VulnScope

VulnScope performs bounded, unauthenticated reconnaissance of authorised
public websites without exploiting vulnerabilities, submitting forms, or
bypassing authentication.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete component, data-flow,
storage, probe-budget, deployment, and third-party service design.

The public beta applies one outbound policy to the initial URL, redirects,
scripts, WordPress checks, CORS probes, methods, and takeover evidence. A scan
allows at most 46 outbound requests, six concurrent target connections, a
25-second request-wide deadline, and bounded response bodies. Sensitive path
and takeover phases are opt-in and report partial coverage when the safe
budget is exhausted.
Reports are opaque bearer links: anyone with the report ID can read an
unexpired report, so share links only with approved reviewers. Reports expire
after the configured retention period, are served with private no-store
caching, and remove cookie values plus query and fragment components from
stored URL evidence. Read [THREAT_MODEL.md](./THREAT_MODEL.md) before
operating a deployment.

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

From `api/`, run `npm run typecheck`, `npm test`, and `npm run smoke:production`.
The production smoke confirms DNS resolution, a measured main GET, the NDJSON
error contract, and the explicit same-Worker self-scan boundary.
