import { pathToFileURL } from "node:url";

const defaultBaseUrl = process.env.VULNSCOPE_BASE_URL || "https://scan.illek.ie";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertHeader(response, name, expected) {
  const value = response.headers.get(name) || "";
  assert(expected.test(value), `${name} was ${JSON.stringify(value)}`);
}

export async function runReadOnlySmoke(baseUrl = defaultBaseUrl) {
  const base = new URL(baseUrl);
  const origin = base.origin;

  const shell = await fetch(new URL("/", base), { redirect: "manual" });
  assert(shell.status === 200, `Public shell returned HTTP ${shell.status}`);
  assertHeader(shell, "Content-Type", /^text\/html\b/i);
  assertHeader(shell, "Strict-Transport-Security", /\bmax-age=/i);
  assertHeader(shell, "Content-Security-Policy", /\bdefault-src\b/i);
  assertHeader(shell, "X-Content-Type-Options", /^nosniff$/i);

  const health = await fetch(new URL("/api/health", base));
  assert(health.ok, `Health returned HTTP ${health.status}`);
  const healthBody = await health.json();
  assert(healthBody.ok === true, "Health payload was not healthy");

  const metadata = await fetch(new URL("/api/v2", base));
  assert(metadata.ok, `API metadata returned HTTP ${metadata.status}`);
  const metadataBody = await metadata.json();
  assert(typeof metadataBody.version === "string", "API metadata omitted its version");
  assertHeader(metadata, "X-Robots-Tag", /\bnoindex\b/i);

  const mcp = await fetch(new URL("/mcp/v2", base), {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "read-only-smoke",
      method: "initialize",
      params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "vulnscope-smoke", version: "1" } },
    }),
  });
  assert(mcp.ok, `MCP initialize returned HTTP ${mcp.status}`);
  const mcpBody = await mcp.json();
  assert(mcpBody.result?.protocolVersion === "2025-11-25", "MCP returned an unexpected protocol version");
  assert(mcp.headers.get("Access-Control-Allow-Origin") === origin, "MCP initialize omitted its allowed origin");
  assertHeader(mcp, "Cache-Control", /\bno-store\b/i);
  assertHeader(mcp, "X-Robots-Tag", /\bnoindex\b/i);

  const preflight = await fetch(new URL("/mcp/v2", base), {
    method: "OPTIONS",
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type",
    },
  });
  assert(preflight.status === 204, `MCP preflight returned HTTP ${preflight.status}`);
  assert(preflight.headers.get("Access-Control-Allow-Origin") === origin, "MCP preflight omitted its allowed origin");

  if (base.protocol === "https:") {
    const insecure = new URL(base);
    insecure.protocol = "http:";
    const redirect = await fetch(insecure, { redirect: "manual" });
    assert(redirect.status === 308, `HTTP entry returned HTTP ${redirect.status}`);
    const location = new URL(redirect.headers.get("Location") || "", insecure);
    assert(location.protocol === "https:" && location.host === base.host, "HTTP entry did not redirect to the canonical HTTPS host");
  }

  console.log(`VulnScope read-only production smoke passed at ${origin}, API ${metadataBody.version}, MCP ${mcpBody.result.protocolVersion}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runReadOnlySmoke();
}
