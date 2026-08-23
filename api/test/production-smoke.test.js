import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { runReadOnlySmoke } from "../scripts/production-smoke.mjs";

describe("read-only production smoke", () => {
  const requests = [];
  let baseUrl;
  let server;

  beforeAll(async () => {
    server = createServer(async (request, response) => {
      requests.push({ method: request.method, url: request.url });

      if (request.method === "GET" && request.url === "/") {
        response.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
          "Content-Security-Policy": "default-src 'self'",
          "X-Content-Type-Options": "nosniff",
        });
        response.end("<!doctype html><title>VulnScope</title>");
        return;
      }

      if (request.method === "GET" && request.url === "/api/health") {
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ ok: true }));
        return;
      }

      if (request.method === "GET" && request.url === "/api/v2") {
        response.writeHead(200, {
          "Content-Type": "application/json",
          "X-Robots-Tag": "noindex, nofollow",
        });
        response.end(JSON.stringify({ version: "2.0.0" }));
        return;
      }

      if (request.method === "POST" && request.url === "/mcp/v2") {
        const origin = request.headers.origin;
        response.writeHead(200, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": origin,
          "Cache-Control": "no-store",
          "X-Robots-Tag": "noindex, nofollow",
        });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: "read-only-smoke", result: { protocolVersion: "2025-11-25" } }));
        return;
      }

      if (request.method === "OPTIONS" && request.url === "/mcp/v2") {
        response.writeHead(204, { "Access-Control-Allow-Origin": request.headers.origin });
        response.end();
        return;
      }

      response.writeHead(500);
      response.end("unexpected request");
    });

    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server did not bind a TCP port");
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });

  it("checks public metadata and MCP CORS without starting or retrieving a scan", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await runReadOnlySmoke(baseUrl);
    } finally {
      log.mockRestore();
    }

    expect(requests).toEqual([
      { method: "GET", url: "/" },
      { method: "GET", url: "/api/health" },
      { method: "GET", url: "/api/v2" },
      { method: "POST", url: "/mcp/v2" },
      { method: "OPTIONS", url: "/mcp/v2" },
    ]);
  });
});
