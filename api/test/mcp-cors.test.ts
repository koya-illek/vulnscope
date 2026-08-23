import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";

const env = {
  ALLOWED_ORIGINS: "https://client.example",
} as unknown as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

describe("MCP browser boundary", () => {
  it("returns CORS and security headers to an allowed browser origin", async () => {
    const response = await worker.fetch(new Request("https://scan.illek.ie/mcp/v2", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://client.example",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
    }), env, ctx);

    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe("https://client.example");
    expect(response.headers.get("vary")).toBe("Origin");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-robots-tag")).toBe("noindex, nofollow");
  });

  it("adds the same policy headers to preflight responses", async () => {
    const response = await worker.fetch(new Request("https://scan.illek.ie/mcp/v2", {
      method: "OPTIONS",
      headers: { Origin: "https://client.example" },
    }), env, ctx);

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("https://client.example");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-robots-tag")).toBe("noindex, nofollow");
  });
});
