import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";

const env = { ALLOWED_ORIGINS: "" } as unknown as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

async function post(body: Record<string, unknown>): Promise<Response> {
  return worker.fetch(new Request("https://scan.illek.ie/api/v2/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }), env, ctx);
}

describe("REST scan input boundary", () => {
  it("rejects fields outside the published OpenAPI schema", async () => {
    const response = await post({ url: "https://example.com", unexpected: true });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "JSON request body contains an unsupported field.",
    });
  });

  it("rejects option values that do not match the published boolean type", async () => {
    const response = await post({ url: "https://example.com", probePaths: "yes" });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "probePaths must be a boolean.",
    });
  });

  it("defaults WordPress and TRACE options to false", async () => {
    const response = await post({ url: "https://example.com", checkWordPress: "yes" });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "checkWordPress must be a boolean.",
    });
  });
});
