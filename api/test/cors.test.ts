import { afterEach, describe, expect, it, vi } from "vitest";
import { testCors } from "../src/cors";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("testCors", () => {
  it("reports arbitrary-origin reflection without claiming credentialed access", async () => {
    globalThis.fetch = vi.fn(() => Promise.resolve(new Response(null, {
      status: 200,
      headers: { "access-control-allow-origin": "https://evil.example" },
    })));

    const { result, findings } = await testCors("https://example.com");
    expect(result.reflectsOrigin).toBe(true);
    expect(result.wildcardWithCredentials).toBe(false);
    expect(result.vulnerable).toBe(true);
    // Reflection without allowed credentials only exposes public data.
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].detail).toContain("credentials are not allowed");
    expect(findings[0].detail).not.toContain("authenticated cross-origin requests");
  });

  it("prices reflection with credentials as high", async () => {
    globalThis.fetch = vi.fn(() => Promise.resolve(new Response(null, {
      status: 200,
      headers: {
        "access-control-allow-origin": "https://evil.example",
        "access-control-allow-credentials": "true",
      },
    })));

    const { result, findings } = await testCors("https://example.com");
    expect(result.reflectsOrigin).toBe(true);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "cors-origin-reflection",
      severity: "high",
    });
    expect(findings[0].detail).toContain("authenticated responses");
  });

  it("reports wildcard plus credentials as misconfiguration without claiming exploitation", async () => {
    globalThis.fetch = vi.fn(() => Promise.resolve(new Response(null, {
      status: 200,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      },
    })));

    const { result, findings } = await testCors("https://example.com");
    expect(result.reflectsOrigin).toBe(false);
    expect(result.wildcardWithCredentials).toBe(true);
    expect(result.vulnerable).toBe(false);
    // Browsers refuse credentialed requests alongside a wildcard origin, so
    // the finding documents broken intent rather than demonstrated theft.
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "cors-wildcard-credentials",
      severity: "low",
    });
    expect(findings[0].detail).toContain("not exploitable as-is");
  });

  it("does not combine reflected origin and credentials from different responses", async () => {
    globalThis.fetch = vi.fn((_input, init) => Promise.resolve(new Response(null, {
      status: 200,
      headers: init?.method === "GET"
        ? { "access-control-allow-origin": "https://evil.example" }
        : { "access-control-allow-credentials": "true" },
    })));

    const { result, findings } = await testCors("https://example.com");
    expect(result.reflectsOrigin).toBe(true);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "cors-origin-reflection",
      severity: "medium",
    });
    expect(findings[0].detail).toContain("credentials are not allowed");
  });

  it("does not combine wildcard origin and credentials from different responses", async () => {
    globalThis.fetch = vi.fn((_input, init) => Promise.resolve(new Response(null, {
      status: 200,
      headers: init?.method === "GET"
        ? { "access-control-allow-origin": "*" }
        : { "access-control-allow-credentials": "true" },
    })));

    const { result, findings } = await testCors("https://example.com");
    expect(result.wildcardWithCredentials).toBe(false);
    expect(result.vulnerable).toBe(false);
    expect(findings).toEqual([]);
  });
});
