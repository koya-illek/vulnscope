import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mergeMethodResult, probeMethods } from "../src/methods";
import type { MethodResult } from "../src/types";

const originalFetch = globalThis.fetch;

describe("probeMethods", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns empty results when all methods are rejected", async () => {
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("Network error")));
    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.methods).toEqual([]);
    expect(result.traceVulnerable).toBe(false);
  });

  it("reports PUT and DELETE only as OPTIONS advertisements and never sends them", async () => {
    const observedMethods: string[] = [];
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const method = String(init?.method || "GET").toUpperCase();
      observedMethods.push(method);
      if (method === "OPTIONS") {
        return Promise.resolve(new Response(null, {
          status: 204,
          headers: { allow: "GET, HEAD, POST, PUT, DELETE, OPTIONS" },
        }));
      }
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com");
    expect(result.methods.map((method) => method.method)).toEqual(["PUT", "DELETE"]);
    expect(result.methods.every((method) => method.observation === "advertised")).toBe(true);
    expect(result.methods[0].evidence).toContain("no PUT request was sent");
    expect(observedMethods).toEqual(["OPTIONS"]);
    expect(observedMethods).not.toContain("PUT");
    expect(observedMethods).not.toContain("DELETE");
    expect(observedMethods).not.toContain("TRACE");
  });

  it("sends TRACE only when probeTrace is enabled and still never sends PUT or DELETE", async () => {
    const observedMethods: string[] = [];
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const method = String(init?.method || "GET").toUpperCase();
      observedMethods.push(method);
      if (method === "OPTIONS") {
        return Promise.resolve(new Response(null, {
          status: 204,
          headers: { allow: "GET, HEAD, POST, PUT, DELETE, OPTIONS" },
        }));
      }
      return Promise.resolve(new Response("", { status: 405 }));
    });

    await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(observedMethods).toEqual(["OPTIONS", "TRACE"]);
    expect(observedMethods).not.toContain("PUT");
    expect(observedMethods).not.toContain("DELETE");
  });

  it("ignores mundane methods from Allow header", async () => {
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "OPTIONS") {
        return Promise.resolve(new Response(null, {
          status: 204,
          headers: { allow: "GET, HEAD, POST, OPTIONS" },
        }));
      }
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.methods.find((method) => method.method === "GET")).toBeFalsy();
    expect(result.methods.find((method) => method.method === "HEAD")).toBeFalsy();
    expect(result.methods.find((method) => method.method === "POST")).toBeFalsy();
  });

  it("detects TRACE reflection (XST)", async () => {
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "TRACE") {
        const canary = new Headers(init.headers).get("X-Test-Header");
        return Promise.resolve(new Response(
          `TRACE / HTTP/1.1\r\nUser-Agent: VulnScanner/1.0\r\nX-Test-Header: ${canary}\r\n`,
          { status: 200 },
        ));
      }
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.traceVulnerable).toBe(true);
    const trace = result.methods.find((method) => method.method === "TRACE");
    expect(trace).toBeTruthy();
    expect(trace!.allowed).toBe(true);
    expect(trace!.observation).toBe("observed");
    expect(trace!.evidence).toContain("XST");
  });

  it("does not treat generic TRACE or User-Agent text as reflected request data", async () => {
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "TRACE") {
        return Promise.resolve(new Response(
          "TRACE is supported for diagnostics. Send a User-Agent header with your request.",
          { status: 200 },
        ));
      }
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.traceVulnerable).toBe(false);
    const trace = result.methods.find((method) => method.method === "TRACE");
    expect(trace).toBeTruthy();
    expect(trace!.evidence).toContain("no reflected request data observed");
  });

  it("reports TRACE without reflection as observed but not XST", async () => {
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "TRACE") return Promise.resolve(new Response("OK", { status: 200 }));
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.traceVulnerable).toBe(false);
    const trace = result.methods.find((method) => method.method === "TRACE");
    expect(trace).toBeTruthy();
    expect(trace!.allowed).toBe(true);
    expect(trace!.observation).toBe("observed");
    expect(trace!.evidence).toContain("no reflected request data observed");
  });

  it("merges an advertised TRACE with the real non-reflecting TRACE probe", async () => {
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "OPTIONS") {
        return Promise.resolve(new Response(null, { status: 204, headers: { allow: "TRACE" } }));
      }
      return Promise.resolve(new Response("OK", { status: 200 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    const traces = result.methods.filter((method) => method.method === "TRACE");
    expect(traces).toHaveLength(1);
    expect(traces[0].observation).toBe("observed");
    expect(traces[0].evidence).toContain("OPTIONS Allow header advertises TRACE");
    expect(traces[0].evidence).toContain("no reflected request data observed");
    expect(traces[0].evidence).not.toContain("no TRACE request was sent");
    expect(result.traceVulnerable).toBe(false);
  });

  it("merges an advertised TRACE with reflected TRACE evidence without duplicating it", async () => {
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "OPTIONS") {
        return Promise.resolve(new Response(null, { status: 204, headers: { allow: "TRACE" } }));
      }
      const canary = new Headers(init?.headers).get("X-Test-Header");
      return Promise.resolve(new Response(`TRACE X-Test-Header: ${canary}`, { status: 200 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.methods.filter((method) => method.method === "TRACE")).toHaveLength(1);
    expect(result.traceVulnerable).toBe(true);
  });

  it("does not report TRACE when 405 returned", async () => {
    globalThis.fetch = vi.fn(() => Promise.resolve(new Response("", { status: 405 })));
    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.methods.find((method) => method.method === "TRACE")).toBeFalsy();
    expect(result.traceVulnerable).toBe(false);
  });

  it("records every target fetch method and keeps the result shape explicit", async () => {
    const observedMethods: string[] = [];
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const method = String(init?.method || "GET").toUpperCase();
      observedMethods.push(method);
      if (method === "OPTIONS") return Promise.resolve(new Response(null, { status: 204, headers: { allow: "PUT, DELETE" } }));
      if (method === "TRACE") return Promise.resolve(new Response("TRACE reflected", { status: 200 }));
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.methods.length).toBeGreaterThan(0);
    for (const method of result.methods) {
      const typed: MethodResult = method;
      expect(typeof typed.method).toBe("string");
      expect(typeof typed.allowed).toBe("boolean");
      expect(typeof typed.evidence).toBe("string");
      expect(["advertised", "observed"]).toContain(typed.observation);
    }
    expect(observedMethods).toEqual(["OPTIONS", "TRACE"]);
  });

  it("handles empty Allow header gracefully", async () => {
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "OPTIONS") return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(new Response("", { status: 405 }));
    });

    const result = await probeMethods("https://example.com", undefined, { probeTrace: true });
    expect(result.methods.find((method) => method.method === "PUT")).toBeFalsy();
    expect(result.methods.find((method) => method.method === "DELETE")).toBeFalsy();
  });
});

describe("mergeMethodResult", () => {
  it("keeps one observed TRACE result and retains advertisement context", () => {
    const merged = mergeMethodResult(
      { method: "TRACE", allowed: true, observation: "advertised", evidence: "Allow advertises TRACE" },
      { method: "TRACE", allowed: true, observation: "observed", evidence: "TRACE returned 200; no reflected request data observed" },
    );

    expect(merged).toEqual({
      method: "TRACE",
      allowed: true,
      observation: "observed",
      evidence: "Allow advertises TRACE; TRACE returned 200; no reflected request data observed",
    });
  });
});
