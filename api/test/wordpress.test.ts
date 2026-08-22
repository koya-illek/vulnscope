import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { scanWordPress } from "../src/wordpress";
import type { WpFinding } from "../src/types";

// Mock fetch for WordPress scanning tests
const originalFetch = globalThis.fetch;

function mockFetch(
  responses: Record<string, { status?: number; body?: string; headers?: Record<string, string> }>,
  observedCalls: Array<{ url: string; method: string; body: BodyInit | null | undefined }> = [],
) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    observedCalls.push({
      url: urlStr,
      method: String(init?.method || "GET").toUpperCase(),
      body: init?.body,
    });
    // Match by path suffix
    for (const [path, resp] of Object.entries(responses)) {
      if (urlStr.includes(path)) {
        return Promise.resolve(
          new Response(resp.body || "", {
            status: resp.status || 200,
            headers: resp.headers || {},
          }),
        );
      }
    }
    return Promise.resolve(new Response("Not Found", { status: 404 }));
  });
}

describe("scanWordPress", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns empty array when no WordPress issues are found", async () => {
    globalThis.fetch = mockFetch({});
    const results = await scanWordPress(
      new URL("https://example.com"),
      '<html><head></head><body></body></html>',
    );
    expect(results).toEqual([]);
  });

  it("detects WordPress version from meta generator tag", async () => {
    globalThis.fetch = mockFetch({});
    const html = '<meta name="generator" content="WordPress 3.9.1">';
    const results = await scanWordPress(new URL("https://example.com"), html);
    const versionFinding = results.find((r) => r.check === "wp-version-vulnerable");
    expect(versionFinding).toBeTruthy();
    expect(versionFinding!.severity).toBe("high");
    expect(versionFinding!.title).toContain("3.9.1");
  });

  it("does not flag a current WordPress version", async () => {
    globalThis.fetch = mockFetch({});
    const html = '<meta name="generator" content="WordPress 6.5.2">';
    const results = await scanWordPress(new URL("https://example.com"), html);
    const versionFinding = results.find((r) => r.check === "wp-version-vulnerable");
    expect(versionFinding).toBeFalsy();
  });

  it("flags unsupported 5.x releases as high severity", async () => {
    globalThis.fetch = mockFetch({});
    const html = '<meta name="generator" content="WordPress 5.4.1">';
    const results = await scanWordPress(new URL("https://example.com"), html);
    const versionFinding = results.find((r) => r.check === "wp-version-vulnerable");
    expect(versionFinding).toBeTruthy();
    expect(versionFinding!.severity).toBe("high");
  });

  it("flags dated 6.x releases as medium severity", async () => {
    globalThis.fetch = mockFetch({});
    const html = '<meta name="generator" content="WordPress 6.4.2">';
    const results = await scanWordPress(new URL("https://example.com"), html);
    const versionFinding = results.find((r) => r.check === "wp-version-vulnerable");
    expect(versionFinding).toBeTruthy();
    expect(versionFinding!.severity).toBe("medium");
  });

  it("detects user enumeration via REST API", async () => {
    globalThis.fetch = mockFetch({
      "/wp-json/wp/v2/users": {
        status: 200,
        body: JSON.stringify([
          { id: 1, name: "admin", slug: "admin" },
          { id: 2, name: "editor", slug: "editor" },
        ]),
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const userEnum = results.find((r) => r.check === "wp-rest-users");
    expect(userEnum).toBeTruthy();
    expect(userEnum!.severity).toBe("medium");
    expect(userEnum!.detail).toContain("2");
  });

  it("detects REST API exposure", async () => {
    globalThis.fetch = mockFetch({
      "/wp-json/": {
        status: 200,
        body: JSON.stringify({ name: "Test Site", description: "Just another WordPress site", namespaces: ["wp/v2"] }),
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const restApi = results.find((r) => r.check === "wp-rest-api");
    expect(restApi).toBeTruthy();
    expect(restApi!.severity).toBe("low");
  });

  it("detects readme.html version disclosure", async () => {
    globalThis.fetch = mockFetch({
      "/readme.html": {
        status: 200,
        body: "<html><body>Version 6.2<br>WordPress</body></html>",
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const readme = results.find((r) => r.check === "wp-readme");
    expect(readme).toBeTruthy();
    expect(readme!.severity).toBe("low");
  });

  it("detects the XML-RPC endpoint with a GET-only signature probe", async () => {
    const observedCalls: Array<{ url: string; method: string; body: BodyInit | null | undefined }> = [];
    globalThis.fetch = mockFetch({
      "/xmlrpc.php": {
        status: 200,
        body: "XML-RPC server accepts POST requests only.",
      },
    }, observedCalls);
    const results = await scanWordPress(new URL("https://example.com"), "");
    const xmlrpc = results.find((r) => r.check === "wp-xmlrpc");
    expect(xmlrpc).toBeTruthy();
    expect(xmlrpc!.severity).toBe("medium");
    expect(xmlrpc!.evidence).toContain("GET /xmlrpc.php");
    const xmlrpcCall = observedCalls.find((call) => call.url.endsWith("/xmlrpc.php"));
    expect(xmlrpcCall?.method).toBe("GET");
    expect(xmlrpcCall?.body).toBeUndefined();
    expect(observedCalls.every((call) => ["GET", "HEAD", "OPTIONS", "TRACE"].includes(call.method))).toBe(true);
  });

  it("detects config backup exposure", async () => {
    globalThis.fetch = mockFetch({
      "/wp-config.txt": {
        status: 200,
        body: "<?php\ndefine('DB_PASSWORD', 'secret');\ndefine('DB_USER', 'root');\n$table_prefix = 'wp_';",
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const configBackup = results.find((r) => r.check === "wp-config-backup-/wp-config.txt");
    expect(configBackup).toBeTruthy();
    expect(configBackup!.severity).toBe("critical");
  });

  it("detects debug log exposure", async () => {
    globalThis.fetch = mockFetch({
      "/wp-content/debug.log": {
        status: 200,
        body: "[04-Jan-2024] PHP Warning: some error\n[04-Jan-2024] PHP Stack trace:\n",
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const debugLog = results.find((r) => r.check === "wp-debug-log");
    expect(debugLog).toBeTruthy();
    expect(debugLog!.severity).toBe("medium");
  });

  it("detects directory listing for uploads", async () => {
    globalThis.fetch = mockFetch({
      "/wp-content/uploads/": {
        status: 200,
        body: "<html><head><title>Index of /wp-content/uploads/</title></head></html>",
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const dirListing = results.find((r) => r.check === "wp-dir-listing-uploads");
    expect(dirListing).toBeTruthy();
    expect(dirListing!.severity).toBe("medium");
  });

  it("detects directory listing for plugins", async () => {
    globalThis.fetch = mockFetch({
      "/wp-content/plugins/": {
        status: 200,
        body: "<html><head><title>Index of /wp-content/plugins/</title></head></html>",
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    const dirListing = results.find((r) => r.check === "wp-dir-listing-plugins");
    expect(dirListing).toBeTruthy();
  });

  it("detects author enumeration via redirect", async () => {
    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (urlStr.includes("?author=1")) {
        return Promise.resolve(
          new Response("", {
            status: 301,
            headers: { location: "https://example.com/author/admin/" },
          }),
        );
      }
      return Promise.resolve(new Response("Not Found", { status: 404 }));
    });

    const results = await scanWordPress(new URL("https://example.com"), "");
    const authorEnum = results.find((r) => r.check === "wp-author-enum");
    expect(authorEnum).toBeTruthy();
    expect(authorEnum!.severity).toBe("medium");
    expect(authorEnum!.detail).toContain("admin");
    expect(authorEnum!.evidence).not.toContain("author=1");
    expect(authorEnum!.evidence).toContain("?[redacted]");
  });

  it("all findings have correct WpFinding shape", async () => {
    globalThis.fetch = mockFetch({
      "/wp-json/wp/v2/users": {
        status: 200,
        body: JSON.stringify([{ id: 1, slug: "admin" }]),
      },
    });
    const results = await scanWordPress(new URL("https://example.com"), "");
    expect(results.length).toBeGreaterThan(0);
    for (const finding of results) {
      const w: WpFinding = finding;
      expect(typeof w.check).toBe("string");
      expect(["critical", "high", "medium", "low", "info"]).toContain(w.severity);
      expect(typeof w.title).toBe("string");
      expect(typeof w.detail).toBe("string");
      expect(typeof w.evidence).toBe("string");
      expect(typeof w.recommendation).toBe("string");
    }
  });
});
