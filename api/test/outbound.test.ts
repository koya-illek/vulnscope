import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createOutboundContext,
  infrastructureFetch,
  OutboundBudget,
  readBoundedBody,
  safeFetch,
} from "../src/outbound";
import { auditCookies } from "../src/cookies";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("bounded public outbound policy", () => {
  it("rejects a redirect to a private or literal-IP target before the second fetch", async () => {
    const context = createOutboundContext({}, { "example.com": ["93.184.216.34"] });
    const fetchMock = vi.fn(async () => new Response(null, {
      status: 302,
      headers: { location: "http://127.0.0.1/admin" },
    }));
    globalThis.fetch = fetchMock;

    await expect(safeFetch("https://example.com", { baseUrl: new URL("https://example.com"), context }))
      .rejects.toThrow(/public hostname|outbound/i);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("revalidates a redirect hop to defend against DNS rebinding", async () => {
    const context = createOutboundContext({}, { "example.com": ["93.184.216.34"] });
    let resolutions = 0;
    context.resolveHost = async () => {
      resolutions++;
      return resolutions === 1 ? ["93.184.216.34"] : ["192.168.1.10"];
    };
    globalThis.fetch = vi.fn(async () => new Response(null, {
      status: 302,
      headers: { location: "https://example.com/private" },
    }));

    await expect(safeFetch("https://example.com", { baseUrl: new URL("https://example.com"), context }))
      .rejects.toThrow(/public address|private/i);
    expect(resolutions).toBe(2);
  });

  it("blocks cross-host navigation unless the caller opts into the same registrable domain", async () => {
    const context = createOutboundContext({}, {
      "example.com": ["93.184.216.34"],
      "cdn.example.net": ["93.184.216.35"],
    });
    globalThis.fetch = vi.fn(async () => new Response("ok", { status: 200 }));

    await expect(safeFetch("https://cdn.example.net/app.js", {
      baseUrl: new URL("https://example.com"),
      context,
    })).rejects.toThrow(/outside the approved target boundary/i);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("uses Worker-supported manual redirects and rejects an infrastructure redirect", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://unexpected.example/" },
      }),
    );
    globalThis.fetch = fetchMock;

    await expect(
      infrastructureFetch("https://cloudflare-dns.com/dns-query", undefined),
    ).rejects.toThrow(/unexpected redirect/i);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://cloudflare-dns.com/dns-query",
      expect.objectContaining({ redirect: "manual" }),
    );
  });

  it("caps response bodies and records truncation", async () => {
    const context = createOutboundContext({}, { "example.com": ["93.184.216.34"] });
    const response = new Response("0123456789", { status: 200 });
    const result = await readBoundedBody(response, 4, context, "test");
    expect(result.text).toBe("0123");
    expect(result.bytes).toBe(4);
    expect(result.truncated).toBe(true);
    expect(context.budget.truncatedBodies).toBe(1);
  });

  it("enforces the aggregate response-body budget across phases", async () => {
    const context = createOutboundContext({ maxBodyBytes: 4 }, { "example.com": ["93.184.216.34"] });
    const first = await readBoundedBody(new Response("0123456789"), 10, context, "first");
    const second = await readBoundedBody(new Response("abcd"), 10, context, "second");
    expect(first).toEqual({ text: "0123", bytes: 4, truncated: true });
    expect(second).toEqual({ text: "", bytes: 0, truncated: true });
    expect(context.budget.bodyBytes).toBe(4);
    expect(context.budget.truncatedBodies).toBe(2);
  });
});

describe("public host resolution through CNAME answers", () => {
  function cnameDohResponse() {
    // Production DoH resolvers return the alias chain inside the same Answer
    // array as the address records (verified against cloudflare-dns.com and
    // dns.google). The alias hostname must not enter the IP candidate list.
    return Response.json({
      Status: 0,
      AD: false,
      Answer: [
        { name: "www.example.com.", type: 5, TTL: 300, data: "cdn.example.net." },
        { name: "cdn.example.net", type: 1, TTL: 60, data: "93.184.216.34" },
      ],
    });
  }

  it("resolves a host whose DNS answer contains a CNAME record", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => cnameDohResponse()));
    const context = createOutboundContext();

    await expect(context.resolveHost!("www.example.com")).resolves.toEqual(["93.184.216.34"]);
  });

  it("completes a redirect hop that requires fresh resolution of a CNAME-bearing host", async () => {
    globalThis.fetch = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
        return cnameDohResponse();
      }
      if (url.protocol === "http:") {
        return new Response(null, { status: 301, headers: { location: "https://www.example.com/home" } });
      }
      return new Response("target page", { status: 200 });
    });
    // No seeded addresses: every hop resolves fresh, like a redirect chain.
    const context = createOutboundContext();

    const response = await safeFetch("http://www.example.com/", {
      baseUrl: new URL("http://www.example.com"),
      context,
    });
    expect(response.status).toBe(200);
    expect(context.budget.redirects).toEqual([
      { from: "http://www.example.com/", to: "https://www.example.com/home", status: 301 },
    ]);
  });

  it("still fails closed when a CNAME chain yields no address records", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      Status: 0,
      AD: false,
      Answer: [{ name: "broken.example.com.", type: 5, TTL: 300, data: "missing.example.net." }],
    })));
    const context = createOutboundContext();

    await expect(context.resolveHost!("broken.example.com")).rejects.toThrow(/no confirmed public address/i);
  });
});

describe("public report cookie evidence", () => {
  it("keeps cookie policy metadata without storing the cookie value", () => {
    const headers = new Headers();
    headers.append("Set-Cookie", "session=super-secret-token; Path=/");
    const result = auditCookies(headers);
    const evidence = result.findings[0]?.evidence || "";
    expect(evidence).toContain("session=[redacted]");
    expect(evidence).not.toContain("super-secret-token");
  });
});

describe("OutboundBudget concurrency slot accounting", () => {
  it("never exceeds maxConcurrent when a release races a fast-path acquire", async () => {
    const budget = new OutboundBudget({ maxConcurrent: 1 });
    await budget.acquire();
    // Second caller queues because the only slot is held.
    const queued = budget.acquire();
    // Releasing resolves the queued waiter but does not wait for it to run.
    // A caller arriving in that gap must not stack on top of the woken
    // waiter (the old implementation incremented twice and pushed
    // activePeak past the cap).
    budget.release();
    await budget.acquire();
    expect(budget.active).toBe(1);
    expect(budget.activePeak).toBe(1);
    budget.release();
    await queued;
    expect(budget.active).toBe(1);
    expect(budget.activePeak).toBe(1);
  });

  it("drains every queued acquirer without exceeding maxConcurrent", async () => {
    const budget = new OutboundBudget({ maxConcurrent: 2 });
    const holders = [
      budget.acquire(),
      budget.acquire(),
      budget.acquire(),
      budget.acquire(),
    ];
    budget.release();
    budget.release();
    await Promise.all(holders);
    expect(budget.activePeak).toBeLessThanOrEqual(2);
    expect(budget.active).toBe(2);
  });
});
