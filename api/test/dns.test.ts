import { afterEach, describe, expect, it, vi } from "vitest";
import { queryDnsWithFallback } from "../src/dns";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DNS resolver fallback", () => {
  it("uses Google Public DNS when the Cloudflare endpoint is unavailable", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.hostname === "cloudflare-dns.com") {
        return new Response("unavailable", { status: 503 });
      }
      return Response.json({
        Status: 0,
        AD: false,
        Answer: [
          {
            name: "example.com.",
            type: 1,
            TTL: 300,
            data: "93.184.216.34",
          },
        ],
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await queryDnsWithFallback("example.com", "A");

    expect(result).toMatchObject({
      resolver: "Google Public DNS",
      status: 0,
      answers: [{ type: "A", data: "93.184.216.34" }],
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("keeps a valid empty DNS answer without asking a second resolver", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({ Status: 0, AD: false, Answer: [] }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await queryDnsWithFallback("example.com", "AAAA");

    expect(result).toMatchObject({
      resolver: "Cloudflare DNS",
      status: 0,
      answers: [],
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns fallback failure evidence when both resolvers fail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("resolver network unavailable");
      }),
    );

    const result = await queryDnsWithFallback("example.com", "A");

    expect(result).toMatchObject({
      resolver: "Google Public DNS",
      status: -1,
      answers: [],
      error: "resolver network unavailable",
    });
  });
});
