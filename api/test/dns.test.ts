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

  it("drops RRSIG signature records while keeping the address evidence", async () => {
    // do=true makes DNSSEC-signed zones attach RRSIG (type 46) records to
    // every answer; they are signature blobs with no report value.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          Status: 0,
          AD: true,
          Answer: [
            { name: "example.com.", type: 1, TTL: 300, data: "93.184.216.34" },
            { name: "example.com.", type: 46, TTL: 300, data: "A 13 2 300 1787569466 1787389466 34505 example.com. jRb+YDzsO6eEBuH5XEQ3dFxRV9Ko7jE5==" },
          ],
        }),
      ),
    );

    const result = await queryDnsWithFallback("example.com", "A");

    expect(result.authenticatedData).toBe(true);
    expect(result.answers).toEqual([{ name: "example.com", type: "A", ttl: 300, data: "93.184.216.34" }]);
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
