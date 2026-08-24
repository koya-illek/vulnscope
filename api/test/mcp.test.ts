import { describe, expect, it, vi } from "vitest";
import { handleMcp, sanitizeToolError } from "../src/mcp";
import { BlockedTargetError, InputError, RateLimitError, ResolverUnavailableError } from "../src/security";
import { OutboundPolicyError } from "../src/outbound";
import type { ScanReport } from "../src/types";

const report = {
  schemaVersion: 2,
  id: "abcdefghijklmnop",
  requestedUrl: "https://example.com/",
  hostname: "example.com",
  status: "complete",
  createdAt: "2026-08-14T00:00:00.000Z",
  expiresAt: "2026-08-28T00:00:00.000Z",
  totalDurationMs: 100,
  summary: { grade: "A", critical: 0, high: 0, medium: 0, low: 0, info: 0 },
} as unknown as ScanReport;

function rpc(method: string, params: unknown = {}, id: number | undefined = 1): Request {
  return new Request("https://scan.illek.ie/mcp/v2", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
}

describe("VulnScope MCP", () => {
  it("negotiates protocol 2025-11-25", async () => {
    const response = await handleMcp(rpc("initialize", { protocolVersion: "2025-11-25" }), async () => report);
    expect(response.headers.get("mcp-protocol-version")).toBe("2025-11-25");
    await expect(response.json()).resolves.toMatchObject({ result: { serverInfo: { name: "vulnscope", version: "2.0.0" } } });
  });

  it("echoes a client-pinned older supported protocol version", async () => {
    const response = await handleMcp(rpc("initialize", { protocolVersion: "2025-06-18" }), async () => report);
    expect(response.headers.get("mcp-protocol-version")).toBe("2025-06-18");
    const body = await response.json<{ result: { protocolVersion: string } }>();
    expect(body.result.protocolVersion).toBe("2025-06-18");
  });

  it("answers unsupported or missing version requests with the latest version", async () => {
    for (const params of [{ protocolVersion: "1999-01-01" }, {}, undefined]) {
      const response = await handleMcp(rpc("initialize", params), async () => report);
      expect(response.headers.get("mcp-protocol-version")).toBe("2025-11-25");
      const body = await response.json<{ result: { protocolVersion: string } }>();
      expect(body.result.protocolVersion).toBe("2025-11-25");
    }
  });

  it("publishes scan and report retrieval tools with complete schemas", async () => {
    const response = await handleMcp(rpc("tools/list"), async () => report);
    const body = await response.json<{ result: { tools: Array<{ name: string; description: string; inputSchema: object; outputSchema: object }> } }>();
    expect(body.result.tools.map(tool => tool.name)).toEqual(["scan_website", "get_vulnscope_report"]);
    expect(body.result.tools.every(tool => tool.inputSchema && tool.outputSchema)).toBe(true);
    expect(body.result.tools[0].description).toContain("does not exploit");
  });

  it("passes explicit scan options to the shared engine", async () => {
    const execute = vi.fn(async () => report);
    const response = await handleMcp(rpc("tools/call", {
      name: "scan_website",
      arguments: { url: "https://example.com", probePaths: false, checkTakeover: true },
    }), execute);
    const body = await response.json<{ result: { structuredContent: ScanReport } }>();
    expect(execute).toHaveBeenCalledWith("scan_website", { url: "https://example.com", probePaths: false, checkTakeover: true });
    expect(body.result.structuredContent.summary.grade).toBe("A");
  });

  it("rejects arguments outside the published tool schema", async () => {
    const execute = vi.fn(async () => report);
    const response = await handleMcp(rpc("tools/call", {
      name: "scan_website",
      arguments: { url: "https://example.com", unexpected: true },
    }), execute);
    const body = await response.json<{ error: { code: number; message: string } }>();

    expect(body.error).toEqual({
      code: -32602,
      message: "scan_website received an unsupported argument",
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("acknowledges notifications and rejects GET streams", async () => {
    expect((await handleMcp(rpc("notifications/initialized", {}, undefined), async () => report)).status).toBe(202);
    expect((await handleMcp(new Request("https://scan.illek.ie/mcp"), async () => report)).status).toBe(405);
  });

  it("keeps caller-facing error messages and returns them as tool errors", async () => {
    const response = await handleMcp(rpc("tools/call", { name: "scan_website", arguments: { url: "https://example.com" } }), async () => {
      throw new BlockedTargetError("The hostname resolves to a private or reserved network address.");
    });
    const body = await response.json<{ result: { content: Array<{ text: string }>; isError: boolean } }>();
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toBe("The hostname resolves to a private or reserved network address.");
  });

  it("returns generic text for internal faults instead of leaking internals", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const response = await handleMcp(rpc("tools/call", { name: "scan_website", arguments: { url: "https://example.com" } }), async () => {
        throw new Error('D1_ERROR: internal constraint details');
      });
      const body = await response.json<{ result: { content: Array<{ text: string }>; isError: boolean } }>();
      expect(body.result.isError).toBe(true);
      expect(body.result.content[0].text).toBe("The scan could not be completed. Please try again.");
      expect(body.result.content[0].text).not.toContain("D1_ERROR");
      expect(consoleError).toHaveBeenCalledWith("scan_failed_mcp", expect.any(Error));
    } finally {
      consoleError.mockRestore();
    }
  });

  it("sanitises only unexpected errors, preserving known classes", () => {
    const input = new InputError("A URL is required.");
    const blocked = new BlockedTargetError("nope");
    const resolver = new ResolverUnavailableError("resolvers down");
    const quota = new RateLimitError("Daily scan limit of 10 reached.", 10, 11, "2026-08-22T23:59:59.999Z");
    const policy = new OutboundPolicyError("The scan time budget was exhausted.", "budget");
    const internal = new Error("secret internals");

    expect(sanitizeToolError(input)).toBe(input);
    expect(sanitizeToolError(blocked)).toBe(blocked);
    expect(sanitizeToolError(resolver)).toBe(resolver);
    expect(sanitizeToolError(quota)).toBe(quota);
    expect(sanitizeToolError(policy)).toBe(policy);

    const sanitizedInternal = sanitizeToolError(internal);
    expect(sanitizedInternal).not.toBe(internal);
    expect(sanitizedInternal.message).toBe("The scan could not be completed. Please try again.");
  });});
