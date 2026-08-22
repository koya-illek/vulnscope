import { describe, expect, it, vi } from "vitest";
import { handleMcp } from "../src/mcp";
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

  it("acknowledges notifications and rejects GET streams", async () => {
    expect((await handleMcp(rpc("notifications/initialized", {}, undefined), async () => report)).status).toBe(202);
    expect((await handleMcp(new Request("https://scan.illek.ie/mcp"), async () => report)).status).toBe(405);
  });
});
