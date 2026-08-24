import type { ScanReport } from "./types";
import { BlockedTargetError, InputError, RateLimitError, ResolverUnavailableError } from "./security";
import { OutboundPolicyError } from "./outbound";
import { decodeUtf8, readBoundedRequestBody, RequestBodyError } from "./http-body";
import { reportToMarkdown } from "./markdown";

import { VERSION } from "./version";

/**
 * Protocol versions this endpoint answers. A client-pinned version that the
 * tool surface actually supports is echoed back so older agents do not
 * disconnect; anything else (including a missing request) receives the latest
 * supported version, per the spec's negotiation rule.
 */
const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18"] as const;
const LATEST_PROTOCOL_VERSION = "2025-11-25";
const MAX_MCP_REQUEST_BYTES = 16 * 1024;

function negotiateProtocolVersion(requested: unknown): string {
  return typeof requested === "string" && requested.length > 0
    && (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
    ? requested
    : LATEST_PROTOCOL_VERSION;
}

export interface VulnScopeMcpInput {
  url: string;
  probePaths?: boolean;
  checkTakeover?: boolean;
}

/**
 * Tool failures become JSON-RPC result text, so the same split as the REST
 * path applies: caller-facing validation, policy, and quota errors keep their
 * actionable messages; anything unexpected is logged server-side and returned
 * generically instead of leaking internals to agent clients.
 */
export function sanitizeToolError(error: unknown): Error {
  if (
    error instanceof InputError ||
    error instanceof BlockedTargetError ||
    error instanceof ResolverUnavailableError ||
    error instanceof RateLimitError ||
    error instanceof OutboundPolicyError
  ) {
    return error;
  }
  console.error("scan_failed_mcp", error);
  return new Error("The scan could not be completed. Please try again.");
}

export async function handleMcp(
  request: Request,
  execute: (name: string, input: Record<string, unknown>) => Promise<ScanReport>,
): Promise<Response> {
  const methodHeaders = { Allow: "POST, OPTIONS", "X-Robots-Tag": "noindex, nofollow" };
  if (request.method === "GET") return new Response(null, { status: 405, headers: methodHeaders });
  if (request.method !== "POST") return new Response(null, { status: 405, headers: methodHeaders });
  if (!(request.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) {
    return rpcError(null, -32600, "Content-Type must be application/json", 415);
  }

  let message: Record<string, unknown>;
  try {
    message = await readMessage(request);
  } catch (error) {
    return rpcError(null, -32700, error instanceof Error ? error.message : "Invalid JSON", 400);
  }
  const id = message.id as string | number | null | undefined;
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string") return rpcError(id ?? null, -32600, "Invalid JSON-RPC request", 400);
  if (id !== undefined && id !== null && typeof id !== "string" && typeof id !== "number") return rpcError(null, -32600, "JSON-RPC id must be a string, number, or null", 400);
  if (message.method.startsWith("notifications/") || id === undefined) return new Response(null, { status: 202 });

  if (message.method === "initialize") {
    const requested = message.params && typeof message.params === "object"
      ? (message.params as Record<string, unknown>).protocolVersion
      : undefined;
    const protocolVersion = negotiateProtocolVersion(requested);
    return rpcResult(id, {
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "vulnscope", title: "VulnScope", version: VERSION },
      instructions: "Use scan_website for authorised, unauthenticated reconnaissance of a public HTTP or HTTPS site and get_vulnscope_report to retrieve an unexpired shared report. VulnScope does not exploit vulnerabilities, submit forms, or bypass authentication.",
    }, protocolVersion);
  }
  if (message.method === "ping") return rpcResult(id, {});
  if (message.method === "tools/list") return rpcResult(id, { tools: [scanTool(), reportTool()] });
  if (message.method !== "tools/call") return rpcError(id, -32601, `Method not found: ${message.method}`);

  const params = message.params && typeof message.params === "object" ? message.params as Record<string, unknown> : {};
  if (!["scan_website", "get_vulnscope_report"].includes(String(params.name))) return rpcError(id, -32602, "Unknown tool name");
  const args = params.arguments && typeof params.arguments === "object" ? params.arguments as Record<string, unknown> : {};
  if (params.name === "get_vulnscope_report") {
    if (Object.keys(args).some((key) => key !== "reportId" && key !== "format")) return rpcError(id, -32602, "get_vulnscope_report received an unsupported argument");
    if (typeof args.reportId !== "string") return rpcError(id, -32602, "get_vulnscope_report requires reportId");
    if (args.format !== undefined && args.format !== "json" && args.format !== "markdown") {
      return rpcError(id, -32602, "format must be \"json\" or \"markdown\"");
    }
  } else {
    const scanKeys = new Set(["url", "probePaths", "checkTakeover"]);
    if (Object.keys(args).some((key) => !scanKeys.has(key))) return rpcError(id, -32602, "scan_website received an unsupported argument");
    if (typeof args.url !== "string") return rpcError(id, -32602, "scan_website requires a URL");
  }
  if (args.probePaths !== undefined && typeof args.probePaths !== "boolean") return rpcError(id, -32602, "probePaths must be a boolean");
  if (args.checkTakeover !== undefined && typeof args.checkTakeover !== "boolean") return rpcError(id, -32602, "checkTakeover must be a boolean");

  try {
    const report = await execute(String(params.name), args);
    // Markdown keeps the structured JSON in structuredContent for schema
    // validating clients and swaps the human-readable text content, so both
    // audiences get their preferred rendering of the same report.
    const text = params.name === "get_vulnscope_report" && args.format === "markdown"
      ? reportToMarkdown(report)
      : JSON.stringify(report);
    return rpcResult(id, {
      content: [{ type: "text", text }],
      structuredContent: report,
      isError: false,
    });
  } catch (error) {
    let text = sanitizeToolError(error).message;
    if (error instanceof RateLimitError) {
      // Agents plan retries; unlike REST headers, a JSON-RPC result has no
      // side channel, so the daily-window reset belongs in the text itself.
      text += ` Quota resets at ${error.resetAt}.`;
    }
    return rpcResult(id, { content: [{ type: "text", text }], isError: true });
  }
}

function reportTool() {
  return {
    name: "get_vulnscope_report", title: "Retrieve a VulnScope report",
    description: "Retrieve a previously created, unexpired VulnScope report by its 16-character report ID, including coverage, evidence, findings, and recommendations.",
    inputSchema: { type: "object", additionalProperties: false, required: ["reportId"], properties: { reportId: { type: "string", pattern: "^[A-Za-z0-9_-]{16}$" }, format: { type: "string", enum: ["json", "markdown"], default: "json", description: "Return the report as machine-readable JSON or human-readable Markdown for tickets and review docs." } } },
    outputSchema: scanOutputSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  };
}

function scanTool() {
  return {
    name: "scan_website",
    title: "Scan a public website with VulnScope",
    description: "Run authorised, unauthenticated web reconnaissance for public exposure, headers, cookies, CORS, fingerprints, secrets, WordPress signals, HTTP method advertisements, DNS, and optional takeover evidence. The tool does not exploit vulnerabilities, submit forms, or bypass authentication.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url"],
      properties: {
        url: { type: "string", maxLength: 2048, description: "Public HTTP or HTTPS URL you are authorised to assess." },
        probePaths: { type: "boolean", default: false, description: "Opt in to the bounded public sensitive-path catalogue." },
        checkTakeover: { type: "boolean", default: false, description: "Enable bounded subdomain takeover evidence checks." },
      },
    },
    outputSchema: scanOutputSchema(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  };
}

function scanOutputSchema() {
  const phaseSchema = {
    type: "object",
    additionalProperties: false,
    required: ["status", "detail"],
    properties: {
      status: { type: "string", enum: ["measured", "unavailable", "skipped", "failed", "partial"] },
      detail: { type: "string" }, requested: { type: "boolean" }, attempts: { type: "integer", minimum: 0 },
      succeeded: { type: "integer", minimum: 0 }, failed: { type: "integer", minimum: 0 }, skipped: { type: "integer", minimum: 0 },
      bytes: { type: "integer", minimum: 0 }, truncated: { type: "boolean" }, errors: { type: "array", items: { type: "string" } },
    },
  };
  return {
      type: "object",
      additionalProperties: false,
      required: ["schemaVersion", "id", "requestedUrl", "hostname", "status", "createdAt", "expiresAt", "totalDurationMs", "observation", "outbound", "coverage", "dns", "ssl", "fingerprint", "headers", "cookies", "exposedPaths", "cors", "findings", "summary"],
      properties: {
        schemaVersion: { type: "integer", enum: [2] }, id: { type: "string" },
        requestedUrl: { type: "string" }, hostname: { type: "string" },
        status: { type: "string", enum: ["complete", "partial", "failed"] },
        createdAt: { type: "string", format: "date-time" }, expiresAt: { type: "string", format: "date-time" }, totalDurationMs: { type: "integer", minimum: 0 },
        observation: { type: "object" }, outbound: { type: "object" },
        coverage: {
          type: "object", additionalProperties: false,
          required: ["mainFetch", "headers", "tlsProtocolCipher", "certificateEvidence", "dns", "cookies", "paths", "cors", "secrets", "wordpress", "methods", "takeover", "criticalGaps"],
          properties: {
            mainFetch: phaseSchema, headers: phaseSchema, tlsProtocolCipher: phaseSchema, certificateEvidence: phaseSchema,
            dns: phaseSchema, cookies: phaseSchema, paths: phaseSchema, cors: phaseSchema, secrets: phaseSchema,
            wordpress: phaseSchema, methods: phaseSchema, takeover: phaseSchema, criticalGaps: { type: "array", items: { type: "string" } },
          },
        },
        dns: { type: "object" }, ssl: { type: "object" }, fingerprint: { type: "object" }, headers: { type: "object" },
        cookies: { type: "array", items: { type: "object" } }, exposedPaths: { type: "array", items: { type: "object" } }, cors: { type: "object" },
        takeover: { type: "array", items: { type: "object" } }, secrets: { type: "array", items: { type: "object" } }, wordpress: { type: "array", items: { type: "object" } }, methods: { type: "object" },
        findings: { type: "array", items: { type: "object", additionalProperties: false, required: ["id", "severity", "category", "title", "detail", "evidence", "recommendation"], properties: { id: { type: "string" }, severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] }, category: { type: "string" }, title: { type: "string" }, detail: { type: "string" }, evidence: { type: "string" }, recommendation: { type: "string" } } } },
        summary: { type: "object", required: ["grade", "critical", "high", "medium", "low", "info"], properties: {
          grade: { type: "string", enum: ["A", "B", "C", "D", "F", "INCOMPLETE"] },
          critical: { type: "integer" }, high: { type: "integer" }, medium: { type: "integer" },
          low: { type: "integer" }, info: { type: "integer" },
        } },
      },
  };
}

async function readMessage(request: Request): Promise<Record<string, unknown>> {
  let bytes: Uint8Array;
  try {
    bytes = await readBoundedRequestBody(request, MAX_MCP_REQUEST_BYTES);
  } catch (error) {
    if (error instanceof RequestBodyError) {
      throw new Error(error.code === "missing" ? "MCP request body is required" : "MCP request is too large");
    }
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeUtf8(bytes));
  } catch {
    throw new Error("Invalid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid JSON-RPC request");
  return parsed as Record<string, unknown>;
}

function rpcResult(id: string | number | null, result: unknown, protocolVersion = LATEST_PROTOCOL_VERSION): Response {
  return rpc({ jsonrpc: "2.0", id, result }, 200, protocolVersion);
}

function rpcError(id: string | number | null, code: number, message: string, status = 200): Response {
  return rpc({ jsonrpc: "2.0", id, error: { code, message } }, status);
}

function rpc(payload: unknown, status = 200, protocolVersion = LATEST_PROTOCOL_VERSION): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "MCP-Protocol-Version": protocolVersion,
      "X-Content-Type-Options": "nosniff",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}
