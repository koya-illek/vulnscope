import { analyzeUrl, type AnalyzerProgress } from "./analyzer";
import { buildSummary, gradeBlockingCoverageGaps } from "./scorer";
import {
  allowedOrigin,
  BlockedTargetError,
  InputError,
  normalizeUrl,
  RateLimitError,
  redactUrlForStorage,
  ResolverUnavailableError,
} from "./security";
import type { CoverageStatus, Env, Finding, OutboundRequestSummary, ScanCoverage, ScanReport } from "./types";
import { handleMcp } from "./mcp";
import { deriveDailyQuotaKey } from "./quota";
import { decodeUtf8, readBoundedRequestBody, RequestBodyError } from "./http-body";
import { reportToMarkdown } from "./markdown";
import { VERSION, WEBSITE_ORIGIN } from "./version";

const API_VERSION = VERSION;
const REPORT_SCHEMA_VERSION = 2;
const REPORT_ID = /^[A-Za-z0-9_-]{16}$/;
const MAX_REQUEST_BYTES = 8192;
const RECENT_SCAN_TTL = 300;

/**
 * Set-equality assertions between the stored-report validation lists and the
 * types they mirror. These lists decide which stored fields are trusted on
 * read, so adding a coverage phase, status, or severity to one side without
 * the other must fail compilation rather than silently skip validation.
 */
type SetsEqual<A, B> = ((<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : never);
type AssertExact<Actual, Expected> = SetsEqual<Actual, Expected>;

const COVERAGE_PHASES = [
  "mainFetch",
  "headers",
  "tlsProtocolCipher",
  "certificateEvidence",
  "dns",
  "cookies",
  "paths",
  "cors",
  "secrets",
  "wordpress",
  "methods",
  "takeover",
] as const;
type CoveragePhasesExact = AssertExact<typeof COVERAGE_PHASES[number], Exclude<keyof ScanCoverage, "criticalGaps">>;
const coveragePhaseListMatchesScanCoverage: CoveragePhasesExact = true;
const COVERAGE_STATUSES = ["measured", "unavailable", "skipped", "failed", "partial"] as const;
type CoverageStatusesExact = AssertExact<typeof COVERAGE_STATUSES[number], CoverageStatus>;
const coverageStatusListMatchesType: CoverageStatusesExact = true;
const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type FindingSeveritiesExact = AssertExact<typeof FINDING_SEVERITIES[number], Finding["severity"]>;
const findingSeverityListMatchesType: FindingSeveritiesExact = true;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // HEAD must behave like GET everywhere: without this, HEAD requests miss
    // the GET-only routes and asset fall-through and land in the JSON 404
    // handler, which breaks HEAD-based uptime checks. The runtime strips the
    // body of HEAD responses, so GET handlers stay correct.
    if (request.method === "HEAD") {
      request = new Request(request.url, { method: "GET", headers: request.headers });
    }
    const url = new URL(request.url);

    // Static assets are configured to run through this Worker first. Redirect
    // production HTTP requests before any API or asset handling so every path
    // (including assets and API endpoints) has one deterministic HTTPS hop.
    // Local development skips the redirect: `wrangler dev` emulates the
    // custom-domain host over plain HTTP, so an unconditional guard would
    // 308-loop every local request. api/.dev.vars sets ENVIRONMENT=development.
    if (env.ENVIRONMENT !== "development" && url.protocol === "http:" && !isLocalDevelopmentHost(url.hostname)) {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 308);
    }

    const origin = allowedOrigin(request, env.ALLOWED_ORIGINS || "");
    const cors = corsHeaders(origin);

    if (request.method === "OPTIONS") {
      if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403);
      return new Response(null, { status: 204, headers: { ...securityHeaders(), ...cors } });
    }

    try {
      if (url.pathname === "/mcp" || url.pathname === "/mcp/v2") {
        if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403, cors);
        const response = await handleMcp(request, async (tool, input) => {
          if (tool === "get_vulnscope_report") {
            const reportId = String(input.reportId || "");
            if (!REPORT_ID.test(reportId)) throw new InputError("A valid 16-character report ID is required.");
            const report = await loadReport(env.DB, reportId);
            if (!report) throw new InputError("Report not found or expired.");
            return report;
          }
          return createScan(request, {
            url: String(input.url || ""),
            probePaths: input.probePaths === true,
            checkTakeover: input.checkTakeover === true,
          }, env, ctx, () => {}, scanQuotaPolicy(env, "mcp"));
        });
        return addResponseHeaders(response, { ...securityHeaders(), ...cors });
      }

      // Let non-API GET requests fall through to static assets
      if (!url.pathname.startsWith("/api") && request.method === "GET") {
        const assetResponse = await env.ASSETS.fetch(request);
        const response = new Response(assetResponse.body, assetResponse);
        response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
        return response;
      }

      if ((url.pathname === "/api" || url.pathname === "/api/" || url.pathname === "/api/v2") && request.method === "GET") {
        return json({
          service: "VulnScanner API",
          version: API_VERSION,
          website: WEBSITE_ORIGIN,
          endpoints: {
            health: "GET /api/health",
            createScan: "POST /api/scans",
            streamScan: "POST /api/scans/stream",
            getScan: "GET /api/scans/:id",
            exportScan: "GET /api/scans/:id/export",
            v2Scan: "POST /api/v2/scan",
            mcp: "POST /mcp (also /mcp/v2)",
          },
        }, 200, cors);
      }

      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({
          ok: true,
          service: "vuln-scanner-api",
          version: API_VERSION,
          environment: env.ENVIRONMENT,
          protection: "rate-limit",
          time: new Date().toISOString(),
        }, 200, cors);
      }

      if ((url.pathname === "/api/scans" || url.pathname === "/api/scans/stream" || url.pathname === "/api/v2/scan") && request.method === "POST") {
        if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403, cors);
        const input = await readScanInput(request);
        if (url.pathname.endsWith("/stream")) {
          return streamScan(request, input, env, ctx, cors);
        }
        const report = await createScan(request, input, env, ctx);
        return json(report, 201, { ...cors, "Cache-Control": "no-store" });
      }

      const match = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9_-]+)(\/export)?$/);
      if (match && request.method === "GET") {
        if (!REPORT_ID.test(match[1])) return json({ error: "Report not found" }, 404, cors);
        const report = await loadReport(env.DB, match[1]);
        if (!report) return json({ error: "Report not found or expired" }, 404, cors);
        // Stored reports are immutable once written and the read-path
        // normalisation is deterministic, so a content hash is an honest
        // strong ETag; polling agents can revalidate instead of re-downloading.
        const ifNoneMatch = request.headers.get("If-None-Match");
        if (match[2]) {
          const format = url.searchParams.get("format");
          if (format && !["json", "markdown", "md"].includes(format)) {
            return json({ error: "Unsupported export format." }, 400, cors);
          }
          // Stored fields are trusted in aggregate but not per-field on
          // migrated or corrupted rows; never let them steer header syntax.
          const fileSlug = (value: string) => value.replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "report";
          if (format && format !== "json") {
            const markdown = reportToMarkdown(report);
            const etag = await etagFor(markdown);
            if (matchesIfNoneMatch(ifNoneMatch, etag)) return notModified(etag, cors);
            return new Response(markdown, {
              headers: {
                ...cors,
                "Content-Type": "text/markdown; charset=utf-8",
                "Content-Disposition": `attachment; filename="vulnscope-${fileSlug(report.hostname)}-${fileSlug(report.id)}.md"`,
                "Cache-Control": "private, no-store",
                ETag: etag,
                ...securityHeaders(),
              },
            });
          }
          const body = JSON.stringify(report, null, 2);
          const etag = await etagFor(body);
          if (matchesIfNoneMatch(ifNoneMatch, etag)) return notModified(etag, cors);
          return new Response(body, {
            headers: {
              ...cors,
              "Content-Type": "application/json; charset=utf-8",
              "Content-Disposition": `attachment; filename="vulnscope-${fileSlug(report.hostname)}-${fileSlug(report.id)}.json"`,
              "Cache-Control": "private, no-store",
              ETag: etag,
              ...securityHeaders(),
            },
          });
        }
        const body = JSON.stringify(report);
        const etag = await etagFor(body);
        if (matchesIfNoneMatch(ifNoneMatch, etag)) return notModified(etag, cors);
        return new Response(body, {
          status: 200,
          headers: {
            ...cors,
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "private, no-store",
            ETag: etag,
            ...securityHeaders(),
          },
        });
      }

      return json({ error: "Not found" }, 404, cors);
    } catch (error) {
      return errorResponse(error, cors);
    }
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cleanExpired(env.DB));
  },
};

function isLocalDevelopmentHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

interface ScanInput {
  url: string;
  probePaths: boolean;
  checkTakeover: boolean;
}

async function readScanInput(request: Request): Promise<ScanInput> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new InputError("Content-Type must be application/json.");
  }
  let bytes: Uint8Array;
  try {
    bytes = await readBoundedRequestBody(request, MAX_REQUEST_BYTES);
  } catch (error) {
    if (error instanceof RequestBodyError) {
      throw new InputError(error.code === "missing" ? "Request body is required." : "Request body is too large.");
    }
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeUtf8(bytes));
  } catch {
    throw new InputError("Invalid JSON request body.");
  }
  if (!parsed || typeof parsed !== "object") throw new InputError("JSON request body must be an object.");
  const body = parsed as Record<string, unknown>;
  const allowedKeys = new Set(["url", "probePaths", "checkTakeover"]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key))) {
    throw new InputError("JSON request body contains an unsupported field.");
  }
  if (typeof body.url !== "string") throw new InputError("A URL is required.");
  if (body.probePaths !== undefined && typeof body.probePaths !== "boolean") {
    throw new InputError("probePaths must be a boolean.");
  }
  if (body.checkTakeover !== undefined && typeof body.checkTakeover !== "boolean") {
    throw new InputError("checkTakeover must be a boolean.");
  }
  return {
    url: body.url,
    probePaths: body.probePaths === true,
    checkTakeover: body.checkTakeover === true,
  };
}

async function createScan(
  request: Request,
  input: ScanInput,
  env: Env,
  ctx: ExecutionContext,
  onProgress: (event: AnalyzerProgress) => void = () => {},
  quota: QuotaPolicy = scanQuotaPolicy(env, "web"),
): Promise<ScanReport> {
  const normalized = normalizeUrl(input.url);
  if (normalized.hostname === new URL(request.url).hostname) {
    throw new BlockedTargetError(
      "VulnScope cannot scan its own hostname from inside the same Cloudflare Worker. Use a different public target.",
    );
  }
  // Serve a cached recent scan before the quota counter so repeat requests do
  // not burn the caller's daily allowance on work that was already done.
  // Validation failures above are likewise uncharged; failed target scans
  // remain charged because the analysis actually ran.
  const cacheKey = await recentScanCacheKey(request.url, normalized.toString(), input.probePaths, input.checkTakeover);
  const recentCache = await caches.open("vuln-scanner-recent");
  const cached = await recentCache.match(cacheKey);
  if (cached) {
    const cachedReport = upgradeStoredReport(await cached.json<unknown>());
    if (cachedReport) {
      onProgress({ stage: "complete", message: "Loaded a recent scan" });
      return cachedReport;
    }
  }
  await enforceRateLimit(request, env, quota);

  const retention = clampInt(env.REPORT_RETENTION_DAYS, 14, 1, 90);
  const incomingCf = request.cf as Record<string, unknown> | undefined;
  const report = await analyzeUrl(
    input.url,
    retention,
    {
      colo: typeof incomingCf?.colo === "string" ? incomingCf.colo : undefined,
      country: typeof incomingCf?.country === "string" ? incomingCf.country : undefined,
    },
    onProgress,
    {
      probePaths: input.probePaths,
      checkTakeover: input.checkTakeover,
      maxPaths: clampInt(env.MAX_PATH_PROBES, 18, 0, 18),
      maxSubrequests: clampInt(env.MAX_SCAN_SUBREQUESTS, 46, 20, 46),
      maxConcurrent: clampInt(env.MAX_SCAN_CONCURRENCY, 6, 1, 6),
      maxDurationMs: clampInt(env.MAX_SCAN_DURATION_MS, 25_000, 5_000, 25_000),
    },
  );
  await saveReport(env.DB, report);
  const cacheResponse = new Response(JSON.stringify(report), {
    headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${RECENT_SCAN_TTL}` },
  });
  ctx.waitUntil(recentCache.put(cacheKey, cacheResponse));
  return report;
}

function streamScan(
  request: Request,
  input: ScanInput,
  env: Env,
  ctx: ExecutionContext,
  cors: Record<string, string>,
): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (value: unknown) => controller.enqueue(encoder.encode(`${JSON.stringify(value)}\n`));
      try {
        send({ type: "progress", stage: "accepted", message: "Scan accepted" });
        const report = await createScan(request, input, env, ctx, (event) => send({ type: "progress", ...event }));
        send({ type: "result", report });
      } catch (error) {
        const normalized = normalizeError(error);
        send({ type: "error", error: normalized.message, status: normalized.status });
      } finally {
        controller.close();
      }
    },
  });
  return new Response(stream, {
    status: 200,
    headers: {
      ...cors,
      ...securityHeaders(),
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function recentScanCacheKey(
  requestUrl: string,
  targetUrl: string,
  probePaths: boolean,
  checkTakeover: boolean,
): Promise<Request> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${targetUrl}:${probePaths}:${checkTakeover}`));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const base = new URL(requestUrl);
  return new Request(`${base.origin}/__recent_scan/${hash}`, { method: "GET" });
}

export interface QuotaPolicy {
  scope: string;
  limit: number;
  label: string;
}

/**
 * Web-form and agent scans draw from separate per-IP daily buckets so one
 * caller class cannot exhaust the other's allowance. Both are charged through
 * the same atomic D1 counter.
 */
export function scanQuotaPolicy(env: Env, source: "web" | "mcp"): QuotaPolicy {
  return source === "mcp"
    ? { scope: "mcp", limit: clampInt(env.MCP_DAILY_LIMIT, 50, 1, 1000), label: "Daily MCP scan limit" }
    : { scope: "scan", limit: clampInt(env.DAILY_SCAN_LIMIT, 10, 1, 500), label: "Daily scan limit" };
}

function enforceRateLimit(request: Request, env: Env, quota: QuotaPolicy): Promise<void> {
  return enforceScopedDailyRateLimit(request, env, quota.scope, quota.limit, quota.label);
}

async function enforceScopedDailyRateLimit(request: Request, env: Env, scope: string, limit: number, label: string): Promise<void> {
  const date = new Date().toISOString().slice(0, 10);
  const ip = request.headers.get("CF-Connecting-IP") || "local";
  const key = await deriveDailyQuotaKey({
    scope,
    date,
    clientAddress: ip,
    secret: env.RATE_LIMIT_HMAC_KEY,
  });
  const now = new Date().toISOString();
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits (client_key, window_date, request_count, updated_at)
    VALUES (?, ?, 1, ?)
    ON CONFLICT(client_key, window_date)
    DO UPDATE SET request_count = request_count + 1, updated_at = excluded.updated_at
    RETURNING request_count
  `).bind(key, date, now).first<{ request_count: number }>();
  const count = row?.request_count || 1;
  const resetAt = `${date}T23:59:59.999Z`;
  if (count > limit) throw new RateLimitError(`${label} of ${limit} reached.`, limit, count, resetAt);
}

async function saveReport(db: D1Database, report: ScanReport): Promise<void> {
  await db.prepare(`
    INSERT INTO scans (
      id, normalized_url, hostname, status, schema_version,
      duration_ms, report_json, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    report.id,
    report.requestedUrl,
    report.hostname,
    report.status,
    report.schemaVersion,
    report.totalDurationMs,
    JSON.stringify(report),
    report.createdAt,
    report.expiresAt,
  ).run();
}

async function loadReport(db: D1Database, id: string): Promise<ScanReport | null> {
  const row = await db.prepare(`
    SELECT report_json FROM scans WHERE id = ? AND expires_at > ?
  `).bind(id, new Date().toISOString()).first<{ report_json: string }>();
  if (!row) return null;
  // Shape-invalid rows already read as not-found via upgradeStoredReport;
  // keep syntax-corrupt rows on the same honest path instead of surfacing
  // scan-failure language from a read endpoint.
  try {
    return upgradeStoredReport(JSON.parse(row.report_json));
  } catch {
    return null;
  }
}

function upgradeStoredReport(raw: unknown): ScanReport | null {
  if (!raw || typeof raw !== "object") return null;
  const report = raw as Omit<Partial<ScanReport>, "schemaVersion"> & { schemaVersion?: number; url?: string };
  if (report.schemaVersion === REPORT_SCHEMA_VERSION) {
    if (!isValidStoredV2Report(report)) return null;

    const storedReport = report as ScanReport;
    const outbound = storedReport.outbound
      ? storedReport.outbound
      : emptyOutboundSummary();
    const previousCriticalGaps = storedReport.coverage.criticalGaps;
    const coverage: ScanCoverage = {
      ...storedReport.coverage,
      criticalGaps: gradeBlockingCoverageGaps(storedReport.coverage),
    };
    const status = normalizeStoredV2Status(storedReport.status, previousCriticalGaps, coverage);

    return {
      ...storedReport,
      requestedUrl: redactUrlForStorage(storedReport.requestedUrl),
      outbound,
      status,
      coverage,
      summary: buildSummary(storedReport.findings, coverage),
    };
  }
  if (report.schemaVersion !== 1) return null;

  // Schema 1 reports predate explicit coverage and may have been graded from
  // incomplete evidence. Preserve their observations but intentionally mark
  // them as migrated and not gradeable instead of silently presenting an A.
  const coverage = legacyCoverage();
  return {
    ...report,
    schemaVersion: REPORT_SCHEMA_VERSION,
    requestedUrl: report.requestedUrl || report.url
      ? redactUrlForStorage(String(report.requestedUrl || report.url))
      : "[legacy URL unavailable]",
    status: report.status === "failed" ? "failed" : "partial",
    coverage,
    observation: {
      ...(report.observation || { vantage: "cloudflare-edge" }),
      disclaimer: `${report.observation?.disclaimer || "Legacy report."} This legacy schema was migrated without coverage metadata and is not graded.`,
    },
    summary: {
      ...(report.summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
      grade: "INCOMPLETE",
    },
    outbound: emptyOutboundSummary(),
  } as ScanReport;
}

function isValidStoredV2Report(report: Record<string, unknown>): boolean {
  const coverage = report.coverage;
  if (!coverage || typeof coverage !== "object") return false;
  const typedCoverage = coverage as Record<string, unknown>;

  return (
    (report.status === "complete" || report.status === "partial" || report.status === "failed") &&
    typeof report.requestedUrl === "string" &&
    Array.isArray(typedCoverage.criticalGaps) &&
    typedCoverage.criticalGaps.every((gap) => typeof gap === "string") &&
    COVERAGE_PHASES.every((phase) => isValidCoveragePhase(typedCoverage[phase])) &&
    Array.isArray(report.findings) &&
    report.findings.every(isValidFinding) &&
    (report.outbound === undefined || isValidOutboundSummary(report.outbound))
  );
}

function isValidOutboundSummary(value: unknown): value is OutboundRequestSummary {
  if (!value || typeof value !== "object") return false;
  const outbound = value as Record<string, unknown>;
  const counters = [
    "maxSubrequests",
    "maxConcurrent",
    "maxDurationMs",
    "requestsAttempted",
    "requestsSucceeded",
    "requestsFailed",
    "requestsSkipped",
    "activePeak",
    "bodyBytes",
    "truncatedBodies",
  ];
  return counters.every((key) => typeof outbound[key] === "number" && Number.isFinite(outbound[key]) && (outbound[key] as number) >= 0)
    && Array.isArray(outbound.redirects)
    && outbound.redirects.every((redirect) => {
      if (!redirect || typeof redirect !== "object") return false;
      const value = redirect as Record<string, unknown>;
      return typeof value.from === "string" && typeof value.to === "string" && typeof value.status === "number";
    });
}

function emptyOutboundSummary(): OutboundRequestSummary {
  return {
    maxSubrequests: 46,
    maxConcurrent: 6,
    maxDurationMs: 25_000,
    requestsAttempted: 0,
    requestsSucceeded: 0,
    requestsFailed: 0,
    requestsSkipped: 0,
    activePeak: 0,
    bodyBytes: 0,
    truncatedBodies: 0,
    redirects: [],
  };
}

function isValidCoveragePhase(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const phase = value as Record<string, unknown>;
  return (
    typeof phase.status === "string" &&
    COVERAGE_STATUSES.includes(phase.status as typeof COVERAGE_STATUSES[number]) &&
    typeof phase.detail === "string"
  );
}

function isValidFinding(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const finding = value as Record<string, unknown>;
  return (
    typeof finding.severity === "string" &&
    FINDING_SEVERITIES.includes(finding.severity as typeof FINDING_SEVERITIES[number]) &&
    typeof finding.id === "string" &&
    typeof finding.category === "string" &&
    typeof finding.title === "string" &&
    typeof finding.detail === "string" &&
    typeof finding.evidence === "string" &&
    typeof finding.recommendation === "string"
  );
}

function normalizeStoredV2Status(
  status: ScanReport["status"],
  previousCriticalGaps: string[],
  coverage: ScanCoverage,
): ScanReport["status"] {
  if (status === "failed") return status;
  if (coverage.criticalGaps.length > 0) return "partial";
  if (status !== "partial" || previousCriticalGaps.length === 0) return status;

  return previousCriticalGaps.every((gap) =>
    /^(tlsProtocolCipher|certificateEvidence):/.test(gap),
  ) ? "complete" : status;
}

function legacyCoverage(): ScanCoverage {
  const unavailable = (detail: string) => ({ status: "unavailable" as const, detail });
  const skipped = (detail: string) => ({ status: "skipped" as const, detail });
  const coverage: ScanCoverage = {
    mainFetch: unavailable("Legacy report has no explicit main-fetch coverage metadata."),
    headers: unavailable("Legacy report has no explicit header coverage metadata."),
    tlsProtocolCipher: unavailable("Legacy report may contain untrusted TLS metadata; it is not used after migration."),
    certificateEvidence: unavailable("Legacy report has no explicit certificate evidence provenance."),
    dns: unavailable("Legacy report has no explicit DNS coverage metadata."),
    cookies: skipped("Legacy report has no explicit cookie coverage metadata."),
    paths: skipped("Legacy report has no explicit path coverage metadata."),
    cors: skipped("Legacy report has no explicit CORS coverage metadata."),
    secrets: skipped("Legacy report has no explicit secret coverage metadata."),
    wordpress: skipped("Legacy report has no explicit WordPress coverage metadata."),
    methods: skipped("Legacy report has no explicit method coverage metadata."),
    takeover: skipped("Legacy report has no explicit takeover coverage metadata."),
    criticalGaps: [],
  };
  coverage.criticalGaps = gradeBlockingCoverageGaps(coverage);
  return coverage;
}

async function cleanExpired(db: D1Database): Promise<void> {
  const today = new Date().toISOString();
  await db.batch([
    db.prepare("DELETE FROM scans WHERE expires_at <= ?").bind(today),
    db.prepare("DELETE FROM rate_limits WHERE window_date < date('now', '-2 day')"),
  ]);
}

function clampInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

async function etagFor(payload: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `"${hash.slice(0, 32)}"`;
}

/**
 * Strong comparison only (RFC 9110 §8.8.3.2): a weak-tagged or syntactically
 * different validator never matches, and "*" means "any representation exists".
 */
function matchesIfNoneMatch(headerValue: string | null, etag: string): boolean {
  if (!headerValue) return false;
  return headerValue.split(",").some((tag) => tag.trim() === "*" || tag.trim() === etag);
}

function notModified(etag: string, cors: Record<string, string>): Response {
  return new Response(null, {
    status: 304,
    headers: { ...cors, ...securityHeaders(), "Cache-Control": "private, no-store", ETag: etag },
  });
}

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    ...(origin ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {}),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id",
    "Access-Control-Max-Age": "86400",
  };
}

function securityHeaders(): Record<string, string> {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
  };
}

function normalizeError(error: unknown): { status: number; message: string } {
  if (
    error instanceof InputError ||
    error instanceof BlockedTargetError ||
    error instanceof ResolverUnavailableError
  )
    return { status: error.status, message: error.message };
  if (error instanceof RateLimitError) return { status: 429, message: error.message };
  console.error("scan_failed", error);
  return { status: 500, message: "The scan could not be completed. Please try again." };
}

function errorResponse(error: unknown, cors: Record<string, string>): Response {
  const normalized = normalizeError(error);
  if (error instanceof RateLimitError) {
    // Agents need the quota state in the payload, not only in headers they
    // may not inspect, so the 429 body carries the same numbers.
    const retrySeconds = Math.max(1, Math.ceil((Date.parse(error.resetAt) - Date.now()) / 1000));
    return json({
      error: normalized.message,
      limit: error.limit,
      remaining: Math.max(0, error.limit - error.count),
      resetAt: error.resetAt,
    }, normalized.status, {
      ...cors,
      "RateLimit-Limit": String(error.limit),
      "RateLimit-Remaining": "0",
      "RateLimit-Reset": String(Math.max(0, Math.ceil((Date.parse(error.resetAt) - Date.now()) / 1000))),
      "Retry-After": String(retrySeconds),
    });
  }
  return json({ error: normalized.message }, normalized.status, {
    ...cors,
  });
}

function json(payload: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...securityHeaders(),
      ...extra,
    },
  });
}

function addResponseHeaders(response: Response, extra: Record<string, string>): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
