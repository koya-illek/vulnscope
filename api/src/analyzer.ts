import { inspectDns, queryDnsWithFallback } from "./dns";
import { getDomain } from "tldts";
import { inspectSsl } from "./ssl";
import { probePaths } from "./paths";
import { auditHeaders } from "./headers-audit";
import { fingerprint } from "./fingerprint";
import { auditCookies } from "./cookies";
import { testCors } from "./cors";
import { scanForSecrets } from "./secrets";
import { scanWordPress } from "./wordpress";
import { probeMethods } from "./methods";
import { buildSummary, exposedPathFindings, gradeBlockingCoverageGaps, methodFindings, tlsFindings } from "./scorer";
import {
  BlockedTargetError,
  InputError,
  isPublicIp,
  normalizeUrl,
  redactUrlForStorage,
  ResolverUnavailableError,
} from "./security";
import type {
  CookieAuditResult,
  CoveragePhase,
  CorsResult,
  ExposedPath,
  Finding,
  FingerprintResult,
  HeaderAuditResult,
  MethodResult,
  ScanReport,
  ScanCoverage,
  SecretFinding,
  SslDetail,
  WpFinding,
} from "./types";
import {
  createOutboundContext,
  infrastructureFetch,
  phaseStats,
  readBoundedBody,
  safeFetch,
  setOutboundPhase,
  USER_AGENT,
  type OutboundContext,
} from "./outbound";

export interface AnalyzerProgress {
  stage:
    | "validated"
    | "dns"
    | "fetch"
    | "ssl"
    | "fingerprint"
    | "headers"
    | "cookies"
    | "paths"
    | "cors"
    | "secrets"
    | "wordpress"
    | "methods"
    | "takeover"
    | "complete";
  message: string;
  phase?: string;
  progress?: number;
}

export interface AnalyzerOptions {
  probePaths: boolean;
  checkTakeover: boolean;
  maxPaths?: number;
  maxSubrequests?: number;
  maxConcurrent?: number;
  maxDurationMs?: number;
}

const MAX_BODY_BYTES = 256 * 1024;

export async function analyzeUrl(
  rawUrl: unknown,
  retentionDays: number,
  observer: { colo?: string; country?: string } = {},
  onProgress: (event: AnalyzerProgress) => void = () => {},
  options: AnalyzerOptions = { probePaths: false, checkTakeover: false },
): Promise<ScanReport> {
  const started = performance.now();
  const initial = normalizeUrl(rawUrl);
  const outbound = createOutboundContext({
    maxSubrequests: options.maxSubrequests,
    maxConcurrent: options.maxConcurrent,
    maxDurationMs: options.maxDurationMs,
  });
  let lastProgress = 0;
  const emit = (event: AnalyzerProgress) => {
    const progressByStage: Record<AnalyzerProgress["stage"], number> = {
      validated: 4, dns: 12, fetch: 24, ssl: 30, fingerprint: 36, headers: 44,
      cookies: 50, paths: 60, cors: 67, secrets: 74, wordpress: 81,
      methods: 87, takeover: 94, complete: 100,
    };
    lastProgress = Math.max(lastProgress, progressByStage[event.stage]);
    onProgress({ ...event, phase: event.stage, progress: lastProgress });
  };
  emit({ stage: "validated", message: `Validated ${initial.hostname}` });

  const id = randomId();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + retentionDays * 86_400_000);

  // --- DNS ---
  setOutboundPhase(outbound, "dns");
  const dnsQueries = await inspectDns(initial.hostname, outbound);
  assertPublicResolution(initial.hostname, dnsQueries);
  outbound.addresses.set(initial.hostname, addressAnswers(dnsQueries));
  const coverage: ScanCoverage = emptyCoverage();
  const dnsStats = phaseStats(outbound, "dns");
  const dnsPartial = dnsStats.failed > 0 || dnsStats.skipped > 0 || dnsStats.truncated;
  coverage.dns = {
    status: dnsPartial ? "partial" : "measured",
    detail: `Public DNS resolution confirmed ${addressAnswers(dnsQueries).length} address record(s).${dnsPartial ? " Some resolver observations did not complete within the safe budget." : ""}`,
    requested: true,
    ...statsMetadata(outbound, "dns"),
  };
  emit({ stage: "dns", message: `Resolved ${addressAnswers(dnsQueries).length} address records` });

  // --- Fetch the main page ---
  let response: Response | null = null;
  let bodyText = "";
  let status: ScanReport["status"] = "complete";

  try {
    setOutboundPhase(outbound, "mainFetch");
    response = await safeFetch(initial.toString(), {
      method: "GET",
      baseUrl: initial,
      context: outbound,
      phase: "mainFetch",
      cache: "no-store",
      headers: {
        Accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
        "User-Agent": USER_AGENT,
      },
      timeoutMs: 15_000,
    });
    if (!response.ok) {
      const httpStatus = response.status;
      await response.body?.cancel();
      response = null;
      status = "failed";
      coverage.mainFetch = {
        status: "failed",
        detail: `GET returned HTTP ${httpStatus}. VulnScope did not treat that error response as the target page or grade its headers.`,
        requested: true,
        ...statsMetadata(outbound, "mainFetch"),
      };
      emit({
        stage: "fetch",
        message: `Main page unavailable with HTTP ${httpStatus}`,
      });
    } else {
      const bodyResult = await readBoundedBody(
        response,
        MAX_BODY_BYTES,
        outbound,
        "mainFetch",
      );
      bodyText = bodyResult.text;
      coverage.mainFetch = {
        status: bodyResult.truncated ? "partial" : "measured",
        detail: `GET response received with HTTP ${response.status}${bodyResult.truncated ? "; body truncated at the phase limit" : ""}.`,
        requested: true,
        attempts: phaseStats(outbound, "mainFetch").attempts,
        succeeded: phaseStats(outbound, "mainFetch").succeeded,
        failed: phaseStats(outbound, "mainFetch").failed,
        skipped: phaseStats(outbound, "mainFetch").skipped,
        bytes: bodyResult.bytes,
        truncated: bodyResult.truncated,
      };
      emit({
        stage: "fetch",
        message: `Fetched ${response.status} from ${initial.hostname}`,
      });
    }
  } catch (error) {
    status = "failed";
    coverage.mainFetch = {
      status: "failed",
      detail: `GET failed: ${error instanceof Error ? error.message : "unknown error"}`,
      requested: true,
      ...statsMetadata(outbound, "mainFetch"),
    };
    emit({ stage: "fetch", message: `Fetch failed: ${error instanceof Error ? error.message : "unknown error"}` });
  }

  // --- SSL ---
  setOutboundPhase(outbound, "certificateEvidence");
  const ssl: SslDetail = await inspectSsl(initial.hostname, response, outbound);
  coverage.tlsProtocolCipher = {
    status: "unavailable",
    detail: "Origin TLS protocol/cipher was not assessed because Cloudflare Worker fetches do not expose the scanned origin's negotiated TLS protocol or cipher, and no active TLS probe was run.",
  };
  coverage.certificateEvidence = ssl.certificateEvidence.status === "observed"
    ? { status: "measured", detail: `${ssl.certificateEvidence.source} returned historical certificate-transparency evidence only. ${ssl.certificateEvidence.limitation}` }
    : { status: "unavailable", detail: `Certificate-transparency evidence was unavailable. ${ssl.certificateEvidence.limitation}` };
  emit({ stage: "ssl", message: ssl.protocol ? `TLS: ${ssl.protocol}` : "TLS data unavailable" });

  // --- Header audit ---
  // Header/cookie auditing runs before fingerprinting so emitted progress
  // stages stay in the advertised order (headers, fingerprint, paths).
  const { result: headerResult, findings: headerFindings } = response
    ? auditHeaders(response.headers)
    : { result: emptyHeaderResult(), findings: [] as Finding[] };
  coverage.headers = response
    ? { status: "measured", detail: "Security headers were audited from the main GET response.", requested: true }
    : { status: "skipped", detail: "Security header audit skipped because the main fetch failed.", requested: true };
  emit({ stage: "headers", message: `Header audit: ${headerFindings.length} findings` });

  // --- Cookies ---
  const { cookies, findings: cookieFindings } = response
    ? auditCookies(response.headers)
    : { cookies: [] as CookieAuditResult[], findings: [] as Finding[] };
  coverage.cookies = response
    ? { status: "measured", detail: `Audited ${cookies.length} cookie(s) from the main GET response.`, requested: true }
    : { status: "skipped", detail: "Cookie audit skipped because the main fetch failed.", requested: true };
  emit({ stage: "cookies", message: `Cookies: ${cookies.length} audited` });

  // --- Fingerprint ---
  const { result: fingerprintResult, findings: fingerprintFindings } = response
    ? fingerprint(response.headers, bodyText)
    : { result: emptyFingerprint(), findings: [] as Finding[] };
  emit({ stage: "fingerprint", message: fingerprintResult.cms ? `CMS: ${fingerprintResult.cms.name}` : "Fingerprint complete" });

  // --- Exposed paths ---
  let exposedPaths: ExposedPath[] = [];
  if (options.probePaths && status !== "failed") {
    setOutboundPhase(outbound, "paths");
    try {
      exposedPaths = await probePaths({ baseUrl: initial, homepageBody: bodyText, context: outbound, maxPaths: options.maxPaths });
      coverage.paths = phaseCoverage(outbound, "paths", `Sensitive path probes completed with ${exposedPaths.length} response(s).`, true);
    } catch (error) {
      coverage.paths = { status: "failed", detail: `Sensitive path probing failed: ${error instanceof Error ? error.message : "unknown error"}`, requested: true, ...statsMetadata(outbound, "paths") };
    }
    emit({ stage: "paths", message: `Exposed paths: ${exposedPaths.length} found` });
  } else {
    coverage.paths = { status: "skipped", detail: "Sensitive path probing was not enabled for this scan.", requested: false };
    emit({ stage: "paths", message: "Path probing skipped" });
  }

  // --- CORS ---
  let cors: CorsResult;
  let corsFindings: Finding[];
  if (status !== "failed") {
    setOutboundPhase(outbound, "cors");
    const corsOutcome = await testCors(initial.toString(), outbound);
    cors = corsOutcome.result;
    corsFindings = corsOutcome.findings;
    coverage.cors = phaseCoverage(outbound, "cors", "GET and OPTIONS CORS probes completed.", true);
    emit({ stage: "cors", message: cors.vulnerable ? "CORS misconfiguration detected" : "CORS OK" });
  } else {
    cors = {
      testedOrigin: "https://evil.example",
      acaoGet: null,
      acaoOptions: null,
      acacGet: null,
      acacOptions: null,
      reflectsOrigin: false,
      wildcardWithCredentials: false,
      vulnerable: false,
      evidence: "CORS test skipped (fetch failed)",
    };
    corsFindings = [];
    coverage.cors = { status: "skipped", detail: "CORS probes skipped because the main fetch failed.", requested: false };
    emit({ stage: "cors", message: "CORS test skipped" });
  }

  // --- Secret detection (Phase 5b) ---
  let secretFindings: SecretFinding[] = [];
  if (status !== "failed" && bodyText) {
    setOutboundPhase(outbound, "secrets");
    const bundles = await extractJsBundles(initial, bodyText, outbound);
    secretFindings = await scanForSecrets(bundles);
    coverage.secrets = phaseCoverage(outbound, "secrets", `Scanned ${bundles.length} JavaScript bundle(s) for exposed secrets.`, true);
    emit({ stage: "secrets", message: `Secret scan: ${secretFindings.length} findings in ${bundles.length} JS bundles` });
  } else {
    coverage.secrets = { status: "skipped", detail: "Secret scanning skipped because the main fetch failed.", requested: false };
    emit({ stage: "secrets", message: "Secret scan skipped" });
  }

  // --- WordPress checks (Phase 5c) ---
  let wpFindings: WpFinding[] = [];
  if (status !== "failed" && fingerprintResult.cms?.name === "WordPress" && response) {
    setOutboundPhase(outbound, "wordpress");
    wpFindings = await scanWordPress(initial, bodyText, outbound);
    coverage.wordpress = phaseCoverage(outbound, "wordpress", `WordPress checks completed with ${wpFindings.length} finding(s).`, true);
    emit({ stage: "wordpress", message: `WordPress scan: ${wpFindings.length} findings` });
  } else {
    coverage.wordpress = { status: "skipped", detail: "WordPress checks skipped because the target was not identified as WordPress or the main fetch failed.", requested: false };
    emit({ stage: "wordpress", message: "WordPress scan skipped (not WordPress)" });
  }

  // --- HTTP methods (Phase 5d) ---
  let methodResults: { methods: MethodResult[]; traceVulnerable: boolean };
  if (status !== "failed") {
    setOutboundPhase(outbound, "methods");
    methodResults = await probeMethods(initial.toString(), outbound);
    coverage.methods = phaseCoverage(outbound, "methods", "OPTIONS Allow and non-mutating TRACE reconnaissance completed.", true);
    emit({ stage: "methods", message: methodResults.traceVulnerable ? "XST vulnerability detected" : `HTTP methods: ${methodResults.methods.length} allowed` });
  } else {
    methodResults = { methods: [], traceVulnerable: false };
    coverage.methods = { status: "skipped", detail: "HTTP method reconnaissance skipped because the main fetch failed.", requested: false };
    emit({ stage: "methods", message: "HTTP methods skipped" });
  }

  // --- Subdomain takeover (optional) ---
  let takeover: ScanReport["takeover"] = undefined;
  if (options.checkTakeover) {
    setOutboundPhase(outbound, "takeover");
    try {
      takeover = await checkSubdomainTakeover(initial.hostname, outbound);
      coverage.takeover = phaseCoverage(outbound, "takeover", `Subdomain takeover checks completed for ${takeover.length} subdomain(s).`, true);
    } catch (error) {
      takeover = [];
      coverage.takeover = { status: "failed", detail: `Subdomain takeover checks failed: ${error instanceof Error ? error.message : "unknown error"}`, requested: true, ...statsMetadata(outbound, "takeover") };
    }
    emit({ stage: "takeover", message: `Takeover check: ${takeover.length} subdomains checked` });
  } else {
    coverage.takeover = { status: "skipped", detail: "Subdomain takeover checks were not enabled for this scan.", requested: false };
  }

  // --- Aggregate findings ---
  const findings: Finding[] = [
    ...tlsFindings(ssl.protocol, ssl.daysUntilExpiry, false),
    ...fingerprintFindings,
    ...headerFindings,
    ...cookieFindings,
    ...corsFindings,
    ...exposedPathFindings(exposedPaths),
    ...secretFindingsAsFindings(secretFindings),
    ...wpFindingsAsFindings(wpFindings),
    ...methodFindings(methodResults),
  ];

  if (takeover) {
    for (const t of takeover) {
      if (t.vulnerable) {
        findings.push({
          id: `takeover-${t.subdomain}`,
          severity: "high",
          category: "takeover",
          title: `Subdomain Takeover Risk: ${t.subdomain}`,
          detail: `The subdomain ${t.subdomain} points to ${t.cname || "an unresolvable service"} and may be vulnerable to takeover.`,
          evidence: t.evidence,
          recommendation: "Remove the dangling DNS record or reclaim the referenced service.",
        });
      }
    }
  }

  coverage.criticalGaps = gradeBlockingCoverageGaps(coverage);
  if (status === "complete" && coverage.criticalGaps.length > 0) status = "partial";
  const summary = buildSummary(findings, coverage);
  emit({ stage: "complete", message: `Scan complete: grade ${summary.grade}` });

  return {
    schemaVersion: 2,
    id,
    requestedUrl: redactUrlForStorage(initial.toString()),
    hostname: initial.hostname,
    status,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    totalDurationMs: Math.round(performance.now() - started),
    observation: {
      vantage: "cloudflare-edge",
      colo: observer.colo,
      country: observer.country,
      disclaimer: "Observations are from the Cloudflare edge. Timings do not represent browser-side performance.",
    },
    outbound: outbound.budget.snapshot(),
    coverage,
    dns: {
      queries: dnsQueries,
      addresses: addressAnswers(dnsQueries),
      dnssecAuthenticated: dnsQueries.some((q) => q.authenticatedData),
    },
    ssl,
    fingerprint: fingerprintResult,
    headers: headerResult,
    cookies,
    exposedPaths,
    cors,
    takeover,
    secrets: secretFindings.length > 0 ? secretFindings : undefined,
    wordpress: wpFindings.length > 0 ? wpFindings : undefined,
    methods: methodResults.methods.length > 0 || methodResults.traceVulnerable ? methodResults : undefined,
    findings,
    summary,
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function assertPublicResolution(hostname: string, queries: Awaited<ReturnType<typeof inspectDns>>): void {
  const addresses = addressAnswers(queries);
  if (addresses.length === 0) {
    const addressQueries = queries.filter(
      (query) => query.type === "A" || query.type === "AAAA",
    );
    if (
      addressQueries.length > 0 &&
      addressQueries.every((query) => query.status === -1)
    ) {
      throw new ResolverUnavailableError(
        `Public DNS resolvers were unavailable while checking ${hostname}. Try the scan again.`,
      );
    }
    throw new BlockedTargetError(`No public A or AAAA address could be confirmed for ${hostname}.`);
  }
  const blocked = addresses.filter((address) => !isPublicIp(address));
  if (blocked.length > 0) {
    throw new BlockedTargetError("The hostname resolves to a private or reserved network address.");
  }
}

function addressAnswers(queries: Awaited<ReturnType<typeof inspectDns>>): string[] {
  return [...new Set(queries.flatMap((query) =>
    query.answers.filter((answer) => answer.type === "A" || answer.type === "AAAA").map((answer) => answer.data),
  ))];
}

async function checkSubdomainTakeover(hostname: string, context?: OutboundContext): Promise<NonNullable<ScanReport["takeover"]>> {
  // Query DNS for CNAME records that might point to dangling services.
  // Provider failures must propagate so coverage records failed work instead
  // of a measured zero; only an empty-but-valid CT answer is legitimate.
  const results: NonNullable<ScanReport["takeover"]> = [];

  {
    const crtResponse = await infrastructureFetch(
      `https://crt.sh/?q=${encodeURIComponent(`%.${hostname}`)}&output=json`,
      context,
      { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(8000) },
      "takeover",
    );
    if (!crtResponse.ok) {
      throw new Error(`Certificate Transparency lookup returned HTTP ${crtResponse.status}.`);
    }
    const entries = JSON.parse((await readBoundedBody(crtResponse, 256 * 1024, context, "takeover")).text) as Array<{ name_value: string }>;
    const targetDomain = getDomain(hostname, { allowPrivateDomains: true });
    const subdomains = [...new Set(
      entries
        .flatMap((e) => e.name_value?.split("\n") || [])
        .map((s) => s.trim().replace(/\.$/, ""))
        .filter((s) => s && s !== hostname && !s.includes("*") && getDomain(s, { allowPrivateDomains: true }) === targetDomain),
    )].slice(0, 10);

    for (const subdomain of subdomains) {
      try {
        const cnameResult = await queryDnsWithFallback(subdomain, "CNAME", context);
        const cname = cnameResult.answers.find((a) => a.type === "CNAME")?.data || null;
        const aResult = await queryDnsWithFallback(subdomain, "A", context);
        const aaaaResult = await queryDnsWithFallback(subdomain, "AAAA", context);
        const addresses = [...aResult.answers, ...aaaaResult.answers].filter((answer) => answer.type === "A" || answer.type === "AAAA");
        const resolvable = addresses.length > 0;
        const resolverState = [aResult.status, aaaaResult.status].some((status) => status === 2 || status < 0)
          ? "incomplete"
          : [aResult.status, aaaaResult.status].every((status) => status === 3)
            ? "nxdomain"
            : "nodata-or-resolved";

        let httpStatus: number | null = null;
        let vulnerable = false;
        let evidence = "";

        if (cname && !resolvable && resolverState === "nxdomain") {
          // A CNAME plus confirmed NXDOMAIN is only a possible dangling
          // record. It is not enough evidence for a critical takeover claim.
          evidence = `CNAME ${cname} has no confirmed A or AAAA address; resolver state NXDOMAIN`;
        }

        if (cname && resolvable) {
          try {
            const target = `https://${subdomain}`;
            const resp = await safeFetch(target, {
              baseUrl: new URL(`https://${hostname}`),
              allowCrossHost: true,
              context,
              phase: "takeover",
              followRedirects: false,
              timeoutMs: 5000,
            });
            httpStatus = resp.status;
            const body = (await readBoundedBody(resp, 32 * 1024, context, "takeover")).text;
            // Check for known takeover fingerprints
            const takeoverSignatures = [
              "NoSuchBucket",
              "Repository not found",
              "no such app",
              "There isn't a GitHub Pages site here",
              " ApplicationUserProxy",
              "The specified bucket does not exist",
            ];
            if (takeoverSignatures.some((sig) => body.includes(sig))) {
              vulnerable = true;
              evidence = `HTTP ${resp.status} body contains a provider takeover signature`;
            }
          } catch {
            // Connection failed — not necessarily vulnerable
          }
        }

        results.push({
          subdomain,
          cname,
          resolvable,
          httpStatus,
          vulnerable,
          evidence: evidence || "No takeover indicators found",
          confidence: vulnerable ? "high" : evidence ? "low" : "none",
          resolverState,
        });
      } catch {
        // Skip individual subdomain errors
      }
    }
  }

  return results;
}

function emptyFingerprint(): FingerprintResult {
  return { server: null, poweredBy: null, cms: null, framework: null, languages: [] };
}

function emptyPhase(): CoveragePhase {
  return { status: "skipped", detail: "Phase was not reached." };
}

function emptyCoverage(): ScanCoverage {
  return {
    mainFetch: emptyPhase(),
    headers: emptyPhase(),
    tlsProtocolCipher: emptyPhase(),
    certificateEvidence: emptyPhase(),
    dns: emptyPhase(),
    cookies: emptyPhase(),
    paths: emptyPhase(),
    cors: emptyPhase(),
    secrets: emptyPhase(),
    wordpress: emptyPhase(),
    methods: emptyPhase(),
    takeover: emptyPhase(),
    criticalGaps: [],
  };
}

function emptyHeaderResult(): HeaderAuditResult {
  return {
    hsts: { present: false, raw: null, maxAge: null, includeSubDomains: false, preload: false },
    csp: { present: false, hasUnsafeInline: false, hasUnsafeEval: false, hasWildcard: false, hasDefaultSrc: false, raw: null },
    xContentTypeOptions: { present: false, value: null },
    xFrameOptions: { present: false, value: null },
    referrerPolicy: { present: false, value: null },
    permissionsPolicy: { present: false, value: null },
    xXssProtection: { present: false, value: null },
    serverRevealsVersion: false,
    poweredByRevealsTech: false,
  };
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ─── JS bundle extraction for secret scanning ─────────────────────────────

async function extractJsBundles(
  baseUrl: URL,
  html: string,
  context?: OutboundContext,
): Promise<Array<{ url: string; content: string }>> {
  const scriptUrls: string[] = [];
  const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = scriptRegex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], baseUrl).toString();
      if (resolved.startsWith("http://") || resolved.startsWith("https://")) {
        scriptUrls.push(resolved);
      }
    } catch {
      // Skip invalid URLs
    }
  }

  // Deduplicate and limit to 8 bundles so the default path set and method
  // probes remain below the declared request budget.
  const unique = [...new Set(scriptUrls)].slice(0, 8);

  const bundles: Array<{ url: string; content: string }> = [];
  await Promise.allSettled(
    unique.map(async (url) => {
      try {
        const response = await safeFetch(url, {
          baseUrl,
          // Cross-origin script execution is not followed by the scanner.
          // Same-host scripts remain eligible and every URL is still checked
          // by the shared public-target policy.
          allowCrossHost: false,
          followRedirects: false,
          context,
          phase: "secrets",
          timeoutMs: 8_000,
          headers: { Accept: "application/javascript,text/javascript,*/*;q=0.5", "User-Agent": USER_AGENT },
        });
        if (response.ok) {
          const content = await readBoundedBody(response, 512 * 1024, context, "secrets"); // 512KB max per bundle
          bundles.push({ url, content: content.text });
        }
      } catch {
        // Skip failed fetches
      }
    }),
  );

  return bundles;
}

// ─── Convert new module results to Findings ─────────────────────────────────

function secretFindingsAsFindings(secrets: SecretFinding[]): Finding[] {
  return secrets.map((s, i) => ({
    id: `secret-${s.type}-${i}`,
    severity: s.severity,
    category: "secret" as const,
    title: `Exposed ${s.type} in JavaScript`,
    detail: `A ${s.type.replace(/-/g, " ")} was found in ${s.source} at approximately line ${s.line}.`,
    evidence: s.snippet,
    recommendation: "Remove hardcoded secrets from client-side code. Use environment variables injected at build time or a server-side secrets manager.",
  }));
}

function wpFindingsAsFindings(wpFindings: WpFinding[]): Finding[] {
  return wpFindings.map((w) => ({
    id: `wordpress-${w.check}`,
    severity: w.severity,
    category: "wordpress" as const,
    title: w.title,
    detail: w.detail,
    evidence: w.evidence,
    recommendation: w.recommendation,
  }));
}

function statsMetadata(context: OutboundContext, phase: string): Pick<CoveragePhase, "attempts" | "succeeded" | "failed" | "skipped" | "bytes" | "truncated" | "errors"> {
  const stats = phaseStats(context, phase);
  return {
    attempts: stats.attempts,
    succeeded: stats.succeeded,
    failed: stats.failed,
    skipped: stats.skipped,
    bytes: stats.bytes,
    truncated: stats.truncated,
    ...(stats.errors.length ? { errors: [...stats.errors] } : {}),
  };
}

function phaseCoverage(
  context: OutboundContext,
  phase: string,
  detail: string,
  requested: boolean,
): CoveragePhase {
  const stats = phaseStats(context, phase);
  let status: CoveragePhase["status"] = "measured";
  if (stats.failed > 0 || stats.skipped > 0 || stats.truncated) {
    status = stats.succeeded > 0 ? "partial" : "failed";
  }
  return {
    status,
    detail: status === "partial" ? `${detail} Some work did not complete within the safe budget.` : detail,
    requested,
    ...statsMetadata(context, phase),
  };
}
