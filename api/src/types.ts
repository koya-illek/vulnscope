// ─── DNS types (copied from RequestScope) ──────────────────────────────────

export interface DnsAnswer {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

export interface DnsQueryResult {
  resolver: string;
  name: string;
  type: string;
  status: number;
  authenticatedData: boolean;
  answers: DnsAnswer[];
  elapsedMs: number;
  error?: string;
  evidenceKind: "dns_observation";
}

// ─── SSL types (copied from RequestScope) ──────────────────────────────────

export interface SslDetail {
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  authorityKeyIdentifier: string | null;
  certificateEvidence: {
    source: "crt.sh";
    status: "observed" | "unavailable";
    limitation: string;
    observedAt: string | null;
  };
}

/**
 * `measured` is retained as the schema-v2 spelling of a successful phase for
 * compatibility with reports already stored in D1. New phase metadata also
 * supports partial work so a skipped request cannot be presented as a clean
 * observation.
 */
export type CoverageStatus = "measured" | "unavailable" | "skipped" | "failed" | "partial";

export interface CoveragePhase {
  status: CoverageStatus;
  detail: string;
  requested?: boolean;
  attempts?: number;
  succeeded?: number;
  failed?: number;
  skipped?: number;
  bytes?: number;
  truncated?: boolean;
  errors?: string[];
}

export interface ScanCoverage {
  mainFetch: CoveragePhase;
  headers: CoveragePhase;
  tlsProtocolCipher: CoveragePhase;
  certificateEvidence: CoveragePhase;
  dns: CoveragePhase;
  cookies: CoveragePhase;
  paths: CoveragePhase;
  cors: CoveragePhase;
  secrets: CoveragePhase;
  wordpress: CoveragePhase;
  methods: CoveragePhase;
  takeover: CoveragePhase;
  criticalGaps: string[];
}

export interface OutboundRequestSummary {
  maxSubrequests: number;
  maxConcurrent: number;
  maxDurationMs: number;
  requestsAttempted: number;
  requestsSucceeded: number;
  requestsFailed: number;
  requestsSkipped: number;
  activePeak: number;
  bodyBytes: number;
  truncatedBodies: number;
  redirects: Array<{
    from: string;
    to: string;
    status: number;
  }>;
}

// ─── Finding ───────────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category:
    | "exposed-path"
    | "missing-header"
    | "weak-tls"
    | "cors"
    | "cookie"
    | "takeover"
    | "fingerprint"
    | "information-disclosure"
    | "secret"
    | "wordpress"
    | "method";
  title: string;
  detail: string;
  evidence: string;
  recommendation: string;
}

// ─── Fingerprint ───────────────────────────────────────────────────────────

export interface CmsDetection {
  name: string;
  version: string | null;
}

export interface FrameworkDetection {
  name: string;
  version: string | null;
}

export interface FingerprintResult {
  server: string | null;
  poweredBy: string | null;
  cms: CmsDetection | null;
  framework: FrameworkDetection | null;
  languages: string[];
}

// ─── Header audit ──────────────────────────────────────────────────────────

export interface HeaderAuditResult {
  hsts: {
    present: boolean;
    raw: string | null;
    maxAge: number | null;
    includeSubDomains: boolean;
    preload: boolean;
  };
  csp: {
    present: boolean;
    hasUnsafeInline: boolean;
    hasUnsafeEval: boolean;
    hasWildcard: boolean;
    hasDefaultSrc: boolean;
    raw: string | null;
  };
  xContentTypeOptions: { present: boolean; value: string | null };
  xFrameOptions: { present: boolean; value: string | null };
  referrerPolicy: { present: boolean; value: string | null };
  permissionsPolicy: { present: boolean; value: string | null };
  xXssProtection: { present: boolean; value: string | null };
  serverRevealsVersion: boolean;
  poweredByRevealsTech: boolean;
}

// ─── Cookies ───────────────────────────────────────────────────────────────

export interface CookieAuditResult {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain: string | null;
  path: string | null;
  expires: string | null;
}

// ─── Exposed paths ─────────────────────────────────────────────────────────

export interface SensitivePathEntry {
  path: string;
  method: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  name: string;
  description: string;
  signatures: string[];
}

export interface ExposedPath {
  path: string;
  method: string;
  status: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  name: string;
  description: string;
  evidence: string;
  responseSize: number;
  truncated?: boolean;
}

// ─── CORS ──────────────────────────────────────────────────────────────────

export interface CorsResult {
  testedOrigin: string;
  acaoGet: string | null;
  acaoOptions: string | null;
  acacGet: string | null;
  acacOptions: string | null;
  reflectsOrigin: boolean;
  wildcardWithCredentials: boolean;
  vulnerable: boolean;
  evidence: string;
}

// ─── Subdomain takeover ────────────────────────────────────────────────────

export interface SubdomainTakeoverCheck {
  subdomain: string;
  cname: string | null;
  resolvable: boolean;
  httpStatus: number | null;
  vulnerable: boolean;
  evidence: string;
  confidence?: "high" | "low" | "none";
  resolverState?: "nxdomain" | "nodata-or-resolved" | "incomplete";
}

// ─── Scan report ───────────────────────────────────────────────────────────

export interface ScanReport {
  schemaVersion: 2;
  id: string;
  requestedUrl: string;
  hostname: string;
  status: "complete" | "partial" | "failed";
  createdAt: string;
  expiresAt: string;
  totalDurationMs: number;
  observation: {
    vantage: "cloudflare-edge";
    colo?: string;
    country?: string;
    disclaimer: string;
  };

  outbound: OutboundRequestSummary;

  coverage: ScanCoverage;

  dns: {
    queries: DnsQueryResult[];
    addresses: string[];
    dnssecAuthenticated: boolean;
  };
  ssl: SslDetail;

  fingerprint: FingerprintResult;

  headers: HeaderAuditResult;

  cookies: CookieAuditResult[];

  exposedPaths: ExposedPath[];

  cors: CorsResult;

  takeover?: SubdomainTakeoverCheck[];

  secrets?: SecretFinding[];

  wordpress?: WpFinding[];

  methods?: { methods: MethodResult[]; traceVulnerable: boolean };

  findings: Finding[];

  summary: {
    grade: "A" | "B" | "C" | "D" | "F" | "INCOMPLETE";
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

// ─── Secret detection ─────────────────────────────────────────────────────

export interface SecretFinding {
  type: string;       // "aws-access-key", "stripe-key", etc.
  // Heuristic shapes that also match ordinary minified JavaScript are capped
  // at medium so one false positive cannot fail an otherwise clean grade.
  severity: "critical" | "high" | "medium";
  // SHA-256 of the matched value. Reports never store prefix, suffix, or
  // connection-string userinfo — only this non-reversible fingerprint.
  hash: string;
  line: number;       // approximate line number
  source: string;     // query/fragment-free JS bundle URL
  confidence?: "high" | "medium" | "low";
}

// ─── WordPress ─────────────────────────────────────────────────────────────

export interface WpFinding {
  check: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  evidence: string;
  recommendation: string;
}

// ─── HTTP methods ──────────────────────────────────────────────────────────

export interface MethodResult {
  method: string;
  allowed: boolean;
  evidence: string;
  observation: "advertised" | "observed";
}

// ─── Env ───────────────────────────────────────────────────────────────────

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ALLOWED_ORIGINS: string;
  REPORT_RETENTION_DAYS: string;
  DAILY_SCAN_LIMIT: string;
  MCP_DAILY_LIMIT: string;
  REPORT_DAILY_LIMIT: string;
  RATE_LIMIT_HMAC_KEY: string;
  MAX_PATH_PROBES?: string;
  MAX_SCAN_SUBREQUESTS?: string;
  MAX_SCAN_CONCURRENCY?: string;
  MAX_SCAN_DURATION_MS?: string;
  ENVIRONMENT: string;
}
