import type { Finding, MethodResult, ScanCoverage, ScanReport } from "./types";

export type ScanGrade = ScanReport["summary"]["grade"];

const REQUIRED_GRADE_PHASES = [
  "mainFetch",
  "headers",
] as const satisfies ReadonlyArray<keyof Pick<ScanCoverage, "mainFetch" | "headers">>;

const OPTIONAL_GRADE_PHASES = [
  "paths",
  "cors",
  "secrets",
  "wordpress",
  "methods",
  "takeover",
] as const satisfies ReadonlyArray<keyof Pick<ScanCoverage, "paths" | "cors" | "secrets" | "wordpress" | "methods" | "takeover">>;

function hasMeasuredGradeCoverage(coverage?: ScanCoverage): boolean {
  // Reports created before coverage metadata existed retain the legacy
  // findings-only grading behavior. Once coverage is supplied, every phase
  // that the HTTP-surface grade depends on must explicitly be measured.
  // criticalGaps is display metadata and is not a security gate.
  return !coverage || gradeBlockingCoverageGaps(coverage).length === 0;
}

export function gradeBlockingCoverageGaps(coverage: ScanCoverage): string[] {
  const requiredGaps = REQUIRED_GRADE_PHASES
    .filter((phase) => coverage[phase]?.status !== "measured")
    .map((phase) => `${phase}: ${coverage[phase]?.detail || "Coverage was not recorded."}`);
  const optionalGaps = OPTIONAL_GRADE_PHASES
    .filter((phase) => {
      const value = coverage[phase];
      if (!value) return false;
      // Older schema-v2 reports did not record whether an optional phase was
      // requested. Preserve their compatibility while making every newly
      // requested failure grade as incomplete.
      if (value.status === "measured") return false;
      return value.requested === true || value.status === "failed" || value.status === "partial";
    })
    .map((phase) => `${phase}: ${coverage[phase]?.detail || "Coverage was not recorded."}`);
  return [...requiredGaps, ...optionalGaps];
}

/**
 * Calculate the overall security grade from findings.
 *
 * - F: any critical finding
 * - D: any high finding
 * - C: more than 3 medium findings
 * - B: more than 3 low findings
 * - A: clean or info-only
 */
export function calculateGrade(findings: Finding[], coverage?: ScanCoverage): ScanGrade {
  if (findings.some((f) => f.severity === "critical")) return "F";
  if (findings.some((f) => f.severity === "high")) return "D";
  if (!hasMeasuredGradeCoverage(coverage)) return "INCOMPLETE";
  if (findings.filter((f) => f.severity === "medium").length > 3) return "C";
  if (findings.filter((f) => f.severity === "low").length > 3) return "B";
  return "A";
}

export function methodFindings(methods: { methods: MethodResult[]; traceVulnerable: boolean }): Finding[] {
  // Stored reports may contain an advertised result and a later observed
  // result for the same method. Collapse those records before scoring so a
  // stale duplicate TRACE entry cannot create duplicate or misleading XST
  // findings. An observed result is authoritative over an advertisement.
  const uniqueMethods = new Map<string, MethodResult>();
  for (const method of methods.methods) {
    const name = method.method.toUpperCase();
    const normalized = { ...method, method: name };
    const previous = uniqueMethods.get(name);
    if (!previous) {
      uniqueMethods.set(name, normalized);
    } else if (previous.observation === "advertised" && normalized.observation === "observed") {
      uniqueMethods.set(name, {
        ...normalized,
        evidence: `${previous.evidence}; ${normalized.evidence}`,
      });
    }
  }

  return [...uniqueMethods.values()].map((method) => {
    const name = method.method.toUpperCase();
    const advertised = method.observation === "advertised";
    const reflectedTrace = name === "TRACE" && method.observation === "observed" && methods.traceVulnerable;
    const severity = reflectedTrace ? "high" : advertised ? "info" : "low";
    const title = reflectedTrace
      ? "HTTP TRACE Reflects Request Data (XST Risk)"
      : advertised
        ? `HTTP ${name} Advertised by Allow Header`
        : `HTTP ${name} Method Observed`;
    const recommendation = reflectedTrace
      ? "Disable the TRACE method on the web server."
      : advertised
        ? `Review whether the advertised ${name} method is required; VulnScope did not send a ${name} request.`
        : name === "TRACE"
          ? "Restrict the TRACE method if it is not required; no reflected request data was observed."
          : `Restrict the ${name} method if it is not required by the application.`;
    return {
      id: `method-${name.toLowerCase()}`,
      severity,
      category: "method" as const,
      title,
      detail: method.evidence,
      evidence: method.evidence,
      recommendation,
    };
  });
}

/**
 * Build the summary object from the findings list.
 */
export function buildSummary(findings: Finding[], coverage?: ScanCoverage): ScanReport["summary"] {
  return {
    grade: calculateGrade(findings, coverage),
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
}

/**
 * Generate a TLS-related finding if the protocol is weak.
 */
export function tlsFindings(
  protocol: string | null,
  daysUntilExpiry: number | null,
  activeCertificateVerified = false,
): Finding[] {
  const findings: Finding[] = [];

  if (protocol) {
    const weakProtocols = ["tlsv1.0", "tlsv1.1", "ssl", "sslv2", "sslv3", "tlsv1"];
    const protocolLower = protocol.toLowerCase();
    if (weakProtocols.some((wp) => protocolLower === wp || protocolLower.startsWith(wp + " ") || protocolLower.includes(" " + wp))) {
      findings.push({
        id: "weak-tls-protocol",
        severity: "high",
        category: "weak-tls",
        title: "Weak TLS Protocol in Use",
        detail: `The server negotiated ${protocol}, which is deprecated and vulnerable to known attacks.`,
        evidence: `TLS protocol: ${protocol}`,
        recommendation: "Disable deprecated TLS versions (1.0 and 1.1) and require TLS 1.2 or higher.",
      });
    }
  }

  // Certificate Transparency dates are historical evidence, not proof of the
  // certificate currently negotiated by the target. Only an explicitly
  // verified active certificate may influence expiry grading.
  if (activeCertificateVerified && daysUntilExpiry !== null) {
    if (daysUntilExpiry < 0) {
      findings.push({
        id: "expired-ssl-certificate",
        severity: "critical",
        category: "weak-tls",
        title: "SSL Certificate Expired",
        detail: `The SSL certificate expired ${Math.abs(daysUntilExpiry)} days ago.`,
        evidence: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`,
        recommendation: "Renew the SSL certificate immediately.",
      });
    } else if (daysUntilExpiry <= 7) {
      findings.push({
        id: "ssl-certificate-expiring-soon",
        severity: "high",
        category: "weak-tls",
        title: "SSL Certificate Expiring Soon",
        detail: `The SSL certificate expires in ${daysUntilExpiry} days.`,
        evidence: `Certificate expires in ${daysUntilExpiry} days`,
        recommendation: "Renew the SSL certificate before it expires.",
      });
    } else if (daysUntilExpiry <= 30) {
      findings.push({
        id: "ssl-certificate-expiring",
        severity: "medium",
        category: "weak-tls",
        title: "SSL Certificate Expiring Within 30 Days",
        detail: `The SSL certificate expires in ${daysUntilExpiry} days.`,
        evidence: `Certificate expires in ${daysUntilExpiry} days`,
        recommendation: "Plan certificate renewal before expiry.",
      });
    }
  }

  return findings;
}

/**
 * Generate findings for exposed paths.
 */
export function exposedPathFindings(
  exposedPaths: ScanReport["exposedPaths"],
): Finding[] {
  return exposedPaths
    .filter((p) => p.severity === "critical" || p.severity === "high" || p.severity === "medium")
    .map((p) => ({
      id: `exposed-path-${p.path.replace(/[^a-z0-9]/gi, "-")}`,
      severity: p.severity,
      category: "exposed-path" as const,
      title: `Exposed: ${p.name}`,
      detail: p.description,
      evidence: `${p.method} ${p.path} → ${p.status} (${p.evidence})`,
      recommendation: `Restrict or remove access to ${p.path}.`,
    }));
}
