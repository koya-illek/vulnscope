import { describe, it, expect } from "vitest";
import { buildSummary, calculateGrade, exposedPathFindings, gradeBlockingCoverageGaps, methodFindings, tlsFindings } from "../src/scorer";
import type { ExposedPath, Finding, ScanCoverage } from "../src/types";

function makeFinding(severity: Finding["severity"], category: Finding["category"] = "missing-header"): Finding {
  return {
    id: `test-${severity}-${Math.random()}`,
    severity,
    category,
    title: `Test ${severity}`,
    detail: "Test detail",
    evidence: "Test evidence",
    recommendation: "Test recommendation",
  };
}

const completeCoverage: ScanCoverage = {
  mainFetch: { status: "measured", detail: "GET measured" },
  headers: { status: "measured", detail: "headers measured" },
  tlsProtocolCipher: { status: "measured", detail: "TLS measured" },
  certificateEvidence: { status: "measured", detail: "certificate measured" },
  dns: { status: "measured", detail: "DNS measured" },
  cookies: { status: "measured", detail: "cookies measured" },
  paths: { status: "measured", detail: "paths measured" },
  cors: { status: "measured", detail: "CORS measured" },
  secrets: { status: "measured", detail: "secrets measured" },
  wordpress: { status: "measured", detail: "WordPress measured" },
  methods: { status: "measured", detail: "methods measured" },
  takeover: { status: "skipped", detail: "optional" },
  criticalGaps: [],
};

const gradeableHttpSurfaceCoverage: ScanCoverage = {
  ...completeCoverage,
  tlsProtocolCipher: { status: "unavailable", detail: "Origin TLS protocol/cipher was not assessed." },
  certificateEvidence: { status: "unavailable", detail: "Certificate-transparency evidence was unavailable." },
};

describe("calculateGrade", () => {
  it("returns F for any critical finding", () => {
    const findings = [makeFinding("info"), makeFinding("critical")];
    expect(calculateGrade(findings)).toBe("F");
  });

  it("returns D for any high finding (no critical)", () => {
    const findings = [makeFinding("info"), makeFinding("high")];
    expect(calculateGrade(findings)).toBe("D");
  });

  it("returns C for more than 3 medium findings", () => {
    const findings = [
      makeFinding("medium"),
      makeFinding("medium"),
      makeFinding("medium"),
      makeFinding("medium"),
    ];
    expect(calculateGrade(findings)).toBe("C");
  });

  it("returns B for more than 3 low findings", () => {
    const findings = [
      makeFinding("low"),
      makeFinding("low"),
      makeFinding("low"),
      makeFinding("low"),
    ];
    expect(calculateGrade(findings)).toBe("B");
  });

  it("returns A for clean or info-only", () => {
    expect(calculateGrade([])).toBe("A");
    expect(calculateGrade([makeFinding("info")])).toBe("A");
    expect(calculateGrade([makeFinding("info"), makeFinding("info")])).toBe("A");
  });

  it("grades a measured main GET plus header audit even when TLS and CT are unavailable", () => {
    expect(calculateGrade([], gradeableHttpSurfaceCoverage)).toBe("A");
    expect(calculateGrade([makeFinding("info")], gradeableHttpSurfaceCoverage)).toBe("A");
  });

  it("surfaces a critical finding as F even when required coverage is missing", () => {
    const incomplete = { ...completeCoverage, mainFetch: { status: "failed" as const, detail: "GET timed out" } };
    expect(calculateGrade([makeFinding("critical")], incomplete)).toBe("F");
  });

  it("surfaces a high finding as D even when required coverage is missing", () => {
    const incomplete = { ...completeCoverage, headers: { status: "skipped" as const, detail: "header audit skipped" } };
    expect(calculateGrade([makeFinding("high")], incomplete)).toBe("D");
  });

  it("treats criticalGaps as display metadata when all required phases are measured", () => {
    const staleMetadata = { ...gradeableHttpSurfaceCoverage, criticalGaps: ["tlsProtocolCipher: not assessed"] };
    expect(calculateGrade([], staleMetadata)).toBe("A");
  });

  it("returns INCOMPLETE when the main fetch fails without a confirmed high or critical finding", () => {
    const failedFetch = { ...completeCoverage, mainFetch: { status: "failed" as const, detail: "GET timed out" }, criticalGaps: ["mainFetch"] };
    expect(calculateGrade([], failedFetch)).toBe("INCOMPLETE");
  });

  it("returns INCOMPLETE when the header audit is skipped without a confirmed high or critical finding", () => {
    const skippedHeaders = { ...gradeableHttpSurfaceCoverage, headers: { status: "skipped" as const, detail: "Header audit skipped." } };
    expect(calculateGrade([], skippedHeaders)).toBe("INCOMPLETE");
  });

  it("keeps deterministic A-F grading for the measured HTTP surface", () => {
    expect(calculateGrade([makeFinding("critical")], gradeableHttpSurfaceCoverage)).toBe("F");
    expect(calculateGrade([makeFinding("high")], gradeableHttpSurfaceCoverage)).toBe("D");
    expect(calculateGrade([], gradeableHttpSurfaceCoverage)).toBe("A");
  });

  it("returns A for 3 or fewer low findings", () => {
    const findings = [makeFinding("low"), makeFinding("low"), makeFinding("low")];
    expect(calculateGrade(findings)).toBe("A");
  });

  it("returns B for more than 3 low with no medium/high/critical", () => {
    const findings = [makeFinding("low"), makeFinding("low"), makeFinding("low"), makeFinding("low")];
    expect(calculateGrade(findings)).toBe("B");
  });

  it("returns A for 3 or fewer medium findings, including heuristic secrets", () => {
    const findings = [makeFinding("medium"), makeFinding("medium"), makeFinding("medium")];
    expect(calculateGrade(findings)).toBe("A");
  });

  it("does not let generic secret findings force grade D or F", () => {
    const genericSecrets: Finding[] = [
      {
        id: "secret-generic-api-key-0",
        severity: "medium",
        category: "secret",
        title: "Exposed generic-api-key in JavaScript",
        detail: "A generic api key was found.",
        evidence: "generic-api-key fingerprint abc at line 1 in https://example.com/app.js",
        recommendation: "Remove hardcoded secrets.",
      },
      {
        id: "secret-generic-secret-0",
        severity: "medium",
        category: "secret",
        title: "Exposed generic-secret in JavaScript",
        detail: "A generic secret was found.",
        evidence: "generic-secret fingerprint def at line 2 in https://example.com/app.js",
        recommendation: "Remove hardcoded secrets.",
      },
    ];
    expect(calculateGrade(genericSecrets)).toBe("A");
    expect(calculateGrade(genericSecrets)).not.toBe("D");
    expect(calculateGrade(genericSecrets)).not.toBe("F");
  });
});

describe("gradeBlockingCoverageGaps", () => {
  it("only treats main fetch and security headers as grade-blocking gaps", () => {
    const coverage = {
      ...gradeableHttpSurfaceCoverage,
      headers: { status: "skipped" as const, detail: "Header audit skipped." },
    };

    expect(gradeBlockingCoverageGaps(coverage)).toEqual([
      "headers: Header audit skipped.",
    ]);
  });
});

describe("buildSummary", () => {
  it("counts findings by severity correctly", () => {
    const findings: Finding[] = [
      makeFinding("critical"),
      makeFinding("high"),
      makeFinding("high"),
      makeFinding("medium"),
      makeFinding("medium"),
      makeFinding("medium"),
      makeFinding("medium"),
      makeFinding("low"),
      makeFinding("info"),
    ];
    const summary = buildSummary(findings);

    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(2);
    expect(summary.medium).toBe(4);
    expect(summary.low).toBe(1);
    expect(summary.info).toBe(1);
    expect(summary.grade).toBe("F"); // has critical
  });

  it("produces correct grade for clean report", () => {
    const summary = buildSummary([]);
    expect(summary.grade).toBe("A");
    expect(summary.critical).toBe(0);
    expect(summary.high).toBe(0);
    expect(summary.medium).toBe(0);
    expect(summary.low).toBe(0);
    expect(summary.info).toBe(0);
  });
});

describe("tlsFindings", () => {
  it("flags weak TLS protocol", () => {
    const findings = tlsFindings("TLSv1.0", 365);
    const weakTls = findings.find((f) => f.title.includes("Weak TLS"));
    expect(weakTls).toBeTruthy();
    expect(weakTls!.severity).toBe("high");
  });

  it("does not flag TLS 1.2 or 1.3", () => {
    const findings1 = tlsFindings("TLSv1.2", 365);
    const findings2 = tlsFindings("TLSv1.3", 365);
    const weakTls1 = findings1.find((f) => f.title.includes("Weak TLS"));
    const weakTls2 = findings2.find((f) => f.title.includes("Weak TLS"));
    expect(weakTls1).toBeFalsy();
    expect(weakTls2).toBeFalsy();
  });

  it("flags expired certificate as critical", () => {
    const findings = tlsFindings("TLSv1.3", -5, true);
    const expired = findings.find((f) => f.title.includes("Expired"));
    expect(expired).toBeTruthy();
    expect(expired!.severity).toBe("critical");
  });

  it("flags certificate expiring within 7 days as high", () => {
    const findings = tlsFindings("TLSv1.3", 3, true);
    const expiring = findings.find((f) => f.title.includes("Expiring Soon"));
    expect(expiring).toBeTruthy();
    expect(expiring!.severity).toBe("high");
  });

  it("flags certificate expiring within 30 days as medium", () => {
    const findings = tlsFindings("TLSv1.3", 20, true);
    const expiring = findings.find((f) => f.title.includes("Expiring Within"));
    expect(expiring).toBeTruthy();
    expect(expiring!.severity).toBe("medium");
  });

  it("does not flag certificate with >30 days validity", () => {
    const findings = tlsFindings("TLSv1.3", 90, true);
    const certFindings = findings.filter((f) => f.category === "weak-tls");
    expect(certFindings.length).toBe(0);
  });

  it("does not grade certificate-transparency expiry as an active certificate finding", () => {
    expect(tlsFindings(null, -5)).toEqual([]);
  });
});

describe("exposedPathFindings", () => {
  it("generates findings for critical and high exposed paths", () => {
    const paths: ExposedPath[] = [
      { path: "/.env", method: "GET", status: 200, severity: "critical", name: "Env", description: "Exposed", evidence: "match", responseSize: 100 },
      { path: "/admin", method: "GET", status: 200, severity: "high", name: "Admin", description: "Exposed", evidence: "match", responseSize: 200 },
    ];
    const findings = exposedPathFindings(paths);
    expect(findings.length).toBe(2);
    expect(findings[0].severity).toBe("critical");
    expect(findings[1].severity).toBe("high");
  });

  it("includes medium severity paths", () => {
    const paths: ExposedPath[] = [
      { path: "/.htaccess", method: "GET", status: 200, severity: "medium", name: "HTAccess", description: "Exposed", evidence: "match", responseSize: 50 },
    ];
    const findings = exposedPathFindings(paths);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("medium");
  });

  it("skips info and low paths", () => {
    const paths: ExposedPath[] = [
      { path: "/robots.txt", method: "GET", status: 200, severity: "info", name: "Robots", description: "Info", evidence: "match", responseSize: 50 },
      { path: "/.DS_Store", method: "GET", status: 200, severity: "low", name: "DS Store", description: "Low", evidence: "match", responseSize: 50 },
    ];
    const findings = exposedPathFindings(paths);
    expect(findings.length).toBe(0);
  });
});

describe("methodFindings", () => {
  it("only calls a reflected TRACE response an XST high finding", () => {
    const advertised = methodFindings({
      traceVulnerable: true,
      methods: [{ method: "TRACE", allowed: true, observation: "advertised", evidence: "OPTIONS Allow header advertises TRACE; no TRACE request was sent" }],
    });
    expect(advertised[0]).toMatchObject({ severity: "info", title: "HTTP TRACE Advertised by Allow Header" });
    expect(advertised[0].title).not.toContain("XST");

    const observed = methodFindings({
      traceVulnerable: false,
      methods: [{ method: "TRACE", allowed: true, observation: "observed", evidence: "TRACE returned 200; no reflected request data observed" }],
    });
    expect(observed[0]).toMatchObject({ severity: "low", title: "HTTP TRACE Method Observed" });
    expect(observed[0].title).not.toContain("XST");

    const reflected = methodFindings({
      traceVulnerable: true,
      methods: [{ method: "TRACE", allowed: true, observation: "observed", evidence: "TRACE returned 200 with reflected request data (XST vulnerability)" }],
    });
    expect(reflected[0]).toMatchObject({ severity: "high", title: "HTTP TRACE Reflects Request Data (XST Risk)" });
  });

  it("deduplicates stale advertised and observed method entries before scoring", () => {
    const findings = methodFindings({
      traceVulnerable: false,
      methods: [
        { method: "TRACE", allowed: true, observation: "advertised", evidence: "Allow advertises TRACE" },
        { method: "TRACE", allowed: true, observation: "observed", evidence: "TRACE returned 200; no reflected request data observed" },
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "low", title: "HTTP TRACE Method Observed" });
    expect(findings[0].title).not.toContain("XST");
    expect(findings[0].evidence).toContain("Allow advertises TRACE");
  });
});
