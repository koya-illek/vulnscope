import { describe, expect, it } from "vitest";
import { calculateGrade, gradeBlockingCoverageGaps } from "../src/scorer";
import type { ScanCoverage } from "../src/types";

const phase = (status: ScanCoverage["mainFetch"]["status"], detail: string, requested = true) => ({ status, detail, requested });

function coverage(): ScanCoverage {
  return {
    mainFetch: phase("measured", "GET measured"),
    headers: phase("measured", "headers measured"),
    tlsProtocolCipher: phase("unavailable", "not exposed by Worker", false),
    certificateEvidence: phase("unavailable", "historical evidence unavailable", false),
    dns: phase("measured", "DNS measured"),
    cookies: phase("measured", "cookies measured"),
    paths: phase("partial", "budget stopped path probes"),
    cors: phase("measured", "CORS measured"),
    secrets: phase("measured", "secrets measured"),
    wordpress: phase("skipped", "not WordPress", false),
    methods: phase("measured", "methods measured"),
    takeover: phase("skipped", "optional", false),
    criticalGaps: [],
  };
}

describe("coverage-aware grading", () => {
  it("does not present a clean grade when a requested phase is partial", () => {
    const value = coverage();
    const gaps = gradeBlockingCoverageGaps(value);
    expect(gaps).toContain("paths: budget stopped path probes");
    expect(calculateGrade([], value)).toBe("INCOMPLETE");
  });
});
