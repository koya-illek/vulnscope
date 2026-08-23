import { describe, expect, it } from "vitest";
import "../../web/report-view.js";

const {
  headerAuditRows,
  corsAuditRows,
  gradePresentation,
  coverageRows,
  exposedPathsState,
  takeoverState,
  fingerprintRows,
  cookieRows,
} = globalThis.VulnScopeReport;

describe("VulnScope report presentation contract", () => {
  it("renders nested HSTS/CSP values and nested CORS observations faithfully", () => {
    const fixture = {
      headers: {
        hsts: {
          present: true,
          raw: "max-age=31536000; includeSubDomains; preload",
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true,
        },
        csp: {
          present: true,
          hasUnsafeInline: false,
          hasUnsafeEval: false,
          hasWildcard: false,
          hasDefaultSrc: true,
          raw: "default-src 'self'; object-src 'none'",
        },
        xFrameOptions: { present: true, value: "DENY" },
        xContentTypeOptions: { present: true, value: "nosniff" },
        referrerPolicy: { present: true, value: "strict-origin-when-cross-origin" },
        permissionsPolicy: { present: true, value: "camera=()" },
        xXssProtection: { present: true, value: "0" },
      },
      cors: {
        testedOrigin: "https://evil.example",
        acaoGet: "https://evil.example",
        acaoOptions: "null",
        acacGet: null,
        acacOptions: null,
        reflectsOrigin: true,
        wildcardWithCredentials: false,
        vulnerable: true,
        evidence: "ACAO (GET): https://evil.example",
      },
    };

    const headerRows = headerAuditRows(fixture.headers);
    expect(headerRows.find((row) => row.name === "Strict-Transport-Security")).toMatchObject({
      value: "max-age=31536000; includeSubDomains; preload",
      status: "Present",
    });
    expect(headerRows.find((row) => row.name === "Content-Security-Policy")).toMatchObject({
      value: "default-src 'self'; object-src 'none'",
      status: "Present",
    });
    expect(headerRows.find((row) => row.name === "X-XSS-Protection")).toMatchObject({
      value: "0",
      status: "Present",
    });
    expect(headerRows.some((row) => row.value === "[object Object]")).toBe(false);

    const corsRows = corsAuditRows(fixture.cors);
    expect(corsRows.find((row) => row.label === "Origin tested").value).toBe("https://evil.example");
    expect(corsRows.find((row) => row.label === "Access-Control-Allow-Origin (GET)").value).toBe("https://evil.example");
    expect(corsRows.find((row) => row.label === "Arbitrary-origin reflection")).toMatchObject({ value: "YES", statusClass: "warn" });
    expect(corsRows.find((row) => row.label === "Wildcard + credentials")).toMatchObject({ value: "No", statusClass: "good" });
    expect(corsRows.some((row) => row.label.includes("credentialed CORS theft"))).toBe(false);
  });

  it("labels the report as an HTTP-surface grade and keeps TLS/CT separate", () => {
    expect(gradePresentation({ grade: "A" })).toMatchObject({
      letter: "A",
      label: "HTTP surface grade",
    });
    expect(gradePresentation({ grade: "INCOMPLETE" })).toMatchObject({
      letter: "N/G",
      label: "HTTP surface ungraded",
    });
    expect(gradePresentation({ grade: "A" }).note).toContain("Origin TLS protocol/cipher");
    expect(gradePresentation({ grade: "A" }).note).toContain("certificate-transparency history");
  });

  it("discloses unavailable TLS and historical CT coverage without marking a grade-blocking gap", () => {
    const rows = coverageRows({
      mainFetch: { status: "measured", detail: "GET response received" },
      headers: { status: "measured", detail: "headers audited" },
      tlsProtocolCipher: { status: "unavailable", detail: "Origin TLS is not exposed by the Worker." },
      certificateEvidence: { status: "measured", detail: "crt.sh historical certificate-transparency evidence only" },
      criticalGaps: [],
    });

    expect(rows.find((row) => row.label === "Origin TLS protocol / cipher")).toMatchObject({
      status: "unavailable",
      detail: "Origin TLS is not exposed by the Worker.",
    });
    expect(rows.find((row) => row.label === "Certificate transparency evidence")).toMatchObject({
      status: "measured",
      detail: "crt.sh historical certificate-transparency evidence only",
    });
  });

  it("marks valid one-year HSTS as present when preload is omitted", () => {
    const rows = headerAuditRows({
      hsts: {
        present: true,
        raw: "max-age=31536000; includeSubDomains",
        maxAge: 31536000,
        includeSubDomains: true,
        preload: false,
      },
    });

    expect(rows.find((row) => row.name === "Strict-Transport-Security")).toMatchObject({
      value: "max-age=31536000; includeSubDomains",
      status: "Present",
      statusClass: "present",
    });
  });

  it("formats schema-v2 fingerprint objects and arrays without object coercion", () => {
    const rows = fingerprintRows({
      server: "nginx",
      poweredBy: "Express",
      cms: { name: "WordPress", version: "6.6.1" },
      framework: { name: "Next.js", version: "14.2.5" },
      languages: ["JavaScript", "PHP"],
    });

    expect(rows).toEqual([
      { label: "Server", value: "nginx" },
      { label: "Powered by", value: "Express" },
      { label: "CMS", value: "WordPress 6.6.1" },
      { label: "Framework", value: "Next.js 14.2.5" },
      { label: "Languages", value: "JavaScript, PHP" },
    ]);
    expect(rows.some((row) => row.value.includes("[object Object]"))).toBe(false);
  });

  it("renders wildcard credentials separately from arbitrary-origin reflection", () => {
    const rows = corsAuditRows({
      testedOrigin: "https://evil.example",
      acaoGet: "*",
      acaoOptions: null,
      acacGet: "true",
      acacOptions: null,
      reflectsOrigin: false,
      wildcardWithCredentials: true,
      vulnerable: true,
      evidence: "ACAO (GET): *; ACAC (GET): true",
    });

    expect(rows.find((row) => row.label === "Arbitrary-origin reflection")).toMatchObject({ value: "No", statusClass: "good" });
    expect(rows.find((row) => row.label === "Wildcard + credentials")).toMatchObject({ value: "YES", statusClass: "high" });
  });

  it("derives reflection and credential state from headers in legacy CORS fixtures", () => {
    const rows = corsAuditRows({
      testedOrigin: "https://evil.example",
      acaoGet: "https://evil.example",
      acaoOptions: null,
      acacGet: null,
      acacOptions: null,
      vulnerable: true,
    });

    expect(rows.find((row) => row.label === "Arbitrary-origin reflection")).toMatchObject({ value: "YES", statusClass: "warn" });
    expect(rows.find((row) => row.label === "Wildcard + credentials")).toMatchObject({ value: "No", statusClass: "good" });
    expect(rows.some((row) => row.value.includes("credentialed CORS theft"))).toBe(false);
  });

  it("distinguishes measured empty, skipped, and failed path coverage", () => {
    expect(exposedPathsState([], { paths: { status: "measured", detail: "0 exposures" } })).toEqual({
      status: "measured",
      message: "Path probing completed; no exposed paths were found.",
    });
    expect(exposedPathsState([], { paths: { status: "skipped", detail: "disabled" } })).toEqual({
      status: "skipped",
      message: "Path probing was not enabled for this scan.",
    });
    expect(exposedPathsState([], { paths: { status: "failed", detail: "timeout" } })).toEqual({
      status: "failed",
      message: "Path probing failed: timeout",
    });
  });

  it("shows measured-empty takeover work with a truthful completed message", () => {
    const state = takeoverState([], { takeover: { status: "measured", requested: true, detail: "Subdomain takeover checks completed for 0 subdomain(s)." } });
    expect(state).toMatchObject({ status: "measured", visible: true });
    expect(state.message).toContain("completed");
    expect(state.message).not.toContain("vulnerable CNAME patterns");
  });

  it("hides the takeover panel when the report never enabled the checks", () => {
    // A viewer's own checkbox must not make a skipped phase claim results.
    expect(takeoverState([], { takeover: { status: "skipped", requested: false, detail: "Subdomain takeover checks were not enabled for this scan." } })).toEqual({
      status: "skipped",
      visible: false,
      message: "Subdomain takeover checks were not enabled for this scan.",
    });
    expect(takeoverState([], {}).visible).toBe(false);
  });

  it("keeps attempted-but-incomplete takeover coverage visible with its reason", () => {
    const failed = takeoverState([], { takeover: { status: "failed", requested: true, detail: "Certificate Transparency lookup returned HTTP 502." } });
    expect(failed.visible).toBe(true);
    expect(failed.message).toContain("HTTP 502");
    const partial = takeoverState([], { takeover: { status: "partial", requested: true, detail: "budget" } });
    expect(partial.visible).toBe(true);
    expect(partial.message).toContain("budget");
    const unavailable = takeoverState([], { takeover: { status: "unavailable", detail: "no coverage recorded" } });
    expect(unavailable.visible).toBe(true);
    expect(unavailable.message).toContain("no coverage recorded");
  });

  it("keeps found takeover rows visible regardless of stored coverage metadata", () => {
    const rows = [{ subdomain: "stale.example.com", vulnerable: true, cname: "dead.example", evidence: "signature", confidence: "high" }];
    expect(takeoverState(rows, {})).toEqual({ status: "measured", visible: true, message: null });
  });

  it("formats cookie attributes from the schema without invented values or lengths", () => {
    const rows = cookieRows([{
      name: "session",
      secure: true,
      httpOnly: false,
      sameSite: "Lax",
      domain: ".example.com",
      path: "/",
      expires: "2026-08-13T00:00:00.000Z",
    }]);

    expect(rows).toEqual([{
      name: "session",
      attrs: [
        { text: "Secure", statusClass: "secure" },
        { text: "No HttpOnly", statusClass: "missing" },
        { text: "SameSite=Lax", statusClass: "sameSite" },
        { text: "Path=/", statusClass: "" },
      ],
      domain: ".example.com",
      expires: "2026-08-13T00:00:00.000Z",
    }]);
    expect(JSON.stringify(rows)).not.toContain("[object Object]");
    expect(JSON.stringify(rows)).not.toContain("value");
  });
});
