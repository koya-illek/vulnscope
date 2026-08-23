(function (root) {
  "use strict";

  const headerDefinitions = [
    { name: "Strict-Transport-Security", key: "hsts" },
    { name: "Content-Security-Policy", key: "csp" },
    { name: "X-Frame-Options", key: "xFrameOptions" },
    { name: "X-Content-Type-Options", key: "xContentTypeOptions" },
    { name: "Referrer-Policy", key: "referrerPolicy" },
    { name: "Permissions-Policy", key: "permissionsPolicy" },
    { name: "X-XSS-Protection", key: "xXssProtection" },
  ];

  function headerAuditRows(headers) {
    return headerDefinitions.map((definition) => {
      const entry = headers?.[definition.key];
      const value = headerValue(definition.key, entry);
      const present = Boolean(entry && typeof entry === "object" ? entry.present : value);
      // Preload is an optional deployment choice. Match the backend: only a
      // present HSTS header with a sub-year max-age is weak.
      const weak = definition.key === "hsts"
        ? present && entry.maxAge !== null && entry.maxAge !== undefined && entry.maxAge < 31536000
        : false;
      return {
        name: definition.name,
        value: value || "Not set",
        status: !present ? "Missing" : weak ? "Weak" : "Present",
        statusClass: !present ? "missing" : weak ? "weak" : "present",
      };
    });
  }

  function headerValue(key, entry) {
    if (!entry) return null;
    if (typeof entry !== "object") return scalarValue(entry);
    if (key === "hsts") {
      if (entry.raw) return scalarValue(entry.raw);
      if (!entry.present) return null;
      const parts = [];
      if (entry.maxAge !== null && entry.maxAge !== undefined) parts.push(`max-age=${entry.maxAge}`);
      if (entry.includeSubDomains) parts.push("includeSubDomains");
      if (entry.preload) parts.push("preload");
      return parts.join("; ") || "Present (value unavailable)";
    }
    if (entry.raw) return scalarValue(entry.raw);
    return scalarValue(entry.value) || (entry.present ? "Present (value unavailable)" : null);
  }

  function scalarValue(value) {
    return value === null || value === undefined || (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean")
      ? null
      : String(value);
  }

  function corsAuditRows(cors) {
    const testedOrigin = typeof cors?.testedOrigin === "string" ? cors.testedOrigin : "";
    const acaoValues = [cors?.acaoGet, cors?.acaoOptions].filter((value) => typeof value === "string");
    const getAllowsCredentials = /^true$/i.test(String(cors?.acacGet || ""));
    const optionsAllowsCredentials = /^true$/i.test(String(cors?.acacOptions || ""));
    // Prefer the explicit schema-v2 booleans, but derive them from the
    // observed headers for older stored reports that only have header values.
    const reflectsOrigin = cors?.reflectsOrigin === true || Boolean(testedOrigin && acaoValues.includes(testedOrigin));
    const recordedHeaders = [cors?.acaoGet, cors?.acaoOptions, cors?.acacGet, cors?.acacOptions]
      .some((value) => typeof value === "string");
    const wildcardWithCredentialsFromHeaders =
      (cors?.acaoGet === "*" && getAllowsCredentials) ||
      (cors?.acaoOptions === "*" && optionsAllowsCredentials);
    const wildcardWithCredentials = recordedHeaders
      ? wildcardWithCredentialsFromHeaders
      : cors?.wildcardWithCredentials === true;
    // Display severity tracks the repriced findings: credentialed reflection
    // is high; bare reflection only exposes public data; wildcard plus ACAC
    // is refused by browsers for credentialed requests.
    const reflectedWithCredentials =
      (cors?.acaoGet === testedOrigin && getAllowsCredentials) ||
      (cors?.acaoOptions === testedOrigin && optionsAllowsCredentials);
    const reflectedSeverity = reflectedWithCredentials ? "high" : "warn";
    const rows = [
      ["Origin tested", cors?.testedOrigin || "Not recorded", ""],
      ["Access-Control-Allow-Origin (GET)", cors?.acaoGet || "Not set", cors?.acaoGet === "*" ? "warn" : ""],
      ["Access-Control-Allow-Origin (OPTIONS)", cors?.acaoOptions || "Not set", cors?.acaoOptions === "*" ? "warn" : ""],
      ["Access-Control-Allow-Credentials (GET)", cors?.acacGet || "Not set", ""],
      ["Access-Control-Allow-Credentials (OPTIONS)", cors?.acacOptions || "Not set", ""],
      ["Arbitrary-origin reflection", reflectsOrigin ? "YES" : "No", reflectsOrigin ? reflectedSeverity : "good"],
      ["Wildcard + credentials", wildcardWithCredentials ? "YES" : "No", wildcardWithCredentials ? "warn" : "good"],
    ];
    return rows.map(([label, value, statusClass]) => ({ label, value, statusClass }));
  }

  function exposedPathsState(paths, coverage) {
    const pathCoverage = coverage?.paths || coverage || {};
    const status = pathCoverage.status || (paths.length ? "measured" : "skipped");
    if (status === "measured" && paths.length === 0) {
      return { status, message: "Path probing completed; no exposed paths were found." };
    }
    if (status === "failed") {
      return { status, message: `Path probing failed: ${pathCoverage.detail || "The scanner could not complete this phase."}` };
    }
    if (status === "partial") {
      return { status, message: `Path probing was partial: ${pathCoverage.detail || "The safe request budget stopped this phase."}` };
    }
    if (status === "skipped") {
      return { status, message: "Path probing was not enabled for this scan." };
    }
    if (paths.length === 0) {
      return { status, message: `Path probing unavailable: ${pathCoverage.detail || "No coverage was recorded."}` };
    }
    return { status, message: null };
  }

  /**
   * Visibility and empty-state copy for the subdomain-takeover panel. The
   * report's own coverage record decides whether checks ran; a viewer's form
   * checkboxes must never make a skipped phase claim results.
   */
  function takeoverState(rows, coverage) {
    const takeoverCoverage = coverage?.takeover || {};
    const status = takeoverCoverage.status || (rows.length ? "measured" : "skipped");
    if (rows.length > 0) return { status, visible: true, message: null };
    if (status === "measured") {
      return { status, visible: true, message: "Subdomain takeover checks completed; no vulnerable indicators were found." };
    }
    if (status === "partial") {
      return { status, visible: true, message: `Subdomain takeover checks were partial: ${takeoverCoverage.detail || "The safe request budget stopped this phase."}` };
    }
    if (status === "failed") {
      return { status, visible: true, message: `Subdomain takeover checks failed: ${takeoverCoverage.detail || "The scanner could not complete this phase."}` };
    }
    if (status === "unavailable") {
      return { status, visible: true, message: `Subdomain takeover checks unavailable: ${takeoverCoverage.detail || "No coverage was recorded."}` };
    }
    return { status: "skipped", visible: false, message: "Subdomain takeover checks were not enabled for this scan." };
  }

  function gradePresentation(summary) {
    const normalized = scalarValue(summary?.grade);
    const grade = normalized ? normalized.toUpperCase() : "Unavailable";
    if (grade === "INCOMPLETE") {
      return {
        grade,
        // tone drives the badge class: an ungraded report must not wear the
        // accent styling of a real letter grade.
        tone: "incomplete",
        letter: "N/G",
        label: "HTTP surface ungraded",
        note: "This report is not graded until VulnScope measures the main GET and security header audit. Origin TLS protocol/cipher and certificate-transparency history remain separate coverage items.",
      };
    }
    return {
      grade,
      tone: /^[A-F]$/.test(grade) ? grade.toLowerCase() : "unavailable",
      letter: grade,
      label: "HTTP surface grade",
      note: "This grade reflects the measured main GET, security header audit, and observed unauthenticated web findings. Origin TLS protocol/cipher and certificate-transparency history are shown separately in coverage.",
    };
  }

  function coverageRows(coverage) {
    const definitions = [
      ["Main fetch", "mainFetch"],
      ["Security headers", "headers"],
      ["Origin TLS protocol / cipher", "tlsProtocolCipher"],
      ["Certificate transparency evidence", "certificateEvidence"],
      ["DNS", "dns"],
      ["Cookies", "cookies"],
      ["Sensitive paths", "paths"],
      ["CORS", "cors"],
      ["Secrets", "secrets"],
      ["WordPress", "wordpress"],
      ["HTTP methods", "methods"],
      ["Subdomain takeover", "takeover"],
    ];
    return definitions.map(([label, key]) => ({
      label,
      status: coverage?.[key]?.status || "unavailable",
      detail: coverage?.[key]?.detail || "Coverage was not recorded.",
    }));
  }

  function fingerprintRows(fingerprint) {
    const rows = [];
    if (typeof fingerprint?.server === "string" && fingerprint.server) {
      rows.push({ label: "Server", value: fingerprint.server });
    }
    if (typeof fingerprint?.poweredBy === "string" && fingerprint.poweredBy) {
      rows.push({ label: "Powered by", value: fingerprint.poweredBy });
    }

    const detections = [
      ["CMS", fingerprint?.cms],
      ["Framework", fingerprint?.framework],
    ];
    for (const [label, detection] of detections) {
      if (!detection || typeof detection !== "object" || typeof detection.name !== "string" || !detection.name) continue;
      const version = typeof detection.version === "string" && detection.version ? ` ${detection.version}` : "";
      rows.push({ label, value: `${detection.name}${version}` });
    }

    if (Array.isArray(fingerprint?.languages)) {
      const languages = fingerprint.languages.filter((language) => typeof language === "string" && language);
      if (languages.length) rows.push({ label: "Languages", value: languages.join(", ") });
    }
    return rows;
  }

  function cookieRows(cookies) {
    return (Array.isArray(cookies) ? cookies : []).map((cookie) => {
      const sameSite = scalarValue(cookie.sameSite);
      const attrs = [
        { text: cookie.secure ? "Secure" : "No Secure", statusClass: cookie.secure ? "secure" : "missing" },
        { text: cookie.httpOnly ? "HttpOnly" : "No HttpOnly", statusClass: cookie.httpOnly ? "httpOnly" : "missing" },
        sameSite
          ? { text: `SameSite=${sameSite}`, statusClass: "sameSite" }
          : { text: "No SameSite", statusClass: "missing" },
      ];
      const path = scalarValue(cookie.path);
      if (path) attrs.push({ text: `Path=${path}`, statusClass: "" });
      return {
        name: scalarValue(cookie.name) || "Unnamed cookie",
        attrs,
        domain: scalarValue(cookie.domain),
        expires: scalarValue(cookie.expires),
      };
    });
  }

  root.VulnScopeReport = {
    headerAuditRows,
    corsAuditRows,
    gradePresentation,
    coverageRows,
    exposedPathsState,
    takeoverState,
    fingerprintRows,
    cookieRows,
  };
})(typeof window === "undefined" ? globalThis : window);
