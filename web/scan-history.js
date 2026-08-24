(function (root) {
  "use strict";

  /**
   * Browser-local scan history. Reports live server-side behind opaque
   * bearer links and the threat model deliberately keeps any server-side
   * history out of scope, so this module records only what this browser has
   * seen — report ID, hostname, grade, status, timestamps — in localStorage.
   * Nothing here ever stores findings, evidence, cookies, or URLs.
   */
  const STORAGE_KEY = "vulnscope.history.v1";
  const MAX_ENTRIES = 24;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];

  function createHistory({ storage, now = () => new Date() } = {}) {
    const safeStorage = storage || null;

    function readEntries() {
      if (!safeStorage) return [];
      let raw = null;
      try {
        raw = safeStorage.getItem(STORAGE_KEY);
      } catch {
        return [];
      }
      if (!raw) return [];
      try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];
        return parsed.filter(isValidEntry);
      } catch {
        try { safeStorage.removeItem(STORAGE_KEY); } catch { /* storage unavailable */ }
        return [];
      }
    }

    function isValidEntry(entry) {
      return Boolean(
        entry && typeof entry === "object" &&
        typeof entry.id === "string" && entry.id &&
        typeof entry.hostname === "string" && entry.hostname &&
        typeof entry.createdAt === "string" &&
        typeof entry.expiresAt === "string"
      );
    }

    function writeEntries(entries) {
      if (!safeStorage) return;
      try {
        safeStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
      } catch {
        // Private browsing or a full quota must never break a scan flow.
      }
    }

    function purgeExpired(entries, currentTime) {
      return entries.filter((entry) => Date.parse(entry.expiresAt) > currentTime);
    }

    function record(report) {
      if (!report || typeof report !== "object") return null;
      if (typeof report.id !== "string" || !report.id) return null;
      if (typeof report.hostname !== "string" || !report.hostname) return null;
      if (typeof report.createdAt !== "string" || typeof report.expiresAt !== "string") return null;
      const currentTime = now().getTime();
      const grade = report.summary && typeof report.summary.grade === "string"
        ? report.summary.grade
        : null;
      const entry = {
        id: report.id,
        hostname: report.hostname,
        status: typeof report.status === "string" ? report.status : null,
        grade,
        critical: countOf(report, "critical"),
        high: countOf(report, "high"),
        medium: countOf(report, "medium"),
        low: countOf(report, "low"),
        info: countOf(report, "info"),
        createdAt: report.createdAt,
        expiresAt: report.expiresAt,
      };
      const rest = purgeExpired(readEntries(), currentTime).filter((existing) => existing.id !== entry.id);
      const entries = [entry, ...rest].slice(0, MAX_ENTRIES);
      writeEntries(entries);
      return entry;
    }

    function countOf(report, severity) {
      const value = report.summary ? report.summary[severity] : undefined;
      return typeof value === "number" && Number.isFinite(value) ? value : 0;
    }

    function entries() {
      return sortNewestFirst(purgeExpired(readEntries(), now().getTime()));
    }

    function sortNewestFirst(list) {
      return [...list].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    }

    function clear() {
      if (!safeStorage) return;
      try { safeStorage.removeItem(STORAGE_KEY); } catch { /* storage unavailable */ }
    }

    /**
     * The most recent earlier entry for the same hostname — the candidate
     * "previous scan" a viewer can diff the current report against.
     */
    function previousEntryFor(report) {
      if (!isValidEntry(report)) return null;
      const currentTime = report.createdAt;
      const candidates = purgeExpired(readEntries(), now().getTime())
        .filter((entry) =>
          entry.hostname === report.hostname &&
          entry.id !== report.id &&
          Date.parse(entry.createdAt) <= Date.parse(currentTime))
        .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
      return candidates[0] || null;
    }

    function get(id) {
      if (typeof id !== "string") return null;
      return entries().find((entry) => entry.id === id) || null;
    }

    return { record, entries, get, clear, previousEntryFor };
  }

  /**
   * Diff two full reports of the same host. Findings are matched by their
   * stable server-assigned IDs, so "added" and "resolved" mean actual finding
   * identity, not prose similarity.
   */
  function compareReports(previous, current) {
    if (!previous || !current || typeof previous !== "object" || typeof current !== "object") return null;
    if (previous.hostname !== current.hostname) return null;
    const previousIds = new Set((previous.findings || []).map((finding) => finding.id));
    const currentFindings = Array.isArray(current.findings) ? current.findings : [];
    const previousFindings = Array.isArray(previous.findings) ? previous.findings : [];
    const currentIds = new Set(currentFindings.map((finding) => finding.id));
    return {
      previousId: previous.id,
      currentId: current.id,
      hostname: current.hostname,
      grades: { from: gradeOf(previous), to: gradeOf(current) },
      statuses: { from: statusOf(previous), to: statusOf(current) },
      severityDeltas: SEVERITIES.map((severity) => ({
        severity,
        from: countSeverity(previousFindings, severity),
        to: countSeverity(currentFindings, severity),
      })),
      added: currentFindings.filter((finding) => !previousIds.has(finding.id)),
      resolved: previousFindings.filter((finding) => !currentIds.has(finding.id)),
    };
  }

  function gradeOf(report) {
    return report.summary && typeof report.summary.grade === "string" ? report.summary.grade : null;
  }

  function statusOf(report) {
    return typeof report.status === "string" ? report.status : null;
  }

  function countSeverity(findings, severity) {
    return findings.filter((finding) => finding && finding.severity === severity).length;
  }

  function formatRelative(isoTimestamp, currentTimeMs) {
    const timestamp = Date.parse(isoTimestamp);
    if (!Number.isFinite(timestamp)) return "";
    const elapsedSeconds = Math.max(0, Math.floor(((currentTimeMs || Date.now()) - timestamp) / 1000));
    if (elapsedSeconds < 60) return "just now";
    const minutes = Math.floor(elapsedSeconds / 60);
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} h ago`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days} d ago`;
    return new Date(timestamp).toLocaleDateString();
  }

  const rootTarget = typeof window === "undefined" ? globalThis : window;
  // Merely touching window.localStorage can throw (blocked cookies, some
  // privacy modes); the whole module must still load, so acquire it safely.
  function defaultStorage() {
    try {
      return typeof rootTarget.localStorage !== "undefined" ? rootTarget.localStorage : null;
    } catch {
      return null;
    }
  }
  rootTarget.VulnScopeHistory = {
    createHistory,
    compareReports,
    formatRelative,
    history: createHistory({ storage: defaultStorage() }),
  };
})(typeof window === "undefined" ? globalThis : window);
