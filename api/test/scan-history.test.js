import { describe, expect, it } from "vitest";

const scanHistoryUrl = new URL("../../web/scan-history.js", import.meta.url);

async function importScanHistory() {
  await import(scanHistoryUrl.href);
  return globalThis.VulnScopeHistory;
}

function memoryStorage() {
  const map = new Map();
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)); },
    removeItem: (key) => { map.delete(key); },
  };
}

const NOW = Date.parse("2026-08-24T12:00:00.000Z");
const clock = () => new Date(NOW);

function makeEntry(overrides = {}) {
  return {
    id: "abcd1234abcd1234",
    hostname: "shop.example",
    status: "complete",
    grade: "B",
    critical: 0,
    high: 1,
    medium: 2,
    low: 0,
    info: 3,
    createdAt: "2026-08-24T10:00:00.000Z",
    expiresAt: "2026-09-07T10:00:00.000Z",
    ...overrides,
  };
}

function makeReport(overrides = {}) {
  const summary = overrides.summary || { grade: "B", critical: 0, high: 1, medium: 2, low: 0, info: 3 };
  return {
    schemaVersion: 2,
    id: "abcd1234abcd1234",
    requestedUrl: "https://shop.example/",
    hostname: "shop.example",
    status: "complete",
    createdAt: "2026-08-24T10:00:00.000Z",
    expiresAt: "2026-09-07T10:00:00.000Z",
    summary,
    findings: [],
    ...overrides,
    summary,
  };
}

describe("VulnScope local scan history", () => {
  it("records a report as a minimal entry and lists it newest-first", async () => {
    const { createHistory } = await importScanHistory();
    const storage = memoryStorage();
    const history = createHistory({ storage, now: clock });
    history.record(makeReport());
    history.record(makeReport({
      id: "eeee5555eeee5555",
      hostname: "api.example",
      createdAt: "2026-08-24T11:00:00.000Z",
    }));
    const listed = history.entries();
    expect(listed.map((entry) => entry.id)).toEqual(["eeee5555eeee5555", "abcd1234abcd1234"]);
    expect(listed[1]).toMatchObject({ hostname: "shop.example", grade: "B", high: 1 });
    // Only the minimal projection is stored — never findings or URLs.
    expect(Object.keys(JSON.parse(storage.getItem("vulnscope.history.v1"))[0]).sort()).toEqual([
      "createdAt", "critical", "expiresAt", "grade", "high", "hostname", "id", "info", "low", "medium", "status",
    ]);
  });

  it("upserts by report ID instead of duplicating a re-read report", async () => {
    const { createHistory } = await importScanHistory();
    const history = createHistory({ storage: memoryStorage(), now: clock });
    history.record(makeReport({ summary: { grade: "C", critical: 0, high: 0, medium: 5, low: 0, info: 0 } }));
    history.record(makeReport({ summary: { grade: "A", critical: 0, high: 0, medium: 0, low: 0, info: 0 } }));
    expect(history.entries()).toHaveLength(1);
    expect(history.entries()[0].grade).toBe("A");
  });

  it("caps the list at 24 entries and drops expired ones on read and write", async () => {
    const { createHistory } = await importScanHistory();
    const history = createHistory({ storage: memoryStorage(), now: clock });
    for (let index = 0; index < 30; index += 1) {
      history.record(makeReport({
        id: String(index).padStart(16, "0"),
        createdAt: new Date(NOW - (index + 1) * 60_000).toISOString(),
      }));
    }
    expect(history.entries()).toHaveLength(24);
    history.record(makeReport({
      id: "ffffffffffffffff",
      createdAt: new Date(NOW - 30_000).toISOString(),
      expiresAt: new Date(NOW - 1000).toISOString(),
    }));
    expect(history.entries().some((entry) => entry.id === "ffffffffffffffff")).toBe(false);
  });

  it("resets gracefully when stored data is corrupted JSON", async () => {
    const { createHistory } = await importScanHistory();
    const storage = memoryStorage();
    storage.setItem("vulnscope.history.v1", "{not json");
    const history = createHistory({ storage, now: clock });
    expect(history.entries()).toEqual([]);
    expect(storage.getItem("vulnscope.history.v1")).toBeNull();
  });

  it("never throws when storage itself is unavailable", async () => {
    const { createHistory } = await importScanHistory();
    const throwing = {
      getItem: () => { throw new Error("denied"); },
      setItem: () => { throw new Error("denied"); },
      removeItem: () => { throw new Error("denied"); },
    };
    const history = createHistory({ storage: throwing, now: clock });
    expect(() => history.record(makeReport())).not.toThrow();
    expect(history.entries()).toEqual([]);
  });

  it("finds the latest earlier same-host entry for comparison", async () => {
    const { createHistory } = await importScanHistory();
    const history = createHistory({ storage: memoryStorage(), now: clock });
    history.record(makeEntry({ id: "1111111111111111", hostname: "shop.example", createdAt: "2026-08-20T10:00:00.000Z" }));
    history.record(makeEntry({ id: "2222222222222222", hostname: "other.example", createdAt: "2026-08-23T10:00:00.000Z" }));
    history.record(makeEntry({ id: "3333333333333333", hostname: "shop.example", createdAt: "2026-08-23T09:00:00.000Z" }));
    const previous = history.previousEntryFor(makeReport({ id: "4444444444444444", hostname: "shop.example" }));
    expect(previous.id).toBe("3333333333333333");
    // Nothing recorded predates the oldest shop.example scan.
    expect(history.previousEntryFor(makeReport({
      id: "5555555555555555",
      hostname: "shop.example",
      createdAt: "2026-08-19T10:00:00.000Z",
    }))).toBeNull();
  });

  it("clears all entries", async () => {
    const { createHistory } = await importScanHistory();
    const history = createHistory({ storage: memoryStorage(), now: clock });
    history.record(makeReport());
    history.clear();
    expect(history.entries()).toEqual([]);
  });
});

describe("VulnScope report comparison", () => {
  it("diffs grades, statuses, severity counts, and finding identity", async () => {
    const { compareReports } = await importScanHistory();
    const previous = makeReport({
      id: "1111111111111111",
      summary: { grade: "C", critical: 0, high: 2, medium: 1, low: 0, info: 0 },
      findings: [
        { id: "F1", severity: "high", title: "Missing HSTS", detail: "", evidence: "", recommendation: "" },
        { id: "F2", severity: "medium", title: "Old server banner", detail: "", evidence: "", recommendation: "" },
        { id: "F3", severity: "high", title: "Open CORS reflection", detail: "", evidence: "", recommendation: "" },
      ],
    });
    const current = makeReport({
      id: "2222222222222222",
      summary: { grade: "A", critical: 0, high: 0, medium: 1, low: 1, info: 0 },
      findings: [
        { id: "F2", severity: "medium", title: "Old server banner", detail: "", evidence: "", recommendation: "" },
        { id: "F9", severity: "low", title: "Cookie without SameSite", detail: "", evidence: "", recommendation: "" },
      ],
    });
    const comparison = compareReports(previous, current);
    expect(comparison.grades).toEqual({ from: "C", to: "A" });
    expect(comparison.severityDeltas).toEqual([
      { severity: "critical", from: 0, to: 0 },
      { severity: "high", from: 2, to: 0 },
      { severity: "medium", from: 1, to: 1 },
      { severity: "low", from: 0, to: 1 },
      { severity: "info", from: 0, to: 0 },
    ]);
    expect(comparison.added.map((finding) => finding.id)).toEqual(["F9"]);
    expect(comparison.resolved.map((finding) => finding.id)).toEqual(["F1", "F3"]);
  });

  it("refuses to compare different hosts", async () => {
    const { compareReports } = await importScanHistory();
    expect(compareReports(
      makeReport({ hostname: "a.example" }),
      makeReport({ hostname: "b.example" }),
    )).toBeNull();
  });

  it("formats relative timestamps in honest buckets", async () => {
    const { formatRelative } = await importScanHistory();
    expect(formatRelative("2026-08-24T11:59:40.000Z", NOW)).toBe("just now");
    expect(formatRelative("2026-08-24T11:40:00.000Z", NOW)).toBe("20 min ago");
    expect(formatRelative("2026-08-24T07:00:00.000Z", NOW)).toBe("5 h ago");
    expect(formatRelative("2026-08-21T12:00:00.000Z", NOW)).toBe("3 d ago");
    expect(formatRelative("not-a-date", NOW)).toBe("");
  });
});
