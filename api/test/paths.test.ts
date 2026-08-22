import { describe, it, expect } from "vitest";
import { SENSITIVE_PATHS, selectProbeEntries } from "../src/paths";

// We test the path database integrity here since probePaths requires network.

describe("SENSITIVE_PATHS database", () => {
  it("contains at least 30 entries", () => {
    expect(SENSITIVE_PATHS.length).toBeGreaterThanOrEqual(30);
  });

  it("each entry has required fields", () => {
    for (const entry of SENSITIVE_PATHS) {
      expect(entry.path).toBeTruthy();
      expect(entry.method).toBe("GET");
      expect(entry.severity).toMatch(/^(critical|high|medium|low|info)$/);
      expect(entry.name).toBeTruthy();
      expect(entry.description).toBeTruthy();
      expect(entry.signatures).toBeInstanceOf(Array);
      expect(entry.signatures.length).toBeGreaterThan(0);
    }
  });

  it("includes critical paths", () => {
    const paths = SENSITIVE_PATHS.map((e) => e.path);
    expect(paths).toContain("/.env");
    expect(paths).toContain("/.git/config");
    expect(paths).toContain("/.git/HEAD");
    expect(paths).toContain("/.svn/entries");
    expect(paths).toContain("/.aws/credentials");
    expect(paths).toContain("/.ssh/id_rsa");
    expect(paths).toContain("/backup.sql");
    expect(paths).toContain("/dump.sql");
    expect(paths).toContain("/wp-config.php");
  });

  it("includes high severity paths", () => {
    const paths = SENSITIVE_PATHS.map((e) => e.path);
    expect(paths).toContain("/admin");
    expect(paths).toContain("/wp-admin");
    expect(paths).toContain("/administrator");
    expect(paths).toContain("/phpmyadmin");
  });

  it("includes medium severity paths", () => {
    const paths = SENSITIVE_PATHS.map((e) => e.path);
    expect(paths).toContain("/.htaccess");
    expect(paths).toContain("/web.config");
    expect(paths).toContain("/server-status");
    expect(paths).toContain("/xmlrpc.php");
    expect(paths).toContain("/error_log");
  });

  it("includes low and info paths", () => {
    const paths = SENSITIVE_PATHS.map((e) => e.path);
    expect(paths).toContain("/.DS_Store");
    expect(paths).toContain("/composer.json");
    expect(paths).toContain("/package.json");
    expect(paths).toContain("/robots.txt");
    expect(paths).toContain("/.well-known/security.txt");
    expect(paths).toContain("/sitemap.xml");
    expect(paths).toContain("/login");
    expect(paths).toContain("/api");
  });

  it("includes WordPress config variants", () => {
    const paths = SENSITIVE_PATHS.map((e) => e.path);
    expect(paths).toContain("/wp-config.php.bak");
    expect(paths).toContain("/wp-config.php~");
    expect(paths).toContain("/wp-config.php.save");
  });
});

describe("selectProbeEntries sampling", () => {
  it("returns the full catalogue when the limit covers it", () => {
    const selected = selectProbeEntries(SENSITIVE_PATHS.length);
    expect(selected).toHaveLength(SENSITIVE_PATHS.length);
    expect(new Set(selected.map((e) => e.path)).size).toBe(SENSITIVE_PATHS.length);
  });

  it("caps at the limit without duplicates", () => {
    for (const limit of [0, 1, 5, 18, 40]) {
      const selected = selectProbeEntries(limit);
      expect(selected).toHaveLength(Math.min(limit, SENSITIVE_PATHS.length));
      expect(new Set(selected.map((e) => e.path)).size).toBe(selected.length);
    }
  });

  it("keeps every severity tier reachable at the default limit", () => {
    // With a plain severity sort, only critical entries fit inside the
    // deployed budget and every lower tier was unreachable.
    const selected = selectProbeEntries(18);
    const severities = new Set(selected.map((e) => e.severity));
    for (const severity of ["critical", "high", "medium", "low", "info"]) {
      expect(severities.has(severity as never)).toBe(true);
    }
  });

  it("keeps critical paths dominant in the sampled subset", () => {
    const counts = selectProbeEntries(18).reduce<Record<string, number>>((acc, entry) => {
      acc[entry.severity] = (acc[entry.severity] || 0) + 1;
      return acc;
    }, {});
    expect(counts.critical).toBeGreaterThanOrEqual(counts.high ?? 0);
    expect(counts.critical).toBeGreaterThanOrEqual(counts.medium ?? 0);
    expect(counts.critical).toBeGreaterThan(counts.low ?? 0);
    expect(counts.critical).toBeGreaterThan(counts.info ?? 0);
  });

  it("rotates the probed subset between scans", () => {
    const first = selectProbeEntries(18).map((e) => e.path).join("|");
    const second = selectProbeEntries(18).map((e) => e.path).join("|");
    expect(first).not.toBe(second);
  });
});
