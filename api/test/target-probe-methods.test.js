import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// index.ts is intentionally excluded: its POST endpoints are VulnScope's own
// API, not requests sent to a scan target.
const TARGET_PROBE_MODULES = [
  "analyzer.ts",
  "cors.ts",
  "dns.ts",
  "methods.ts",
  "paths.ts",
  "ssl.ts",
  "wordpress.ts",
];
const ALLOWED_TARGET_METHODS = new Set(["GET", "OPTIONS", "TRACE"]);

function disallowedMethodLiterals(source) {
  return [...source.matchAll(/\bmethod\s*:\s*(["'])([A-Z]+)\1/gi)]
    .map((match) => match[2].toUpperCase())
    .filter((method) => !ALLOWED_TARGET_METHODS.has(method));
}

describe("target probe HTTP methods", () => {
  it("allows only GET, OPTIONS, and TRACE literals in outbound target-probe modules", async () => {
    const sources = await Promise.all(
      TARGET_PROBE_MODULES.map(async (moduleName) => ({
        moduleName,
        source: await readFile(new URL(`../src/${moduleName}`, import.meta.url), "utf8"),
      })),
    );
    const offenders = sources.flatMap(({ moduleName, source }) => {
      return disallowedMethodLiterals(source).map((method) => `${moduleName}: ${method}`);
    });

    expect(offenders).toEqual([]);
  });

  it("rejects HEAD and mutating method literals", () => {
    const forbiddenFixture = `
      fetch(url, { method: "HEAD" });
      fetch(url, { method: "POST" });
      fetch(url, { method: "PUT" });
      fetch(url, { method: "DELETE" });
      fetch(url, { method: "PATCH" });
    `;

    expect(disallowedMethodLiterals(forbiddenFixture)).toEqual([
      "HEAD",
      "POST",
      "PUT",
      "DELETE",
      "PATCH",
    ]);
  });
});
