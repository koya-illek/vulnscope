import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";

describe("public shell", () => {
  it("includes discovery metadata, structured data and accessible copy", async () => {
    const html = await readFile(new URL("../../web/index.html", import.meta.url), "utf8");
    const favicon = await readFile(new URL("../../web/favicon.svg", import.meta.url), "utf8");

    expect(html).toMatch(/property="og:image"/);
    expect(html).toMatch(/<script type="application\/ld\+json">/);
    expect(html).toMatch(/rel="icon"/);
    expect(favicon).toMatch(/VulnScope/);
    expect(html).toMatch(/Optional scan scope/);
    expect(html).toMatch(/I confirm I own or have permission to scan this target/);
    expect(html).toMatch(/Run authorised scan/);
    expect(html).toMatch(/id="scan-button"[^>]*disabled/);
    expect(html).not.toMatch(/class="(?:eyebrow|section-kicker)"/);
    expect(html).not.toContain("—");
  });
});
