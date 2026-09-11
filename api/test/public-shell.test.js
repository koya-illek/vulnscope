import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";

describe("public shell", () => {
  it("includes discovery metadata, structured data and accessible copy", async () => {
    const html = await readFile(new URL("../../web/index.html", import.meta.url), "utf8");
    const favicon = await readFile(new URL("../../web/favicon.svg", import.meta.url), "utf8");
    const headers = await readFile(new URL("../../web/_headers", import.meta.url), "utf8");

    expect(html).toMatch(/property="og:image"/);
    expect(html).toMatch(/<script type="application\/ld\+json">/);
    expect(html).toMatch(/rel="icon"/);
    expect(favicon).toMatch(/VulnScope/);
    expect(html).toMatch(/Optional scan scope/);
    expect(html).toMatch(/I confirm I own or have permission to scan this target/);
    expect(html).toMatch(/WordPress deep checks/);
    expect(html).toMatch(/Probe HTTP TRACE/);
    expect(html).toMatch(/Run authorised scan/);
    expect(html).toMatch(/id="scan-button"[^>]*disabled/);
    // The scan-progress live region covers the stage title only; the route
    // nodes are aria-hidden and the step list is a visual duplicate, so a
    // panel-wide live region would announce the duplication on every stage.
    expect(html).toMatch(/<section class="progress-panel hidden" id="progress-panel">/);
    expect(html).toMatch(/<h2 id="progress-title" aria-live="polite">/);
    expect(html).toMatch(/<progress class="progress-track" id="progress-track"[^>]*max="100" value="0"/);
    expect(html).not.toMatch(/\sstyle=/);
    expect(headers).toMatch(/style-src 'self';/);
    expect(headers).not.toContain("'unsafe-inline'");
    expect(headers).toContain("object-src 'none'");
    expect(headers).not.toContain("cloudflareinsights.com");
    expect(html).not.toMatch(/class="(?:eyebrow|section-kicker)"/);
    expect(html).not.toContain("—");
  });
});
