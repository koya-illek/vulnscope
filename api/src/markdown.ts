import type { Finding, ScanReport } from "./types";

const SEVERITY_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];

/**
 * Render a scan report as a human-readable Markdown document for tickets,
 * pull requests, and review docs. The JSON contract stays authoritative;
 * this view only reformats what is already stored, so nothing here can
 * invent or soften a finding.
 */
export function reportToMarkdown(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`# VulnScope report: ${report.hostname}`);
  lines.push("");
  lines.push(`- Grade: ${report.summary.grade}`);
  lines.push(`- Status: ${report.status}`);
  lines.push(`- Target: ${report.requestedUrl}`);
  lines.push(`- Report ID: \`${report.id}\``);
  lines.push(`- Created: ${report.createdAt}`);
  lines.push(`- Expires: ${report.expiresAt}`);
  lines.push(`- Duration: ${(report.totalDurationMs / 1000).toFixed(1)}s`);
  lines.push(
    `- Outbound work: ${report.outbound.requestsAttempted}/${report.outbound.maxSubrequests} requests` +
    `, ${report.outbound.bodyBytes} body bytes`,
  );
  lines.push(
    `- Findings: ${SEVERITY_ORDER
      .map((severity) => `${report.summary[severity]} ${severity}`)
      .join(", ")}`,
  );

  lines.push("");
  lines.push("## Coverage");
  lines.push("");
  lines.push("| Phase | Status | Detail |");
  lines.push("|---|---|---|");
  const coverage = report.coverage;
  for (const [phase, value] of Object.entries(coverage)) {
    // criticalGaps and any future non-phase metadata are handled separately.
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    const phaseRecord = value as { status: string; detail: string };
    lines.push(`| ${titleCase(phase)} | ${phaseRecord.status} | ${tableCell(String(phaseRecord.detail ?? ""))} |`);
  }
  if (report.coverage.criticalGaps.length > 0) {
    lines.push("");
    for (const gap of report.coverage.criticalGaps) lines.push(`- Coverage gap: ${gap}`);
  }

  lines.push("");
  lines.push("## Findings");
  if (report.findings.length === 0) {
    lines.push("");
    lines.push("No findings were generated.");
  }
  for (const severity of SEVERITY_ORDER) {
    const group = report.findings.filter((finding) => finding.severity === severity);
    if (group.length === 0) continue;
    for (const finding of group) {
      lines.push("");
      lines.push(`### ${titleCase(severity)}: ${finding.title}`);
      lines.push("");
      lines.push(finding.detail);
      lines.push("");
      lines.push("**Evidence**");
      lines.push("");
      lines.push(codeBlock(finding.evidence));
      lines.push("");
      lines.push(`**Fix:** ${finding.recommendation}`);
    }
  }

  lines.push("");
  lines.push("## Observation boundary");
  lines.push("");
  lines.push(report.observation.disclaimer);
  const vantage = [
    report.observation.colo ? `colo ${report.observation.colo}` : null,
    report.observation.country ? `country ${report.observation.country}` : null,
  ].filter(Boolean);
  lines.push(
    vantage.length > 0
      ? `Vantage: ${report.observation.vantage} (${vantage.join(", ")}).`
      : `Vantage: ${report.observation.vantage}.`,
  );
  lines.push("");
  return lines.join("\n");
}

function tableCell(value: string): string {
  return value.replace(/\r?\n/g, " ").replace(/\|/g, "\\|");
}

function codeBlock(value: string): string {
  // Evidence can legitimately contain triple backticks; keep the fence longer
  // than any backtick run inside the payload so the block never breaks.
  const longestRun = value.match(/`+/g)?.reduce((max, run) => Math.max(max, run.length), 0) ?? 0;
  const fence = "`".repeat(Math.max(3, longestRun + 1));
  return `${fence}\n${value}\n${fence}`;
}

function titleCase(value: string): string {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (char) => char.toUpperCase());
}
