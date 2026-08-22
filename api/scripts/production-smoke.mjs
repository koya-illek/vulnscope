const baseUrl = process.env.VULNSCOPE_BASE_URL || "https://scan.illek.ie";
const successfulTarget =
  process.env.VULNSCOPE_SMOKE_TARGET ||
  `https://example.com/?vulnscope-smoke=${Date.now()}`;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function post(path, target) {
  return fetch(new URL(path, baseUrl), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: target,
      probePaths: false,
      checkTakeover: false,
    }),
  });
}

const health = await fetch(new URL("/api/health", baseUrl));
assert(health.ok, `Health returned HTTP ${health.status}`);
const healthBody = await health.json();
assert(healthBody.ok === true, "Health payload was not healthy");

const selfScan = await post("/api/v2/scan", baseUrl);
const selfBody = await selfScan.json();
assert(selfScan.status === 403, `Self-scan returned HTTP ${selfScan.status}`);
assert(
  String(selfBody.error).includes("cannot scan its own hostname"),
  "Self-scan did not return the explicit Worker boundary",
);

const scan = await post("/api/v2/scan", successfulTarget);
assert(scan.status === 201, `Target scan returned HTTP ${scan.status}`);
const report = await scan.json();
assert(report.status === "complete", `Target scan status was ${report.status}`);
assert(
  report.coverage?.dns?.status === "measured" &&
    report.dns?.addresses?.length > 0,
  "Target scan did not confirm public DNS",
);
assert(
  report.coverage?.mainFetch?.status === "measured",
  `Main fetch was ${report.coverage?.mainFetch?.status || "missing"}`,
);
assert(
  report.summary?.grade !== "INCOMPLETE",
  "A fully measured target scan remained ungraded",
);

const stream = await post("/api/scans/stream", baseUrl);
assert(stream.ok, `Stream endpoint returned HTTP ${stream.status}`);
const events = (await stream.text())
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line));
assert(
  events.some(
    (event) =>
      event.type === "error" &&
      event.status === 403 &&
      String(event.error).includes("cannot scan its own hostname"),
  ),
  "Stream endpoint did not preserve the self-scan boundary",
);

console.log(
  `VulnScope production smoke passed at ${baseUrl}: DNS ${report.dns.addresses.length} addresses, main GET measured, grade ${report.summary.grade}, self-scan blocked explicitly.`,
);
