import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readdirSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, normalize, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Release-gate integration check for the promoted "#example" route. The unit
// test imports web/example-report.js directly, which validates the fixture but
// cannot see whether the HTML shell actually loads the module before app.js.
// This check drives a real headless browser over the DevTools protocol: it
// opens /#example, requires the sample report to render, and fails on any
// uncaught page exception or console error. It uses only Node built-ins, so
// the release gate keeps its dependency set unchanged.

const WEB_ROOT = normalize(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "web"));
const NAVIGATION_TIMEOUT_MS = 15_000;
const BROWSER_TIMEOUT_MS = 20_000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function findBrowserCandidates() {
  const candidates = [];
  const override = process.env.VULNSCOPE_BROWSER;
  if (override) candidates.push(override);

  for (const cache of [join(process.env.HOME || "", ".cache", "ms-playwright"), join(process.env.HOME || "", "Library", "Caches", "ms-playwright")]) {
    if (!existsSync(cache)) continue;
    const versions = readdirSync(cache)
      .filter((entry) => /^chromium-\d+$/.test(entry))
      .sort((a, b) => Number(b.slice("chromium-".length)) - Number(a.slice("chromium-".length)));
    for (const version of versions) {
      for (const layout of ["chrome-linux64/chrome", "chrome-linux/chrome", "chrome-mac/Chromium.app/Contents/MacOS/Chromium"]) {
        candidates.push(join(cache, version, layout));
      }
    }
    const shells = readdirSync(cache)
      .filter((entry) => /^chromium_headless_shell-\d+$/.test(entry))
      .sort((a, b) => Number(b.slice("chromium_headless_shell-".length)) - Number(a.slice("chromium_headless_shell-".length)));
    for (const shell of shells) {
      candidates.push(join(cache, shell, "chrome-headless-shell-linux64/chrome-headless-shell"));
    }
  }

  for (const name of ["google-chrome-stable", "google-chrome", "chromium-browser", "chromium", "chrome"]) {
    for (const dir of (process.env.PATH || "").split(":")) {
      if (dir) candidates.push(join(dir, name));
    }
  }
  return candidates.filter((candidate) => {
    try {
      return existsSync(candidate);
    } catch {
      return false;
    }
  });
}

function discoverBrowser() {
  for (const candidate of findBrowserCandidates()) {
    try {
      readdirSync(dirname(candidate));
      return candidate;
    } catch {
      // Candidate missing or unreadable; keep scanning.
    }
  }
  throw new Error(
    "No Chrome or Chromium executable found. Install Google Chrome, or point VULNSCOPE_BROWSER at an existing binary."
  );
}

function launchBrowser(binary, profileDir, useSandbox) {
  const args = [
    "--headless",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    `--user-data-dir=${profileDir}`,
    "--remote-debugging-port=0",
    "about:blank",
  ];
  if (!useSandbox) args.unshift("--no-sandbox");
  const child = spawn(binary, args, { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  const endpoint = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Browser did not expose a DevTools endpoint within ${BROWSER_TIMEOUT_MS}ms\n${stderr}`)), BROWSER_TIMEOUT_MS);
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      const match = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      reject(new Error(`Browser exited early with code ${code} signal ${signal}\n${stderr}`));
    });
  });
  return { child, endpoint, stderr: () => stderr };
}

async function startBrowser(binary, profileDir) {
  // Keep the renderer sandbox wherever the kernel allows it; Ubuntu 23.10+
  // disables unprivileged user namespaces by default, which kills Chromium at
  // startup ("No usable sandbox"), so fall back once for those hosts.
  let launched = launchBrowser(binary, profileDir, true);
  try {
    return { ...launched, endpoint: await launched.endpoint };
  } catch (error) {
    if (!/No usable sandbox/.test(launched.stderr())) throw error;
    launched.child.kill("SIGKILL");
    launched = launchBrowser(binary, profileDir, false);
    return { ...launched, endpoint: await launched.endpoint };
  }
}

async function findPageTarget(browserEndpoint) {
  const httpEndpoint = browserEndpoint.replace(/^ws:/, "http:").replace(/\/devtools\/browser\/.*$/, "/json/list");
  const targets = await (await fetch(httpEndpoint)).json();
  const page = targets.find((target) => target.type === "page");
  assert(page, "Browser opened without a page target");
  return page.webSocketDebuggerUrl;
}

function connectDevTools(socketUrl) {
  const socket = new WebSocket(socketUrl);
  const pending = new Map();
  const listeners = new Map();
  let nextId = 1;

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.id !== undefined) {
      const entry = pending.get(message.id);
      if (!entry) return;
      pending.delete(message.id);
      if (message.error) entry.reject(new Error(`${entry.method} failed: ${message.error.message}`));
      else entry.resolve(message.result ?? {});
      return;
    }
    listeners.get(message.method)?.forEach((handler) => handler(message.params));
  });

  const connected = new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve);
    socket.addEventListener("error", () => reject(new Error("Could not connect to the browser DevTools socket")));
  });

  return {
    connected,
    send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = nextId++;
        pending.set(id, { method, resolve, reject });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    on(method, handler) {
      const handlers = listeners.get(method) ?? new Set();
      handlers.add(handler);
      listeners.set(method, handlers);
      return () => handlers.delete(handler);
    },
    waitForEvent(method, predicate, timeoutMs, label) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          off();
          reject(new Error(`Timed out after ${timeoutMs}ms waiting for ${label}`));
        }, timeoutMs);
        const off = this.on(method, (params) => {
          if (!predicate(params)) return;
          clearTimeout(timer);
          off();
          resolve(params);
        });
      });
    },
    close() {
      socket.close();
    },
  };
}

async function startFileServer() {
  const types = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".yaml": "application/yaml",
    ".json": "application/json",
  };
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://127.0.0.1");
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.endsWith("/")) pathname += "index.html";
      const file = normalize(join(WEB_ROOT, pathname));
      if (!file.startsWith(WEB_ROOT + sep)) {
        response.statusCode = 404;
        response.end();
        return;
      }
      const body = await readFile(file);
      response.setHeader("Content-Type", types[extname(file)] ?? "application/octet-stream");
      response.end(body);
    } catch {
      response.statusCode = 404;
      response.end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    base: `http://127.0.0.1:${server.address().port}/`,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

function describeException(details) {
  const nested = details.exception?.description ? ` ${details.exception.description.split("\n")[0]}` : "";
  return `${details.text}${nested} at ${details.url ?? ""}:${details.lineNumber ?? "?"}`;
}

async function main() {
  const binary = discoverBrowser();
  const files = await startFileServer();
  const profileDir = await mkdtemp(join(tmpdir(), "vulnscope-example-check-"));
  let devtools = null;
  let child = null;
  try {
    const launched = await startBrowser(binary, profileDir);
    child = launched.child;
    devtools = connectDevTools(await findPageTarget(launched.endpoint));
    await devtools.connected;

    const problems = [];
    const uncaught = [];
    const consoleErrors = [];
    await devtools.send("Page.enable");
    await devtools.send("Runtime.enable");
    await devtools.send("Log.enable");
    await devtools.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    devtools.on("Runtime.exceptionThrown", (params) => uncaught.push(describeException(params.exceptionDetails)));
    devtools.on("Log.entryAdded", (params) => {
      if (params.entry.level === "error") consoleErrors.push(`${params.entry.text} (${params.entry.source}${params.entry.url ? ` ${params.entry.url}` : ""})`);
    });
    devtools.on("Runtime.consoleAPICalled", (params) => {
      if (params.type !== "error") return;
      consoleErrors.push(params.args.map((arg) => arg.value ?? arg.description ?? "").join(" "));
    });

    const loaded = devtools.waitForEvent("Page.loadEventFired", () => true, NAVIGATION_TIMEOUT_MS, "page load");
    const navigation = await devtools.send("Page.navigate", { url: `${files.base}#example` });
    assert(!navigation.errorText, `Navigation failed: ${navigation.errorText}`);
    await loaded;

    // Deferred scripts execute before the load event, so showExample() has
    // already run for the #example hash by the time we get here.
    const probe = await devtools.send("Runtime.evaluate", {
      returnByValue: true,
      expression: `(() => {
        const visible = (selector) => {
          const element = document.querySelector(selector);
          return Boolean(element && !element.classList.contains("hidden"));
        };
        const findings = document.querySelector("#findings-list");
        return {
          reportVisible: visible("#report"),
          exampleBadgeVisible: visible("#example-badge"),
          reportHost: document.querySelector("#report-host")?.textContent ?? null,
          findingCount: findings ? findings.childElementCount : -1,
          findingWidths: [...document.querySelectorAll(".finding-body")].map(node => node.getBoundingClientRect().width),
          title: document.title,
        };
      })()`,
    });
    if (probe.exceptionDetails) {
      problems.push(`Probe expression failed: ${describeException(probe.exceptionDetails)}`);
    }
    const state = probe.result.value;

    if (!state.reportVisible) problems.push("#report stayed hidden; the example report did not render.");
    if (!state.exampleBadgeVisible) problems.push("#example-badge stayed hidden; the SAMPLE DATA marker did not render.");
    if (state.reportHost !== "shop.example") problems.push(`#report-host was ${JSON.stringify(state.reportHost)}, expected "shop.example".`);
    if (!(state.findingCount > 0)) problems.push(`#findings-list rendered ${state.findingCount} sections, expected at least one.`);
    if (state.findingWidths.some(width => width < 200)) problems.push("Mobile finding text has less than 200px of readable width.");
    if (state.title !== "Example report: VulnScope") problems.push(`document.title was ${JSON.stringify(state.title)}, expected "Example report: VulnScope".`);
    for (const exception of uncaught) problems.push(`Uncaught page exception: ${exception}`);
    for (const error of consoleErrors) problems.push(`Console error: ${error}`);

    if (problems.length > 0) {
      console.error(`VulnScope #example browser check FAILED against ${files.base}`);
      for (const problem of problems) console.error(`  - ${problem}`);
      process.exitCode = 1;
      return;
    }
    console.log(`VulnScope #example browser integration passed at ${files.base} using ${binary}.`);
  } finally {
    devtools?.close();
    child?.kill("SIGTERM");
    await rm(profileDir, { recursive: true, force: true }).catch(() => {});
    await files.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
