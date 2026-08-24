import { describe, expect, it } from "vitest";

const streamReaderUrl = new URL("../../web/stream-reader.js", import.meta.url);

async function importStreamReader() {
  await import(streamReaderUrl.href);
  return globalThis.VulnScopeStream;
}

function bodyOf(chunks) {
  const encoder = new TextEncoder();
  const payloads = chunks.map((chunk) => encoder.encode(chunk));
  return new ReadableStream({
    start(controller) {
      for (const payload of payloads) controller.enqueue(payload);
      controller.close();
    },
  });
}

describe("VulnScope NDJSON stream reader", () => {
  it("dispatches one parsed event per line, including a final line without newline", async () => {
    const { consumeNdjson } = await importStreamReader();
    const events = [];
    const alive = await consumeNdjson(
      bodyOf(['{"type":"progress","stage":"dns"}\n', '{"type":"result","report":{"id":"1"}}']),
      (event) => events.push(event),
    );
    expect(alive).toBe(true);
    expect(events).toEqual([
      { type: "progress", stage: "dns" },
      { type: "result", report: { id: "1" } },
    ]);
  });

  it("reassembles one event split across chunk boundaries", async () => {
    const { consumeNdjson } = await importStreamReader();
    const events = [];
    await consumeNdjson(
      bodyOf(['{"type":"pro', 'gress","stage":"cors"}\n{"type":"res', 'ult","report":{}}\n']),
      (event) => events.push(event),
    );
    expect(events).toEqual([
      { type: "progress", stage: "cors" },
      { type: "result", report: {} },
    ]);
  });

  it("ignores blank lines between events", async () => {
    const { consumeNdjson } = await importStreamReader();
    const events = [];
    await consumeNdjson(bodyOf(['{"type":"ping"}\n\n\n{"type":"pong"}\n']), (event) => events.push(event));
    expect(events.map((event) => event.type)).toEqual(["ping", "pong"]);
  });

  it("throws on a malformed line instead of dropping part of the stream", async () => {
    const { consumeNdjson } = await importStreamReader();
    await expect(consumeNdjson(bodyOf(['{"type":"ok"}\nnot-json\n']), () => {})).rejects.toThrow(
      "The scan stream returned malformed data.",
    );
  });

  it("stops quietly and reports the stream as not alive once superseded", async () => {
    const { consumeNdjson } = await importStreamReader();
    const events = [];
    let cancelled = false;
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"type":"progress"}\n'));
      },
      cancel() {
        cancelled = true;
      },
    });
    const alive = await consumeNdjson(body, (event) => events.push(event), { isLive: () => false });
    expect(alive).toBe(false);
    expect(events).toEqual([]);
    expect(cancelled).toBe(true);
  });

  it("keeps reading while isLive stays true", async () => {
    const { consumeNdjson } = await importStreamReader();
    const events = [];
    const alive = await consumeNdjson(bodyOf(['{"n":1}\n{"n":2}\n{"n":3}\n']), (event) => events.push(event), {
      isLive: () => true,
    });
    expect(alive).toBe(true);
    expect(events.map((event) => event.n)).toEqual([1, 2, 3]);
  });
});
