(function (root) {
  "use strict";

  /**
   * Consume an NDJSON body and dispatch one parsed object per line.
   *
   * Handles events split across chunk boundaries, tolerates blank lines and
   * streams that end without a trailing newline, and stops quietly (returning
   * false after cancelling the body) once `isLive()` turns false — a run that
   * was abandoned through "New scan", Cancel, or history navigation must not
   * keep downloading or keep mutating the page.
   *
   * A malformed line throws so the caller can surface a stream-integrity
   * error instead of silently dropping part of the conversation.
   */
  async function consumeNdjson(body, handleEvent, { isLive = () => true } = {}) {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const dispatch = (line) => {
      if (!line.trim()) return;
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        throw new Error("The scan stream returned malformed data.");
      }
      handleEvent(event);
    };
    try {
      while (true) {
        if (!isLive()) {
          await reader.cancel().catch(() => {});
          return false;
        }
        const { done, value } = await reader.read();
        buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) dispatch(line);
        if (done) break;
      }
      // Flush the decoder and keep a final event that lacks its trailing
      // newline (a truncated stream must not silently drop the result).
      decoder.decode();
      if (buffer.trim()) dispatch(buffer);
      return true;
    } finally {
      reader.releaseLock();
    }
  }

  root.VulnScopeStream = { consumeNdjson };
})(typeof window === "undefined" ? globalThis : window);
