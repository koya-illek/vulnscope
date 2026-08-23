/**
 * One bounded reader for untrusted request bodies at the API boundaries.
 * REST scan input and MCP JSON-RPC messages share the same contract: a
 * declared Content-Length above the cap fails fast, a streamed body is
 * cancelled the moment it exceeds the cap, and the caller receives a typed
 * error instead of whatever the runtime would raise.
 */

export class RequestBodyError extends Error {
  readonly code: "missing" | "too-large";

  constructor(code: "missing" | "too-large") {
    super(code === "missing" ? "Request body is required." : "Request body is too large.");
    this.name = "RequestBodyError";
    this.code = code;
  }
}

export async function readBoundedRequestBody(request: Request, maxBytes: number): Promise<Uint8Array> {
  const declaredLength = Number.parseInt(request.headers.get("content-length") || "", 10);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new RequestBodyError("too-large");
  if (!request.body) throw new RequestBodyError("missing");

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new RequestBodyError("too-large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
