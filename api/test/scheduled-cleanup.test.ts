import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("scheduled cleanup", () => {
  it("purges expired reports and stale quota windows through the cron handler", async () => {
    const statements: { sql: string; binds: unknown[] }[] = [];
    const db = {
      prepare: (sql: string) => {
        // Record at prepare() time: the quota purge has no parameters and
        // never goes through bind().
        const entry = { sql, binds: [] as unknown[] };
        statements.push(entry);
        return {
          bind: (...binds: unknown[]) => {
            entry.binds = binds;
            return { sql };
          },
        };
      },
      batch: async (batch: { sql: string }[]) =>
        batch.map(() => ({ meta: { changes: 3 } })),
    };
    const waitUntil = vi.fn();
    const scheduledCtx = { waitUntil, passThroughOnException() {} } as unknown as ExecutionContext;
    const info = vi.spyOn(console, "info").mockImplementation(() => {});

    worker.scheduled({ scheduledTime: Date.now(), cron: "23 4 * * *" } as unknown as ScheduledController, { DB: db } as unknown as Env, scheduledCtx);

    // The cleanup runs inside waitUntil so the invocation returns promptly.
    expect(waitUntil).toHaveBeenCalledTimes(1);
    await (waitUntil.mock.calls[0][0] as Promise<void>);

    const deletes = statements.filter((statement) => statement.sql.includes("DELETE FROM"));
    expect(deletes).toHaveLength(2);
    expect(deletes[0].sql).toContain("DELETE FROM scans WHERE expires_at <= ?");
    // The cutoff is the wall clock at run time, parseable ISO.
    expect(deletes[0].binds).toHaveLength(1);
    expect(Number.isNaN(Date.parse(String(deletes[0].binds[0])))).toBe(false);
    expect(deletes[1].sql).toContain("DELETE FROM rate_limits");
    // The quota purge is parameterless; its window is computed in SQL.
    expect(deletes[1].binds).toHaveLength(0);
    // Observability line reports what the batch actually deleted.
    expect(info).toHaveBeenCalledWith(
      JSON.stringify({ event: "cleanup_expired", scansDeleted: 3, quotaRowsPurged: 3 }),
    );
  });
});
