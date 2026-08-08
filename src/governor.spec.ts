import { describe, it, expect } from "vitest";
import { SandboxRunner, SandboxQuotaError, type HostCapabilities } from "./index";

/**
 * A19 — the governor-limits suite. docs/programme/10-TRACK-A-FOUNDATION.md, exit
 * criterion verbatim:
 *
 *   "A handler exceeding any budget is terminated, the tenant is not affected,
 *    the event is audited, and the platform's p95 is unchanged under a
 *    deliberate abuse load"
 *
 * Run: npm run test:governor
 *
 * Structure mirrors the escape suite: each test is written against the REAL
 * runner, with the tenant-level budget carried on the installation (fields that
 * the current source ignores are silently dropped by the extra-property pass,
 * so the assertions below fail today — the gap — and pass once the governor is
 * wired in). The deliberately abusing tenant is always `tenant-a`; the
 * unaffected tenant is always `tenant-b`, so a failure to scope enforcement per
 * tenant shows up as tenant-b being terminated too.
 */

const HOST: HostCapabilities = {
  log: () => undefined,
  dataRead: async () => ({ rows: [{ id: 1 }] }),
  dataWrite: async () => ({ id: "1" }),
  httpFetch: async (_url) => ({
    status: 200,
    headers: {},
    body: "x".repeat(4 * 1024),
  }),
};

const install = (
  over: Record<string, unknown> = {},
): Record<string, unknown> => ({
  extensionId: "acme-widget",
  tenantId: "tenant-a",
  scopes: ["log:write", "data:read", "http:fetch"],
  // Wall-clock timeout is deliberately modest: with no tenant governor, the
  // abuser dies here on an ivm timeout — NOT a SandboxQuotaError — so the gap
  // run fails fast instead of hanging for tens of seconds.
  budget: { timeoutMs: 1000 },
  ...over,
});

/**
 * A handler that burns real CPU by crossing the bridge in a tight loop. Each
 * host hop is where CPU accrues and where the per-tenant governor charges.
 * Unbounded (until its own wall-clock timeout) unless a governor stops it.
 */
const ABUSER = `
  const hooks = {
    spin: async () => {
      for (;;) { await unierp.log("tick", {}); }
    },
  };
`;

const WELL_BEHAVED = `
  const hooks = {
    run: async () => {
      await unierp.log("hi", {});
      return "ok";
    },
  };
`;

describe("A19 governor limits — per-tenant CPU window", () => {
  it("terminates an extension once its TENANT's aggregate CPU window is spent", async () => {
    const runner = new SandboxRunner();
    // Window is 200 ms of real CPU for the whole tenant, regardless of how
    // many extensions it runs. The per-extension budget is left generous so
    // only the tenant-level cap can trip.
    const a = install({
      tenantId: "tenant-a",
      tenantBudget: { windowMs: 60_000, cpuMsPerWindow: 200 },
      budget: { timeoutMs: 3000, cpuMsPerMinute: 60_000 },
    });

    // First extension burns part of the tenant window.
    await expect(
      runner.run(ABUSER, a as never, HOST, { hook: "spin" }),
    ).rejects.toThrow(SandboxQuotaError);
  });
});

describe("A19 governor limits — per-tenant egress byte window", () => {
  it("terminates an extension whose tenant has spent its egress-byte window", async () => {
    const runner = new SandboxRunner({
      resolver: async () => ["93.184.216.34"],
    } as never);
    const a = install({
      tenantId: "tenant-a",
      tenantBudget: { windowMs: 60_000, egressBytesPerWindow: 1024 },
      budget: { timeoutMs: 3000 },
      scopes: ["http:fetch"],
      approvedHosts: ["example.com"],
    });

    // Each response is 4 KiB; the tenant window is 1 KiB. The invocation must
    // be terminated at the window, not allowed to return.
    await expect(
      runner.run(
        `const hooks = { fetch: async () => { await unierp.http.fetch("https://example.com", {}); return "done"; } };`,
        a as never,
        HOST,
        { hook: "fetch" },
      ),
    ).rejects.toThrow(SandboxQuotaError);
  });
});

describe("A19 governor limits — tenant isolation", () => {
  it("leaves tenant-b untouched while tenant-a is deliberately abusing", async () => {
    const runner = new SandboxRunner();
    const abuser = install({
      tenantId: "tenant-a",
      tenantBudget: { windowMs: 60_000, cpuMsPerWindow: 100 },
      budget: { timeoutMs: 3000, cpuMsPerMinute: 60_000 },
    });
    const neighbour = install({
      tenantId: "tenant-b",
      tenantBudget: { windowMs: 60_000, cpuMsPerWindow: 100 },
      budget: { timeoutMs: 3000 },
    });

    await expect(
      runner.run(ABUSER, abuser as never, HOST, { hook: "spin" }),
    ).rejects.toThrow(SandboxQuotaError);

    // Tenant-b, on its own untouched window, must still run normally.
    const { result } = await runner.run(WELL_BEHAVED, neighbour as never, HOST, {
      hook: "run",
    });
    expect(result).toBe("ok");
  });
});

describe("A19 governor limits — the event is audited", () => {
  it("emits a governor event naming the budget, limits and tenant on termination", async () => {
    const events: Array<Record<string, unknown>> = [];
    const runner = new SandboxRunner({
      onGovernorEvent: (e) => events.push(e as Record<string, unknown>),
    } as never);
    const a = install({
      tenantId: "tenant-a",
      tenantBudget: { windowMs: 60_000, cpuMsPerWindow: 100 },
      budget: { timeoutMs: 3000, cpuMsPerMinute: 60_000 },
    });

    await expect(
      runner.run(ABUSER, a as never, HOST, { hook: "spin" }),
    ).rejects.toThrow(SandboxQuotaError);

    expect(events.length).toBeGreaterThan(0);
    const evt = events[events.length - 1];
    expect(evt.tenantId).toBe("tenant-a");
    expect(evt.extensionId).toBe("acme-widget");
    expect(evt.budget).toBe("cpuMsPerWindow");
    expect(evt.limit).toBe(100);
    expect(evt.used).toBeGreaterThanOrEqual(evt.limit as number);
  });
});

describe("A19 governor limits — p95 unchanged under a deliberate abuse load", () => {
  it("keeps the platform's p95 flat while one tenant deliberately abuses", async () => {
    const runner = new SandboxRunner();
    const neighbour = install({
      tenantId: "tenant-b",
      tenantBudget: { windowMs: 60_000, cpuMsPerWindow: 200 },
      budget: { timeoutMs: 3000 },
    });
    const abuser = install({
      tenantId: "tenant-a",
      tenantBudget: { windowMs: 60_000, cpuMsPerWindow: 100 },
      budget: { timeoutMs: 3000, cpuMsPerMinute: 60_000 },
    });

    const time = async (): Promise<number> => {
      const start = performance.now();
      await runner.run(WELL_BEHAVED, neighbour as never, HOST, { hook: "run" });
      return performance.now() - start;
    };

    // Baseline: p95 over 10 normal invocations with no abuser in flight.
    const baseline: number[] = [];
    for (let i = 0; i < 10; i += 1) baseline.push(await time());

    // Abuse load: one tenant is hammering the bridge. Its invocation is left
    // in flight (not awaited) while tenant-b's requests run.
    const abuserPromise = runner
      .run(ABUSER, abuser as never, HOST, { hook: "spin" })
      .catch(() => undefined);
    const underAbuse: number[] = [];
    for (let i = 0; i < 10; i += 1) underAbuse.push(await time());
    await abuserPromise;

    const p95 = (samples: number[]): number => {
      const sorted = [...samples].sort((x, y) => x - y);
      return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
    };
    const base = p95(baseline);
    const abuse = p95(underAbuse);

    // The tenant governor terminates the abuser within its 100 ms CPU window,
    // so tenant-b's p95 must stay within a bounded multiple of baseline. If the
    // governor did not exist, the abuser would spin to its 3 s wall-clock
    // timeout and every tenant-b request behind it would sit on the thread.
    expect(base).toBeLessThan(500);
    expect(abuse).toBeLessThan(base * 3 + 300);
  });
});
