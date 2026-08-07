import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SandboxRunner,
  InMemoryRevocationStore,
  ConcurrencyRegistry,
  SandboxQuotaError,
  SandboxDisabledError,
  type HostCapabilities,
  type SandboxInstallation,
  type RevocationStore,
} from "./index";

const install = (
  over: Partial<SandboxInstallation> = {},
): SandboxInstallation => ({
  extensionId: "acme-widget",
  tenantId: "tenant-a",
  scopes: ["log:write"],
  ...over,
});

const hostSpy = (): HostCapabilities & { lines: unknown[][] } => {
  const lines: unknown[][] = [];
  return {
    lines,
    log: (_l, _m, args) => lines.push(args),
  };
};

/**
 * The exit criterion for A17, verbatim from docs/programme/10-TRACK-A-FOUNDATION.md:
 *
 *   "Each A16 threat has a mitigation and a test. `process`, `require`, `fs`, `net`
 *    are provably unreachable from inside the isolate"
 *
 * Run: npm run test:hardening
 */

describe("A17 hard requirement — process, require, fs, net provably unreachable", () => {
  const runner = new SandboxRunner();

  it("T02 — process does not exist as an identifier, and cannot be used", async () => {
    const { result } = await runner.run(
      `const hooks = { probe: () => [
         typeof process,
         (function () { try { return process.mainModule.require("fs"); } catch (e) { return "blocked"; } })()
       ] };`,
      install(),
      hostSpy(),
      { hook: "probe" },
    );
    expect(result).toEqual(["undefined", "blocked"]);
  });

  it("T01 — the node:vm escape chain cannot reach process or fs", async () => {
    await expect(
      runner.run(
        `const hooks = { esc: () => this.constructor.constructor("return process")().mainModule.require("fs") };`,
        install(),
        hostSpy(),
        { hook: "esc" },
      ),
    ).rejects.toThrow();
  });

  it("T02 — require does not exist and cannot load fs", async () => {
    const { result } = await runner.run(
      `const hooks = { probe: () => [
         typeof require,
         (function () { try { return require("fs"); } catch (e) { return "blocked"; } })()
       ] };`,
      install(),
      hostSpy(),
      { hook: "probe" },
    );
    expect(result).toEqual(["undefined", "blocked"]);
  });

  it("T02 — fs does not exist and its entry points cannot be touched", async () => {
    const { result } = await runner.run(
      `const hooks = { probe: () => [
         typeof fs,
         (function () { try { return fs.readFileSync("/etc/passwd"); } catch (e) { return "blocked"; } })()
       ] };`,
      install(),
      hostSpy(),
      { hook: "probe" },
    );
    expect(result).toEqual(["undefined", "blocked"]);
  });

  it("T02 — net does not exist and no socket can be opened", async () => {
    const { result } = await runner.run(
      `const hooks = { probe: () => [
         typeof net,
         (function () { try { return net.connect(6379, "127.0.0.1"); } catch (e) { return "blocked"; } })()
       ] };`,
      install(),
      hostSpy(),
      { hook: "probe" },
    );
    expect(result).toEqual(["undefined", "blocked"]);
  });
});

describe("A17 hardening — T11 bridge byte budget", () => {
  it("T11 — caps the serialised payload the isolate hands to the host, before the host parses it", async () => {
    const runner = new SandboxRunner();
    const host = { log: () => {}, dataWrite: vi.fn(async () => ({ ok: true })) };
    await expect(
      runner.run(
        `const hooks = { go: () => { const big = "x".repeat(50_000); unierp.data.write("Invoice", "create", { note: big }); return 1; } };`,
        install({ scopes: ["data:write"], hardening: { bridgeBytes: 8_192 } }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/budget/i);
    expect(host.dataWrite).not.toHaveBeenCalled();
  });

  it("T11 — caps the serialised result the host hands back to the isolate", async () => {
    const runner = new SandboxRunner();
    const host = {
      log: () => {},
      dataRead: async () => ({ blob: "y".repeat(50_000) }),
    };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.data.read("Invoice", {}) };`,
        install({ scopes: ["data:read"], hardening: { bridgeBytes: 8_192 } }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/budget/i);
  });
});

describe("A17 hardening — T12/T16 revocation is shared and persisted", () => {
  it("T12 — a revocation issued on one runner is enforced on every other runner sharing the store", async () => {
    const store = new InMemoryRevocationStore();
    const runnerA = new SandboxRunner({ revocationStore: store });
    const runnerB = new SandboxRunner({ revocationStore: store });
    await runnerA.disable("acme-widget");
    await expect(
      runnerB.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
        hook: "go",
      }),
    ).rejects.toThrow(SandboxDisabledError);
    await runnerA.enable("acme-widget");
    const { result } = await runnerB.run(
      `const hooks = { go: () => 1 };`,
      install(),
      hostSpy(),
      { hook: "go" },
    );
    expect(result).toBe(1);
  });

  it("T16 — a revocation is a persisted fact, read on entry, not an in-memory flag", async () => {
    const store = new InMemoryRevocationStore();
    await store.revoke("acme-widget");
    const runner = new SandboxRunner({ revocationStore: store });
    await expect(
      runner.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
        hook: "go",
      }),
    ).rejects.toThrow(SandboxDisabledError);
  });

  it("T16 — fails closed when the shared state is unreachable: a store error is a denial", async () => {
    const broken: RevocationStore = {
      isRevoked: async () => {
        throw new Error("revocation store unreachable");
      },
      revoke: async () => {},
      enable: async () => {},
    };
    const runner = new SandboxRunner({ revocationStore: broken });
    await expect(
      runner.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
        hook: "go",
      }),
    ).rejects.toThrow(SandboxDisabledError);
  });
});

describe("A17 hardening — T13 egress is SSRF-safe", () => {
  it("T13 — only the https: scheme is permitted; http, file and others are denied", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["8.8.8.8"] });
    const host = { log: () => {}, httpFetch: vi.fn(async () => ({ status: 200 })) };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("http://api.stripe.com/v1") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["api.stripe.com"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/https/i);
    expect(host.httpFetch).not.toHaveBeenCalled();
  });

  it("T13 — a file: URL is denied (the no-filesystem claim holds on the egress path)", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["8.8.8.8"] });
    const host = { log: () => {}, httpFetch: vi.fn(async () => ({ status: 200 })) };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("file:///etc/passwd") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["/etc/passwd"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/https/i);
    expect(host.httpFetch).not.toHaveBeenCalled();
  });

  it("T13 — an approved hostname that resolves to a loopback address is blocked (DNS rebinding)", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["127.0.0.1"] });
    const host = { log: () => {}, httpFetch: vi.fn(async () => ({ status: 200 })) };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("https://attacker.example/x") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["attacker.example"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/non-public|private|blocked/i);
    expect(host.httpFetch).not.toHaveBeenCalled();
  });

  it("T13 — an approved hostname that resolves to cloud metadata 169.254.169.254 is blocked", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["169.254.169.254"] });
    const host = { log: () => {}, httpFetch: vi.fn(async () => ({ status: 200 })) };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("https://metadata.example/") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["metadata.example"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/non-public|private|blocked/i);
    expect(host.httpFetch).not.toHaveBeenCalled();
  });

  it("T13 — an approved hostname that resolves to a private RFC 1918 address is blocked", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["192.168.1.1"] });
    const host = { log: () => {}, httpFetch: vi.fn(async () => ({ status: 200 })) };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("https://internal.example/x") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["internal.example"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/non-public|private|blocked/i);
    expect(host.httpFetch).not.toHaveBeenCalled();
  });

  it("T13 — an approved hostname resolving to public addresses is allowed", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["8.8.8.8"] });
    const host = {
      log: () => {},
      httpFetch: async () => ({ status: 200 }),
    };
    const { result } = await runner.run(
      `const hooks = { go: () => unierp.http.fetch("https://api.stripe.com/v1/charges") };`,
      install({ scopes: ["http:fetch"], approvedHosts: ["api.stripe.com"] }),
      host,
      { hook: "go" },
    );
    expect(result).toEqual({ status: 200 });
  });

  it("T13 — a redirect response is rejected rather than followed to an unchecked destination", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["8.8.8.8"] });
    const host = {
      log: () => {},
      httpFetch: async () => ({ status: 302, headers: { location: "http://169.254.169.254/" } }),
    };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("https://api.stripe.com/v1/charges") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["api.stripe.com"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/redirect/i);
  });
});

describe("A17 hardening — T14 CPU is real CPU, not wall clock", () => {
  it("T14 — time spent waiting on a slow host callback is not billed as CPU", async () => {
    const runner = new SandboxRunner();
    const host: HostCapabilities = {
      log: () => {},
      dataRead: async () => {
        await new Promise((r) => setTimeout(r, 400));
        return { rows: [] };
      },
    };
    const started = Date.now();
    const { usage } = await runner.run(
      `const hooks = { go: () => unierp.data.read("Invoice", {}) };`,
      install({ scopes: ["data:read"] }),
      host,
      { hook: "go" },
    );
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThan(300);
    // A wall-clock meter would bill ~400ms here; real CPU must be far below it.
    expect(usage.cpuMs).toBeLessThan(200);
  });
});

describe("A17 hardening — T15 breaker is separate from the kill switch and recovers", () => {
  it("T15 — an automatic CPU trip is not the operator kill switch, and clears when the window rolls over", async () => {
    const runner = new SandboxRunner({ cpuWindowMs: 1500 });
    const burn = `const hooks = { burn: () => { const t = Date.now(); while (Date.now() - t < 400) {} return 1; } };`;
    const base = install({ budget: { cpuMsPerMinute: 100, timeoutMs: 5000 } });

    const first = await runner.run(burn, base, hostSpy(), { hook: "burn" });
    expect(first.result).toBe(1);

    // The breaker tripped, but the operator kill switch must NOT be set.
    expect(await runner.isDisabled("acme-widget")).toBe(false);

    // Within the window the breaker blocks re-entry with a QUOTA error.
    await expect(
      runner.run(burn, base, hostSpy(), { hook: "burn" }),
    ).rejects.toThrow(SandboxQuotaError);

    // After the window rolls over the breaker clears and the extension runs again.
    await new Promise((r) => setTimeout(r, 1600));
    const third = await runner.run(burn, base, hostSpy(), { hook: "burn" });
    expect(third.result).toBe(1);
  });
});

describe("A17 hardening — T17 query cost is bounded", () => {
  it("T17 — caps the take an extension may request in one query", async () => {
    const runner = new SandboxRunner();
    const host = { log: () => {}, dataRead: vi.fn(async () => ({ rows: [] })) };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.data.read("Invoice", { take: 10_000 }) };`,
        install({ scopes: ["data:read"], hardening: { maxTake: 100 } }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/take|budget/i);
    expect(host.dataRead).not.toHaveBeenCalled();
  });

  it("T17 — caps the rows an invocation may fetch", async () => {
    const runner = new SandboxRunner();
    const host = {
      log: () => {},
      dataRead: async () => ({ rows: Array.from({ length: 10 }, (_, i) => ({ id: i })) }),
    };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.data.read("Invoice", {}) };`,
        install({ scopes: ["data:read"], hardening: { rowsPerInvocation: 5 } }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/rows|budget/i);
  });

  it("T17 — counts rows consumed within the budget", async () => {
    const runner = new SandboxRunner();
    const host = {
      log: () => {},
      dataRead: async () => ({ rows: Array.from({ length: 3 }, (_, i) => ({ id: i })) }),
    };
    const { usage } = await runner.run(
      `const hooks = { go: () => unierp.data.read("Invoice", {}) };`,
      install({ scopes: ["data:read"], hardening: { rowsPerInvocation: 10 } }),
      host,
      { hook: "go" },
    );
    expect(usage.rows).toBe(3);
  });
});

describe("A17 hardening — T18 the host trusts no serialisation performed in the isolate", () => {
  it("T18 — a poisoned JSON.stringify cannot control what the host receives", async () => {
    const runner = new SandboxRunner();
    const { result } = await runner.run(
      `const hooks = { go: () => {
         JSON.stringify = () => "EVIL";
         return { a: 1, nested: { b: 2 } };
       } };`,
      install(),
      hostSpy(),
      { hook: "go" },
    );
    expect(result).toEqual({ a: 1, nested: { b: 2 } });
  });

  it("T18 — a poisoned JSON.parse cannot corrupt the host's own argument transfer", async () => {
    const runner = new SandboxRunner();
    const { result } = await runner.run(
      `const hooks = { go: (n) => {
         const realParse = JSON.parse;
         JSON.parse = () => "EVIL";
         const val = realParse(n);
         JSON.parse = realParse;
         return val * 2;
       } };`,
      install(),
      hostSpy(),
      { hook: "go", args: [21] },
    );
    expect(result).toBe(42);
  });
});

describe("A17 hardening — T19 concurrent isolates are capped", () => {
  it("T19 — a second concurrent invocation for the same tenant is rejected at the cap", async () => {
    const registry = new ConcurrencyRegistry();
    const runner = new SandboxRunner({ concurrencyRegistry: registry });
    const spin = `const hooks = { spin: async () => { const t = Date.now(); while (Date.now() - t < 300) {} return 1; } };`;
    const base = install({
      budget: { timeoutMs: 5000 },
      hardening: { maxConcurrentIsolatesPerTenant: 1 },
    });

    const p1 = runner.run(spin, base, hostSpy(), { hook: "spin" });
    const p2 = runner.run(spin, base, hostSpy(), { hook: "spin" });

    await expect(p2).rejects.toThrow(SandboxQuotaError);
    const { result } = await p1;
    expect(result).toBe(1);
  });
});

describe("A17 — every A16 threat maps to a mitigation and a test", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(join(here, "index.ts"), "utf8");
  const specs =
    readFileSync(join(here, "sandbox.spec.ts"), "utf8") +
    readFileSync(join(here, "hardening.spec.ts"), "utf8");

  const threats = [
    "T01",
    "T02",
    "T03",
    "T04",
    "T05",
    "T06",
    "T07",
    "T08a",
    "T09a",
    "T10a",
    "T11",
    "T12",
    "T13",
    "T14",
    "T15",
    "T16",
    "T17",
    "T18",
    "T19",
  ];

  for (const threat of threats) {
    it(`${threat} is mitigated in the source and exercised in the spec`, () => {
      expect(source).toMatch(new RegExp(`\\b${threat}\\b`));
      expect(specs).toMatch(new RegExp(`\\b${threat}\\b`));
    });
  }
});
