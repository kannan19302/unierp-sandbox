import { describe, it, expect, vi } from "vitest";
import {
  SandboxRunner,
  SandboxScopeError,
  SandboxQuotaError,
  SandboxDisabledError,
  type HostCapabilities,
  type SandboxInstallation,
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

describe("SandboxRunner — isolation", () => {
  const runner = new SandboxRunner();

  it("runs a hook and returns its value", async () => {
    const { result } = await runner.run(
      `const hooks = { double: (n) => n * 2 };`,
      install(),
      hostSpy(),
      { hook: "double", args: [21] },
    );
    expect(result).toBe(42);
  });

  it("T01 — denies the node:vm escape that the previous implementation allowed", async () => {
    // This exact expression walks out of a node:vm context to the host process.
    // In an isolate `process` does not exist at all.
    await expect(
      runner.run(
        `const hooks = { esc: () => this.constructor.constructor("return process")().pid };`,
        install(),
        hostSpy(),
        { hook: "esc" },
      ),
    ).rejects.toThrow();
  });

  it("T02 — has no require, no fetch, no process and no host globals", async () => {
    const { result } = await runner.run(
      `const hooks = { probe: () => [
         typeof require, typeof process, typeof fetch, typeof globalThis.Buffer, typeof setTimeout
       ] };`,
      install(),
      hostSpy(),
      { hook: "probe" },
    );
    expect(result).toEqual([
      "undefined",
      "undefined",
      "undefined",
      "undefined",
      "undefined",
    ]);
  });

  it("T08a — enforces a wall-clock deadline on a runaway loop", async () => {
    await expect(
      runner.run(
        `const hooks = { spin: () => { while (true) {} } };`,
        install({ budget: { timeoutMs: 100 } }),
        hostSpy(),
        { hook: "spin" },
      ),
    ).rejects.toThrow(/timed out/i);
  });

  it("T04 — enforces the isolate memory cap", async () => {
    await expect(
      runner.run(
        `const hooks = { hog: () => { const a = []; while (true) a.push(new Array(1e6).fill(7)); } };`,
        install({ budget: { memoryMb: 8, timeoutMs: 5000 } }),
        hostSpy(),
        { hook: "hog" },
      ),
    ).rejects.toThrow();
  });

  it("T05 — freezes the unierp global so an extension cannot replace a capability", async () => {
    const { result } = await runner.run(
      `const hooks = { tamper: () => {
         try { globalThis.unierp = { log: () => "hijacked" }; } catch (e) { return "blocked"; }
         return typeof globalThis.unierp.data === "object" ? "blocked" : "replaced";
       } };`,
      install(),
      hostSpy(),
      { hook: "tamper" },
    );
    expect(result).toBe("blocked");
  });
});

describe("SandboxRunner — capabilities", () => {
  const runner = new SandboxRunner();

  it("grants a capability the installation holds", async () => {
    const host = hostSpy();
    await runner.run(
      `const hooks = { go: () => { unierp.log("hello"); return 1; } };`,
      install({ scopes: ["log:write"] }),
      host,
      { hook: "go" },
    );
    expect(host.lines[0]?.[0]).toBe("hello");
  });

  it("denies a capability the installation does not hold", async () => {
    const host = hostSpy();
    host.dataRead = vi.fn();
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.data.read("Invoice", {}) };`,
        install({ scopes: ["log:write"] }), // no data:read
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow(/scope "data:read"/);
    expect(host.dataRead).not.toHaveBeenCalled();
  });

  it("T03 — re-checks the scope on the host side, not only in the isolate", async () => {
    // Even if an extension reached the bridge directly, the host branch checks
    // the scope again — the capability object is not the authority.
    const host = hostSpy();
    host.dataWrite = vi.fn(async () => ({ ok: true }));
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.data.write("Invoice", "create", {}) };`,
        install({ scopes: ["data:read"] }), // read but not write
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow();
    expect(host.dataWrite).not.toHaveBeenCalled();
  });

  it("T09a — never lets the isolate choose its own tenant", async () => {
    const seen: string[] = [];
    const host: HostCapabilities = {
      log: (_l, meta) => seen.push(meta.tenantId),
    };
    await runner.run(
      `const hooks = { go: () => { unierp.log("x", { tenantId: "tenant-victim" }); return 1; } };`,
      install({ tenantId: "tenant-a", scopes: ["log:write"] }),
      host,
      { hook: "go" },
    );
    // The tenant on the host side comes from the installation, not the payload.
    expect(seen).toEqual(["tenant-a"]);
  });
});

describe("SandboxRunner — governance", () => {
  it("T06 — caps queries per invocation", async () => {
    const runner = new SandboxRunner();
    const host: HostCapabilities = {
      log: () => {},
      dataRead: async () => ({ rows: [] }),
    };
    await expect(
      runner.run(
        `const hooks = { go: () => { for (let i = 0; i < 10; i++) unierp.data.read("Invoice", {}); } };`,
        install({ scopes: ["data:read"], budget: { queriesPerInvocation: 3 } }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow();
  });

  it("T07 — denies egress to a host that was not approved at install time", async () => {
    const runner = new SandboxRunner();
    const host: HostCapabilities = {
      log: () => {},
      httpFetch: vi.fn(async () => ({ status: 200 })),
    };
    await expect(
      runner.run(
        `const hooks = { go: () => unierp.http.fetch("https://evil.example/steal") };`,
        install({ scopes: ["http:fetch"], approvedHosts: ["api.stripe.com"] }),
        host,
        { hook: "go" },
      ),
    ).rejects.toThrow();
    expect(host.httpFetch).not.toHaveBeenCalled();
  });

  it("T07 — allows egress to an approved host", async () => {
    const runner = new SandboxRunner({ resolver: async () => ["8.8.8.8"] });
    const host: HostCapabilities = {
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

  it("T10a — fails closed once the kill switch is thrown", async () => {
    const runner = new SandboxRunner();
    await runner.disable("acme-widget");
    await expect(
      runner.run(`const hooks = { go: () => 1 };`, install(), hostSpy(), {
        hook: "go",
      }),
    ).rejects.toThrow(SandboxDisabledError);
    await runner.enable("acme-widget");
    const { result } = await runner.run(
      `const hooks = { go: () => 1 };`,
      install(),
      hostSpy(),
      { hook: "go" },
    );
    expect(result).toBe(1);
  });

  it("reports the resources an invocation consumed", async () => {
    const runner = new SandboxRunner();
    const host: HostCapabilities = {
      log: () => {},
      dataRead: async () => ({}),
    };
    const { usage } = await runner.run(
      `const hooks = { go: () => { for (let i = 0; i < 1e6; i++) Math.sqrt(i); unierp.data.read("A", {}); unierp.data.read("B", {}); return 1; } };`,
      install({ scopes: ["data:read"] }),
      host,
      { hook: "go" },
    );
    expect(usage.queries).toBe(2);
    expect(usage.cpuMs).toBeGreaterThan(0);
  });
});

describe("error types", () => {
  it("names the scope and the extension on a scope denial", () => {
    const e = new SandboxScopeError("data:write", "acme-widget");
    expect(e.name).toBe("SandboxScopeError");
    expect(e.message).toContain("data:write");
    expect(e.message).toContain("acme-widget");
  });

  it("names the budget and the limit on a quota breach", () => {
    const e = new SandboxQuotaError("per-invocation query", 50, "acme-widget");
    expect(e.name).toBe("SandboxQuotaError");
    expect(e.message).toContain("50");
  });
});

describe("effective scopes", () => {
  it("intersects the manifest request with the installer's own permissions", async () => {
    const { effectiveScopes } = await import("@unerp/extension-api");
    expect(effectiveScopes(["data:read", "data:write"], ["data:read"])).toEqual(
      ["data:read"],
    );
    expect(effectiveScopes(["http:fetch"], ["data:read"])).toEqual([]);
  });
});
