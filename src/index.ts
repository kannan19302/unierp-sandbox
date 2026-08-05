import ivm from "isolated-vm";
import {
  type ResourceBudget,
  ResourceBudgetSchema,
  type Scope,
} from "@unerp/extension-api";

/**
 * Tier-3 extension sandbox — PLATFORM_ARCHITECTURE.md § 8.3, TRD ADR-009.
 *
 * Extension code runs inside a V8 isolate (`isolated-vm`), which is a genuine
 * boundary rather than the `node:vm` context this replaced. `node:vm` shares a
 * heap and a global object with the host, so the classic one-liner
 *
 *   this.constructor.constructor("return process")().mainModule.require("fs")
 *
 * walks straight out to the filesystem. In an isolate there is no `process` to
 * reach — the identifier does not exist — no `require`, no `fetch`, no timers
 * into host code, and a separate heap with a hard cap.
 *
 * The isolate gives isolation. This class adds the three things isolation alone
 * does not:
 *
 *   1. **Capability, not ambient authority.** The only host functions reachable
 *      from inside are the ones the installation's effective scopes grant, and
 *      each is checked again on the host side at call time. A missing scope is
 *      a thrown error inside the isolate, not a silent no-op, so extension
 *      authors find out at development time.
 *   2. **Metering and hard stops.** CPU is charged against a per-minute budget,
 *      queries and HTTP calls against per-invocation budgets, memory against
 *      the isolate cap. Exceeding any of them ends the invocation.
 *   3. **A kill switch.** `disable()` marks the extension dead and disposes the
 *      isolate; every subsequent call fails closed. § 8.3 requires this to be
 *      reachable from the Platform Admin Console.
 *
 * What this deliberately does NOT do: it never hands the isolate a Prisma
 * client, a connection string, a token, or the tenant id as something the
 * extension can influence. Data access goes through a host callback that
 * re-derives the tenant from the installation, so RLS applies to extension
 * queries exactly as it does to first-party ones.
 */

export interface HostCapabilities {
  /** Structured log sink. `console.*` is banned platform-wide (TRD § 3). */
  log: (level: "log" | "error", meta: LogMeta, args: unknown[]) => void;
  /** Tenant-scoped data read. The host re-derives the tenant; the isolate cannot set it. */
  dataRead?: (model: string, query: unknown) => Promise<unknown>;
  /** Tenant-scoped data write. Same re-derivation. */
  dataWrite?: (
    model: string,
    operation: string,
    payload: unknown,
  ) => Promise<unknown>;
  /** Outbound HTTP, already restricted to approved hosts by the caller. */
  httpFetch?: (url: string, init?: unknown) => Promise<unknown>;
  /** Enqueue a job on the platform scheduler under the extension's quota. */
  scheduleJob?: (
    name: string,
    runAt: string,
    payload: unknown,
  ) => Promise<void>;
}

export interface LogMeta {
  extensionId: string;
  tenantId: string;
}

export interface SandboxInstallation {
  extensionId: string;
  tenantId: string;
  /** Already intersected with the installer's permissions — see effectiveScopes(). */
  scopes: readonly Scope[];
  budget?: Partial<ResourceBudget>;
  /** Hosts approved at install time. A declared-but-unapproved host is denied. */
  approvedHosts?: readonly string[];
}

export interface InvocationUsage {
  cpuMs: number;
  queries: number;
  httpCalls: number;
}

export class SandboxScopeError extends Error {
  constructor(scope: Scope, extensionId: string) {
    super(
      `Extension "${extensionId}" called a capability requiring scope "${scope}", which its ` +
        `installation does not grant. Scopes are the intersection of the manifest's request and ` +
        `the installing admin's own permissions — an extension can never exceed its installer.`,
    );
    this.name = "SandboxScopeError";
  }
}

export class SandboxQuotaError extends Error {
  constructor(what: string, limit: number, extensionId: string) {
    super(
      `Extension "${extensionId}" exceeded its ${what} budget of ${limit}.`,
    );
    this.name = "SandboxQuotaError";
  }
}

export class SandboxDisabledError extends Error {
  constructor(extensionId: string) {
    super(
      `Extension "${extensionId}" is disabled by the platform kill switch.`,
    );
    this.name = "SandboxDisabledError";
  }
}

/** Bootstrap installed inside the isolate. Defines the frozen `unierp` global. */
const BOOTSTRAP = `
  (function (host) {
    "use strict";
    function callHost(name, args) {
      // applySyncPromise blocks this isolate — never the host event loop — until
      // the host settles. Extension code therefore sees a normal async API.
      return host.applySyncPromise(undefined, [name, JSON.stringify(args ?? [])]);
    }
    const api = {
      log: function (message, meta) { callHost("log", [String(message), meta ?? null]); },
      data: {
        read: function (model, query) { return JSON.parse(callHost("dataRead", [model, query])); },
        write: function (model, operation, payload) {
          return JSON.parse(callHost("dataWrite", [model, operation, payload]));
        },
      },
      http: {
        fetch: function (url, init) { return JSON.parse(callHost("httpFetch", [url, init ?? null])); },
      },
      jobs: {
        schedule: function (name, runAt, payload) { callHost("scheduleJob", [name, runAt, payload ?? null]); },
      },
    };
    Object.freeze(api.data); Object.freeze(api.http); Object.freeze(api.jobs);
    Object.freeze(api);
    Object.defineProperty(globalThis, "unierp", {
      value: api, writable: false, configurable: false, enumerable: true,
    });
  })
`;

export class SandboxRunner {
  private disabled = new Set<string>();
  private cpuWindow = new Map<string, { windowStart: number; cpuMs: number }>();

  /** Platform kill switch (§ 8.3). Subsequent invocations fail closed. */
  disable(extensionId: string): void {
    this.disabled.add(extensionId);
  }

  enable(extensionId: string): void {
    this.disabled.delete(extensionId);
  }

  isDisabled(extensionId: string): boolean {
    return this.disabled.has(extensionId);
  }

  /**
   * Run an extension's entry module and invoke one exported hook.
   *
   * Returns the hook's JSON-serialisable result plus the resources the
   * invocation actually consumed, so the caller can bill, alert, or trip a
   * circuit breaker on it.
   */
  async run(
    code: string,
    installation: SandboxInstallation,
    host: HostCapabilities,
    entry: { hook: string; args?: unknown[] } = { hook: "default" },
  ): Promise<{ result: unknown; usage: InvocationUsage }> {
    const { extensionId, tenantId } = installation;

    if (this.disabled.has(extensionId)) {
      throw new SandboxDisabledError(extensionId);
    }

    const budget = ResourceBudgetSchema.parse(installation.budget ?? {});
    const scopes = new Set<Scope>(installation.scopes);
    const approved = new Set(installation.approvedHosts ?? []);
    const usage: InvocationUsage = { cpuMs: 0, queries: 0, httpCalls: 0 };

    this.assertCpuWindow(extensionId, budget);

    const isolate = new ivm.Isolate({ memoryLimit: budget.memoryMb });
    const started = process.hrtime.bigint();

    try {
      const context = await isolate.createContext();

      const requireScope = (scope: Scope) => {
        if (!scopes.has(scope)) throw new SandboxScopeError(scope, extensionId);
      };

      // The single host bridge. Everything the isolate can do arrives here, and
      // every branch re-checks the scope on the host side — a capability handed
      // in is not a capability trusted.
      const bridge = new ivm.Reference(
        async (name: string, argsJson: string): Promise<string | undefined> => {
          const args = JSON.parse(argsJson) as unknown[];
          switch (name) {
            case "log": {
              requireScope("log:write");
              host.log("log", { extensionId, tenantId }, args);
              return undefined;
            }
            case "dataRead": {
              requireScope("data:read");
              this.charge(
                usage,
                "queries",
                budget.queriesPerInvocation,
                extensionId,
              );
              if (!host.dataRead)
                throw new Error(
                  "data:read is granted but no host reader is wired",
                );
              return JSON.stringify(
                (await host.dataRead(String(args[0]), args[1])) ?? null,
              );
            }
            case "dataWrite": {
              requireScope("data:write");
              this.charge(
                usage,
                "queries",
                budget.queriesPerInvocation,
                extensionId,
              );
              if (!host.dataWrite)
                throw new Error(
                  "data:write is granted but no host writer is wired",
                );
              return JSON.stringify(
                (await host.dataWrite(
                  String(args[0]),
                  String(args[1]),
                  args[2],
                )) ?? null,
              );
            }
            case "httpFetch": {
              requireScope("http:fetch");
              this.charge(
                usage,
                "httpCalls",
                budget.httpCallsPerInvocation,
                extensionId,
              );
              const url = String(args[0]);
              this.assertEgressAllowed(url, approved, extensionId);
              if (!host.httpFetch)
                throw new Error(
                  "http:fetch is granted but no host fetcher is wired",
                );
              return JSON.stringify(
                (await host.httpFetch(url, args[1])) ?? null,
              );
            }
            case "scheduleJob": {
              requireScope("jobs:schedule");
              if (!host.scheduleJob)
                throw new Error(
                  "jobs:schedule is granted but no host scheduler is wired",
                );
              await host.scheduleJob(String(args[0]), String(args[1]), args[2]);
              return undefined;
            }
            default:
              throw new Error(`Unknown host capability "${name}".`);
          }
        },
      );

      const bootstrap = await context.eval(BOOTSTRAP, {
        reference: true,
        timeout: budget.timeoutMs,
      });
      await bootstrap.apply(undefined, [bridge], { timeout: budget.timeoutMs });

      // Extension module: no `module`/`exports` shim is provided, because handing
      // the isolate a mutable host-shaped object is how ambient authority creeps
      // back in. The contract is that the entry module declares `hooks`; the
      // wrapper lifts it to a private global the invoker reads.
      const moduleScript = await isolate.compileScript(
        `globalThis.__unierp_hooks__ = (function(){ "use strict";\n${code}\n;` +
          ` return typeof hooks !== "undefined" ? hooks : null; })();`,
      );
      await moduleScript.run(context, { timeout: budget.timeoutMs });

      const invoke = await context.eval(
        `(function(hookName, argsJson){
           "use strict";
           const hooks = globalThis.__unierp_hooks__;
           if (!hooks || typeof hooks[hookName] !== "function") {
             throw new Error("Extension does not export hook: " + hookName);
           }
           const out = hooks[hookName].apply(undefined, JSON.parse(argsJson));
           return JSON.stringify(out === undefined ? null : out);
         })`,
        { reference: true, timeout: budget.timeoutMs },
      );

      const raw = await invoke.apply(
        undefined,
        [entry.hook, JSON.stringify(entry.args ?? [])],
        { timeout: budget.timeoutMs, result: { copy: true } },
      );

      usage.cpuMs = Number(process.hrtime.bigint() - started) / 1e6;
      this.chargeCpu(extensionId, usage.cpuMs, budget);

      return { result: raw == null ? null : JSON.parse(String(raw)), usage };
    } finally {
      // Always reclaim the heap, including on timeout or escape attempt.
      if (!isolate.isDisposed) isolate.dispose();
    }
  }

  private charge(
    usage: InvocationUsage,
    field: "queries" | "httpCalls",
    limit: number,
    extensionId: string,
  ): void {
    usage[field] += 1;
    if (usage[field] > limit) {
      throw new SandboxQuotaError(
        field === "queries"
          ? "per-invocation query"
          : "per-invocation HTTP call",
        limit,
        extensionId,
      );
    }
  }

  private assertCpuWindow(extensionId: string, budget: ResourceBudget): void {
    const now = Date.now();
    const w = this.cpuWindow.get(extensionId);
    if (!w || now - w.windowStart >= 60_000) {
      this.cpuWindow.set(extensionId, { windowStart: now, cpuMs: 0 });
      return;
    }
    if (w.cpuMs >= budget.cpuMsPerMinute) {
      throw new SandboxQuotaError(
        "CPU-per-minute",
        budget.cpuMsPerMinute,
        extensionId,
      );
    }
  }

  private chargeCpu(
    extensionId: string,
    cpuMs: number,
    budget: ResourceBudget,
  ): void {
    const w = this.cpuWindow.get(extensionId);
    if (!w) return;
    w.cpuMs += cpuMs;
    // Trip the breaker for the remainder of the window rather than at next entry,
    // so a single very expensive call cannot be repeated immediately.
    if (w.cpuMs >= budget.cpuMsPerMinute) {
      this.disable(extensionId);
    }
  }

  private assertEgressAllowed(
    url: string,
    approved: ReadonlySet<string>,
    extensionId: string,
  ): void {
    let host: string;
    try {
      host = new URL(url).hostname;
    } catch {
      throw new Error(`Extension "${extensionId}" requested a malformed URL.`);
    }
    if (!approved.has(host)) {
      throw new Error(
        `Extension "${extensionId}" attempted egress to "${host}", which is not an ` +
          `admin-approved host for this installation (§ 8.3: outbound HTTP only to ` +
          `manifest-declared, admin-approved hosts).`,
      );
    }
  }
}
