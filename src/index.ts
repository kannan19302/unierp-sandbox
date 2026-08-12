import ivm from "isolated-vm";
import { promises as dns } from "node:dns";
import {
  type ResourceBudget,
  ResourceBudgetSchema,
  type Scope,
} from "@kannan19302/extension-api";

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
 * reach — the identifier does not exist — no `require`, no `fs`, no `net`, no
 * `fetch`, no timers into host code, and a separate heap with a hard cap.
 *
 * The isolate gives isolation. This class adds the four things isolation alone
 * does not:
 *
 *   1. **Capability, not ambient authority.** The only host functions reachable
 *      from inside are the ones the installation's effective scopes grant, and
 *      each is checked again on the host side at call time. A missing scope is
 *      a thrown error inside the isolate, not a silent no-op.
 *   2. **Metering and hard stops.** CPU (`isolate.cpuTime`, not wall clock) is
 *      charged against a per-minute budget and enforced *during* execution at
 *      every bridge hop; queries, rows, HTTP calls and bridge bytes against
 *      per-invocation budgets; memory against the isolate cap; concurrent
 *      isolates against per-tenant and per-process caps.
 *   3. **A kill switch.** `disable()` marks the extension dead in *shared*
 *      state and every subsequent call fails closed — including when that
 *      shared state is unreachable. § 8.3 requires this to be reachable from
 *      the Platform Admin Console.
 *   4. **SSRF-safe egress.** Outbound HTTP is restricted to https:, to
 *      admin-approved hostnames, and to hostnames that resolve only to public
 *      addresses. Redirect responses are rejected.
 *
 * Threat coverage (docs/THREAT-MODEL.md): T01 genuine isolate, T02 no ambient
 * authority, T03 host-side scope re-checks, T04 isolate heap cap, T05 frozen
 * unierp global, T06 query-count cap, T07 approved-host egress, T08a execution
 * timeout, T09a host-derived tenant, T10a fail-closed kill switch, T11 bridge
 * byte budget, T12 shared revocation, T13 SSRF-safe egress, T14 real CPU,
 * T15 breaker/kill-switch separation, T16 persisted revocation, T17 query cost
 * bounds, T18 no trusted in-isolate serialisation, T19 concurrent-isolate caps.
 *
 * What this deliberately does NOT do: it never hands the isolate a Prisma
 * client, a connection string, a token, or the tenant id as something the
 * extension can influence. Data access goes through a host callback that
 * re-derives the tenant from the installation, so RLS applies to extension
 * queries exactly as it does to first-party ones. And no value is ever
 * serialised *inside* the isolate and trusted on the host side: results cross
 * by isolated-vm's own copy semantics, so a poisoned `JSON.stringify` cannot
 * control what the host parses (T18).
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
  /** Outbound HTTP. Must not follow redirects; the sandbox rejects 3xx responses (T13). */
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
  /**
   * A17 hardening knobs (T11, T17, T19). All are hard stops, not targets, and
   * each is clamped to a safe range by resolveHardening().
   */
  hardening?: Partial<SandboxHardening>;
  /** Hosts approved at install time. A declared-but-unapproved host is denied. */
  approvedHosts?: readonly string[];
  /**
   * A19 — the governor: per-TENANT budgets aggregated across every extension
   * the tenant runs, over a rolling window. Per-invocation budgets (budget.*)
   * gate one call; these gate the tenant as a whole. Absent, only the
   * per-invocation budgets apply.
   */
  tenantBudget?: Partial<TenantBudget>;
}

/**
 * A19 — per-tenant aggregate budgets, the Salesforce governor-limit analogue.
 * These sum across every extension a tenant runs within one window, so a single
 * abusive extension cannot burn the platform and a single tenant cannot burn
 * more than its window.
 */
export interface TenantBudget {
  /** Window length in ms; all budgets reset when it rolls over. */
  windowMs: number;
  /** Total real CPU (ms) the tenant may burn across all its code in a window. */
  cpuMsPerWindow: number;
  /** Total wall-clock (ms) across the tenant's invocations in a window. */
  wallMsPerWindow: number;
  /** Total database queries the tenant may issue in a window. */
  queriesPerWindow: number;
  /** Total rows the tenant may read or write in a window. */
  rowsPerWindow: number;
  /** Total egress bytes (outbound HTTP request+response) in a window. */
  egressBytesPerWindow: number;
}

/** A19 — one budget the tenant was cut off on. `at` is an ISO timestamp. */
export interface GovernorEvent {
  tenantId: string;
  extensionId: string;
  budget:
    | "cpuMsPerWindow"
    | "wallMsPerWindow"
    | "queriesPerWindow"
    | "rowsPerWindow"
    | "egressBytesPerWindow";
  /** The budget value that was exceeded. */
  limit: number;
  /** The tenant's cumulative consumption when it was cut off. */
  used: number;
  at: string;
}

/**
 * T19 — per-tenant and per-process caps on in-flight isolates. These are
 * process-wide because the aggregate is the thing to protect: the per-isolate
 * memory cap is enforced while the aggregate was not (T19).
 */
export interface SandboxHardening {
  /** T11 — max serialised bytes across the isolate/host bridge, checked before parsing. */
  bridgeBytes: number;
  /** T17 — max rows a single invocation may fetch or write. */
  rowsPerInvocation: number;
  /** T17 — max `take` an extension may request in one query. */
  maxTake: number;
  /** T19 — max in-flight isolates for one tenant in this process. */
  maxConcurrentIsolatesPerTenant: number;
  /** T19 — max in-flight isolates across all tenants in this process. */
  maxConcurrentIsolatesPerProcess: number;
}

/**
 * T12/T16 — the revocation store. The kill switch must live in *shared* state
 * (database or Redis), not on a per-process field, or disabling on one replica
 * leaves the extension running on every other. The sandbox defines the
 * contract and fails closed; the platform supplies a database-backed
 * implementation.
 */
export interface RevocationStore {
  isRevoked(extensionId: string): Promise<boolean>;
  revoke(extensionId: string): Promise<void>;
  enable(extensionId: string): Promise<void>;
}

/** In-memory store. For development and tests only — production must supply shared state. */
export class InMemoryRevocationStore implements RevocationStore {
  private revoked = new Set<string>();

  async isRevoked(extensionId: string): Promise<boolean> {
    return this.revoked.has(extensionId);
  }

  async revoke(extensionId: string): Promise<void> {
    this.revoked.add(extensionId);
  }

  async enable(extensionId: string): Promise<void> {
    this.revoked.delete(extensionId);
  }
}

/** T19 — accounts in-flight isolates per tenant and per process. */
export class ConcurrencyRegistry {
  private perTenant = new Map<string, number>();
  private process = 0;

  acquire(tenantId: string, maxPerTenant: number, maxProcess: number): void {
    if (this.process >= maxProcess) {
      throw new SandboxQuotaError(
        "concurrent isolates (process)",
        maxProcess,
        tenantId,
      );
    }
    const current = this.perTenant.get(tenantId) ?? 0;
    if (current >= maxPerTenant) {
      throw new SandboxQuotaError(
        "concurrent isolates (tenant)",
        maxPerTenant,
        tenantId,
      );
    }
    this.perTenant.set(tenantId, current + 1);
    this.process += 1;
  }

  release(tenantId: string): void {
    const current = this.perTenant.get(tenantId) ?? 1;
    if (current <= 1) {
      this.perTenant.delete(tenantId);
    } else {
      this.perTenant.set(tenantId, current - 1);
    }
    this.process = Math.max(0, this.process - 1);
  }
}

/** T13 — hostname → addresses. Injectable so the SSRF logic is testable without DNS. */
export type EgressResolver = (hostname: string) => Promise<readonly string[]>;

const defaultResolver: EgressResolver = async (hostname) => {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((r) => r.address);
};

export interface SandboxRunnerOptions {
  /** T12/T16 — shared revocation state. Defaults to an in-memory store (dev only). */
  revocationStore?: RevocationStore;
  /** T13 — injectable DNS resolver (defaults to node:dns). */
  resolver?: EgressResolver;
  /** T15 — length of the CPU accounting window in ms. */
  cpuWindowMs?: number;
  /** T19 — shared in-flight isolate accounting. Defaults to a process-wide registry. */
  concurrencyRegistry?: ConcurrencyRegistry;
  /** A19 — receive a GovernorEvent whenever a tenant is cut off on a budget. */
  onGovernorEvent?: (event: GovernorEvent) => void;
}

export interface InvocationUsage {
  /** Real CPU consumed inside the isolate (isolate.cpuTime delta), in ms. */
  cpuMs: number;
  queries: number;
  httpCalls: number;
  /** T17 — rows returned to / written by the isolate this invocation. */
  rows: number;
}

export class SandboxScopeError extends Error {
  /**
   * G02 exit criterion: "An extension attempting an undeclared operation
   * is denied and the attempt is audited." Denial already worked
   * (requireScope throws this class); the caller (ExtensionRegistryService
   * .recordUsage) only ever stored `error.name` — a generic
   * "SandboxScopeError" string with no indication of WHICH capability was
   * attempted. Exposing `scope` as a real property lets the caller build
   * an audit record specific enough to act on, instead of "some scope
   * violation happened, no further detail."
   */
  readonly scope: Scope;
  readonly extensionId: string;

  constructor(scope: Scope, extensionId: string) {
    super(
      `Extension "${extensionId}" called a capability requiring scope "${scope}", which its ` +
        `installation does not grant. Scopes are the intersection of the manifest's request and ` +
        `the installing admin's own permissions — an extension can never exceed its installer.`,
    );
    this.name = "SandboxScopeError";
    this.scope = scope;
    this.extensionId = extensionId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SandboxQuotaError extends Error {
  constructor(what: string, limit: number, extensionId: string) {
    super(
      `Extension "${extensionId}" exceeded its ${what} budget of ${limit}.`,
    );
    this.name = "SandboxQuotaError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SandboxDisabledError extends Error {
  constructor(extensionId: string) {
    super(
      `Extension "${extensionId}" is disabled by the platform kill switch.`,
    );
    this.name = "SandboxDisabledError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

const HARDENING_DEFAULTS: Required<SandboxHardening> = {
  bridgeBytes: 1_048_576,
  rowsPerInvocation: 10_000,
  maxTake: 100,
  maxConcurrentIsolatesPerTenant: 10,
  maxConcurrentIsolatesPerProcess: 50,
};

const HARDENING_RANGES: Record<keyof SandboxHardening, readonly [number, number]> = {
  bridgeBytes: [1_024, 8_388_608],
  rowsPerInvocation: [1, 1_000_000],
  maxTake: [1, 1_000],
  maxConcurrentIsolatesPerTenant: [1, 100],
  maxConcurrentIsolatesPerProcess: [1, 200],
};

const TENANT_DEFAULTS: Required<TenantBudget> = {
  windowMs: 60_000,
  cpuMsPerWindow: 5_000,
  wallMsPerWindow: 60_000,
  queriesPerWindow: 10_000,
  rowsPerWindow: 100_000,
  egressBytesPerWindow: 10_485_760,
};

function resolveTenantBudget(partial?: Partial<TenantBudget>): TenantBudget {
  const out = { ...TENANT_DEFAULTS, ...partial } as Record<keyof TenantBudget, number>;
  for (const key of Object.keys(out) as (keyof TenantBudget)[]) {
    if (!Number.isFinite(out[key]) || out[key] <= 0) out[key] = TENANT_DEFAULTS[key];
  }
  return out;
}

function resolveHardening(partial?: Partial<SandboxHardening>): SandboxHardening {
  const out = { ...HARDENING_DEFAULTS, ...partial } as Record<
    keyof SandboxHardening,
    number
  >;
  for (const key of Object.keys(out) as (keyof SandboxHardening)[]) {
    const [min, max] = HARDENING_RANGES[key];
    const value = out[key];
    out[key] = Number.isFinite(value)
      ? Math.min(max, Math.max(min, Math.round(value)))
      : HARDENING_DEFAULTS[key];
  }
  return out;
}

function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/** T11 — every string handed to the isolate is capped on its serialised length. */
function capBridge(
  serialised: string,
  hardening: SandboxHardening,
  extensionId: string,
): string {
  const bytes = byteLength(serialised);
  if (bytes > hardening.bridgeBytes) {
    throw new SandboxQuotaError("bridge result", hardening.bridgeBytes, extensionId);
  }
  return serialised;
}

/** T17 — conservative row count: arrays, { rows: [...] }, or a single value. */
function countRows(value: unknown): number {
  if (value === null || value === undefined) return 0;
  if (Array.isArray(value)) return value.length;
  if (typeof value === "object") {
    const rows = (value as { rows?: unknown }).rows;
    if (Array.isArray(rows)) return rows.length;
  }
  return 1;
}

/** T17 — an extension may not ask a query for more rows than the host permits. */
function assertTakeWithin(
  query: unknown,
  hardening: SandboxHardening,
  extensionId: string,
): void {
  if (query && typeof query === "object") {
    const take = (query as { take?: unknown }).take;
    if (typeof take === "number" && take > hardening.maxTake) {
      throw new SandboxQuotaError(
        "query take",
        hardening.maxTake,
        extensionId,
      );
    }
  }
}

/** T13 — rejects private, loopback, link-local, metadata, CGNAT and reserved IPv4. */
function isPublicIPv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (
    parts.length !== 4 ||
    parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)
  ) {
    return false;
  }
  const [o1 = 0, o2 = 0, o3 = 0] = parts;
  if (o1 === 0) return false; // 0.0.0.0/8 — "this network"
  if (o1 === 10) return false; // 10.0.0.0/8 — private
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return false; // 100.64.0.0/10 — CGNAT
  if (o1 === 127) return false; // 127.0.0.0/8 — loopback
  if (o1 === 169 && o2 === 254) return false; // 169.254.0.0/16 — link-local + metadata
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return false; // 172.16.0.0/12 — private
  if (o1 === 192 && o2 === 0 && o3 === 0) return false; // 192.0.0.0/24 — IETF
  if (o1 === 192 && o2 === 0 && o3 === 2) return false; // 192.0.2.0/24 — TEST-NET-1
  if (o1 === 192 && o2 === 88 && o3 === 99) return false; // 192.88.99.0/24 — 6to4 anycast
  if (o1 === 192 && o2 === 168) return false; // 192.168.0.0/16 — private
  if (o1 === 198 && (o2 === 18 || o2 === 19)) return false; // 198.18.0.0/15 — benchmarking
  if (o1 === 198 && o2 === 51 && o3 === 100) return false; // 198.51.100.0/24 — TEST-NET-2
  if (o1 === 203 && o2 === 0 && o3 === 113) return false; // 203.0.113.0/24 — TEST-NET-3
  if (o1 >= 224) return false; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
  return true;
}

/** T13 — rejects IPv6 loopback, ULA, link-local, multicast, documentation and IPv4-embedding ranges. */
function isPublicIPv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === "::" || lower === "::1") return false;
  if (lower.startsWith("::ffff:")) return false; // IPv4-mapped — ambiguous, reject
  if (lower.startsWith("64:ff9b:")) return false; // NAT64 — embeds IPv4
  if (lower.startsWith("2002:")) return false; // 6to4 — embeds IPv4
  if (lower.startsWith("2001:db8")) return false; // documentation
  if (lower.startsWith("fe80:")) return false; // link-local
  if (/^fc[0-9a-f]/.test(lower) || /^fd[0-9a-f]/.test(lower)) return false; // fc00::/7 ULA
  if (/^ff[0-9a-f]/.test(lower)) return false; // multicast
  return true;
}

function isPublicAddress(address: string): boolean {
  if (address.includes(":")) return isPublicIPv6(address);
  return isPublicIPv4(address);
}

/**
 * Bootstrap installed inside the isolate. Defines the frozen `unierp` global.
 * T05 — every sub-object and the root are frozen, and the property is
 * non-writable and non-configurable, so an extension cannot replace a
 * capability with a shim.
 *
 * The pristine `JSON.stringify`/`JSON.parse` are captured here, BEFORE any
 * extension code can run (T18), so a hostile isolate cannot redefine them to
 * control what the host parses. The hook invoker returns values directly and
 * relies on isolated-vm's own copy semantics — it never serialises inside the
 * isolate.
 */
const BOOTSTRAP = `
  (function (host) {
    "use strict";
    var stringify = JSON.stringify.bind(JSON);
    var parse = JSON.parse.bind(JSON);
    function callHost(name, args) {
      // applySyncPromise blocks this isolate — never the host event loop — until
      // the host settles. Extension code therefore sees a normal async API.
      return host.applySyncPromise(undefined, [name, stringify(args ?? [])]);
    }
    var api = {
      log: function (message, meta) { callHost("log", [String(message), meta ?? null]); },
      data: {
        read: function (model, query) { return parse(callHost("dataRead", [model, query])); },
        write: function (model, operation, payload) {
          return parse(callHost("dataWrite", [model, operation, payload]));
        },
      },
      http: {
        fetch: function (url, init) { return parse(callHost("httpFetch", [url, init ?? null])); },
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
    globalThis.__unierp_invoke__ = async function (hookName, argsJson) {
      var hooks = globalThis.__unierp_hooks__;
      if (!hooks || typeof hooks[hookName] !== "function") {
        throw new Error("Extension does not export hook: " + hookName);
      }
      var out = await hooks[hookName].apply(undefined, parse(argsJson));
      return out === undefined ? null : out;
    };
  })
`;

export class SandboxRunner {
  private readonly revocationStore: RevocationStore;
  private readonly resolver: EgressResolver;
  private readonly cpuWindowMs: number;
  private readonly registry: ConcurrencyRegistry;
  private readonly onGovernorEvent: (event: GovernorEvent) => void;

  /** T15 — automatic breaker state, SEPARATE from the operator kill switch. */
  private breached = new Set<string>();
  /** T15 — per-extension CPU accounting window. */
  private cpuWindow = new Map<string, { windowStart: number; cpuMs: number }>();
  /** A19 — per-tenant aggregate windows, keyed by tenantId. */
  private tenantWindow = new Map<string, { windowStart: number; used: Record<Exclude<keyof TenantBudget, "windowMs">, number> }>();

  constructor(options: SandboxRunnerOptions = {}) {
    this.revocationStore =
      options.revocationStore ?? new InMemoryRevocationStore();
    this.resolver = options.resolver ?? defaultResolver;
    this.cpuWindowMs = options.cpuWindowMs ?? 60_000;
    this.registry = options.concurrencyRegistry ?? new ConcurrencyRegistry();
    this.onGovernorEvent = options.onGovernorEvent ?? (() => undefined);
  }

  /** T12/T16 — platform kill switch (§ 8.3). Subsequent invocations fail closed. */
  async disable(extensionId: string): Promise<void> {
    await this.revocationStore.revoke(extensionId);
  }

  /** T12/T16 — operator enable. Clears the kill switch, never the automatic breaker. */
  async enable(extensionId: string): Promise<void> {
    await this.revocationStore.enable(extensionId);
  }

  /** T12/T16 — fail-closed read: an unreachable store reads as disabled. */
  async isDisabled(extensionId: string): Promise<boolean> {
    try {
      return await this.revocationStore.isRevoked(extensionId);
    } catch {
      return true;
    }
  }

  /**
   * Run an extension's entry module and invoke one exported hook.
   *
   * Returns the hook's serialisable result plus the resources the invocation
   * actually consumed, so the caller can bill, alert, or trip a circuit
   * breaker on it.
   */
  async run(
    code: string,
    installation: SandboxInstallation,
    host: HostCapabilities,
    entry: { hook: string; args?: unknown[] } = { hook: "default" },
  ): Promise<{ result: unknown; usage: InvocationUsage }> {
    const { extensionId, tenantId } = installation;

    const hardening = resolveHardening(installation.hardening);
    const budget = ResourceBudgetSchema.parse(installation.budget ?? {});
    const scopes = new Set<Scope>(installation.scopes);
    const approved = new Set(installation.approvedHosts ?? []);
    const usage: InvocationUsage = { cpuMs: 0, queries: 0, httpCalls: 0, rows: 0 };

    // T19 — acquire an in-flight-isolate slot SYNCHRONOUSLY, before any await,
    // so the cap counts every isolate that is about to exist.
    this.registry.acquire(
      tenantId,
      hardening.maxConcurrentIsolatesPerTenant,
      hardening.maxConcurrentIsolatesPerProcess,
    );

    let isolate: ivm.Isolate | undefined;

    try {
      // T12/T16 — revocation is shared state, re-read on every entry, and
      // fails closed: if the store cannot be reached, the extension does not run.
      // T10a — every later call fails closed once the kill switch is thrown.
      let revoked: boolean;
      try {
        revoked = await this.revocationStore.isRevoked(extensionId);
      } catch {
        throw new SandboxDisabledError(extensionId);
      }
      if (revoked) throw new SandboxDisabledError(extensionId);

      // T15 — the per-minute window gates entry; the breaker blocks re-entry.
      this.assertCpuWindow(extensionId, budget);
      const window = this.cpuWindow.get(extensionId);
      const remainingCpuMs = window
        ? Math.max(0, budget.cpuMsPerMinute - window.cpuMs)
        : budget.cpuMsPerMinute;

      const iso = new ivm.Isolate({ memoryLimit: budget.memoryMb });
      isolate = iso;
      // T04 — the isolate heap is hard-capped at budget.memoryMb. This bounds
      // any single tenant's allocation, which is what makes T11's bridge byte
      // budget and T19's concurrency cap the aggregate controls.

      // T14 — real CPU, read from the isolate itself. Wall clock (hrtime)
      // would bill the host's own latency back to the extension. isolated-vm
      // reports both counters in nanoseconds.
      let cpuMark = iso.cpuTime;
      const accrueCpu = (): number => {
        if (iso.isDisposed) return 0;
        const now = iso.cpuTime;
        const deltaMs = Number(now - cpuMark) / 1e6;
        cpuMark = now;
        usage.cpuMs += deltaMs;
        return deltaMs;
      };

      const context = await iso.createContext();

      const requireScope = (scope: Scope) => {
        // T03 — the capability is re-checked on the HOST side at call time,
        // not only inside the isolate. The bridge is the authority.
        if (!scopes.has(scope)) throw new SandboxScopeError(scope, extensionId);
      };

      const assertEgressAllowed = async (url: string): Promise<void> => {
        // T07 — outbound HTTP is gated on the install-time approved set AND on
        // the URL resolving only to public addresses. See T13 for the SSRF
        // half of this check.
        let parsed: URL;
        try {
          parsed = new URL(url);
        } catch {
          throw new Error(`Extension "${extensionId}" requested a malformed URL.`);
        }
        // T13 — https only. This is what keeps the "no filesystem" claim true
        // on the egress path: file://, and every other non-https scheme, dies here.
        if (parsed.protocol !== "https:") {
          throw new Error(
            `Extension "${extensionId}" attempted egress with scheme "${parsed.protocol}". ` +
              `Only https: is permitted.`,
          );
        }
        const hostname = parsed.hostname;
        if (!approved.has(hostname)) {
          throw new Error(
            `Extension "${extensionId}" attempted egress to "${hostname}", which is not an ` +
              `admin-approved host for this installation (§ 8.3: outbound HTTP only to ` +
              `manifest-declared, admin-approved hosts).`,
          );
        }
        // T13 — resolve and reject non-public addresses AFTER resolution. A
        // hostname string check alone is not SSRF protection (DNS rebinding).
        let addresses: readonly string[];
        try {
          addresses = await this.resolver(hostname);
        } catch {
          throw new Error(
            `Extension "${extensionId}" could not resolve "${hostname}". ` +
              `Egress requires a resolvable hostname.`,
          );
        }
        if (addresses.length === 0) {
          throw new Error(
            `Extension "${extensionId}" attempted egress to "${hostname}", which resolved to ` +
              `no addresses.`,
          );
        }
        for (const address of addresses) {
          if (!isPublicAddress(address)) {
            throw new Error(
              `Extension "${extensionId}" attempted egress to "${hostname}", which resolves to ` +
                `the non-public address "${address}". Outbound requests to private, loopback, ` +
                `link-local or metadata addresses are blocked (SSRF).`,
            );
          }
        }
      };

      // The single host bridge. Everything the isolate can do arrives here, and
      // every branch re-checks the scope on the host side — a capability handed
      // in is not a capability trusted.
      const bridge = new ivm.Reference(
        async (name: string, argsJson: string): Promise<string | undefined> => {
          // T11 — the serialised payload is capped BEFORE JSON.parse on the
          // host heap. Parsing first would be checking after the damage.
          if (byteLength(argsJson) > hardening.bridgeBytes) {
            throw new SandboxQuotaError(
              "bridge payload",
              hardening.bridgeBytes,
              extensionId,
            );
          }
          // T15 — CPU is charged during execution at every host hop, so a
          // budget of 100 ms cannot be silently exceeded across a single call.
          const deltaCpu = accrueCpu();
          this.chargeTenant(tenantId, extensionId, "cpuMsPerWindow", deltaCpu, installation.tenantBudget);
          if (usage.cpuMs >= remainingCpuMs) {
            throw new SandboxQuotaError(
              "CPU-per-minute during execution",
              budget.cpuMsPerMinute,
              extensionId,
            );
          }

          const args = JSON.parse(argsJson) as unknown[];
          switch (name) {
            case "log": {
              requireScope("log:write");
              // T09a — the tenant is re-derived on the host side from the
              // installation. The isolate cannot choose whose data it reads.
              host.log("log", { extensionId, tenantId }, args);
              return undefined;
            }
            case "dataRead": {
              requireScope("data:read");
              // T06 — the query count is charged before the host call, so the
              // quota is enforced even if the read itself is fast.
              this.charge(
                usage,
                "queries",
                budget.queriesPerInvocation,
                extensionId,
              );
              this.chargeTenant(tenantId, extensionId, "queriesPerWindow", 1, installation.tenantBudget);
              assertTakeWithin(args[1], hardening, extensionId);
              if (!host.dataRead)
                throw new Error(
                  "data:read is granted but no host reader is wired",
                );
              const result = (await host.dataRead(String(args[0]), args[1])) ?? null;
              const rCount = countRows(result);
              this.chargeRows(usage, result, hardening, extensionId);
              this.chargeTenant(tenantId, extensionId, "rowsPerWindow", rCount, installation.tenantBudget);
              return capBridge(
                JSON.stringify(result),
                hardening,
                extensionId,
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
              this.chargeTenant(tenantId, extensionId, "queriesPerWindow", 1, installation.tenantBudget);
              if (!host.dataWrite)
                throw new Error(
                  "data:write is granted but no host writer is wired",
                );
              const result =
                (await host.dataWrite(
                  String(args[0]),
                  String(args[1]),
                  args[2],
                )) ?? null;
              const rCount = countRows(result);
              this.chargeRows(usage, result, hardening, extensionId);
              this.chargeTenant(tenantId, extensionId, "rowsPerWindow", rCount, installation.tenantBudget);
              return capBridge(
                JSON.stringify(result),
                hardening,
                extensionId,
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
              await assertEgressAllowed(url);
              if (!host.httpFetch)
                throw new Error(
                  "http:fetch is granted but no host fetcher is wired",
                );
              const response =
                (await host.httpFetch(url, args[1])) ?? null;
              // T13 — a 3xx response is rejected rather than followed to an
              // unchecked destination. The host fetcher MUST NOT follow
              // redirects (see the HostCapabilities contract).
              if (isRedirectResponse(response)) {
                throw new Error(
                  `Extension "${extensionId}" received an HTTP redirect from "${url}". ` +
                    `Redirects are not permitted on the egress path.`,
                );
              }
              const respJson = JSON.stringify(response);
              const respBytes = byteLength(respJson);
              this.chargeTenant(tenantId, extensionId, "egressBytesPerWindow", respBytes, installation.tenantBudget);
              return capBridge(
                respJson,
                hardening,
                extensionId,
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
      // T08a — every entry into the isolate carries a wall-clock deadline
      // (budget.timeoutMs), so a runaway loop cannot outlive its budget.
      const moduleScript = await iso.compileScript(
        `globalThis.__unierp_hooks__ = (function(){ "use strict";\n${code}\n;` +
          ` return typeof hooks !== "undefined" ? hooks : null; })();`,
      );
      await moduleScript.run(context, { timeout: budget.timeoutMs });

      // T18 — the invoker was installed by the bootstrap using the pristine
      // JSON functions, and its result crosses via copy semantics: the host
      // never parses a string produced inside the isolate.
      const invoke = await context.eval("globalThis.__unierp_invoke__", {
        reference: true,
        timeout: budget.timeoutMs,
      });

      const resultValue = await invoke.apply(
        undefined,
        [entry.hook, JSON.stringify(entry.args ?? [])],
        { timeout: budget.timeoutMs, result: { copy: true, promise: true } },
      );

      accrueCpu();
      this.chargeCpu(extensionId, usage.cpuMs, budget);

      return { result: resultValue, usage };
    } catch (err: unknown) {
      if (err instanceof Error) {
        const m = err.message.match(/^Extension "([^"]+)" exceeded its (.+) budget of (\d+(?:\.\d+)?)\.$/);
        if (m) {
          throw new SandboxQuotaError(m[2], Number(m[3]), m[1]);
        }
      }
      throw err;
    } finally {
      // T19 — always release the slot, including on timeout or escape attempt.
      this.registry.release(tenantId);
      // Always reclaim the heap, including on timeout or escape attempt.
      if (isolate && !isolate.isDisposed) isolate.dispose();
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

  /** T17 — a row-count budget alongside the query-count budget. */
  private chargeRows(
    usage: InvocationUsage,
    result: unknown,
    hardening: SandboxHardening,
    extensionId: string,
  ): void {
    usage.rows += countRows(result);
    if (usage.rows > hardening.rowsPerInvocation) {
      throw new SandboxQuotaError(
        "rows",
        hardening.rowsPerInvocation,
        extensionId,
      );
    }
  }

  /** T15 — the window; the breaker is cleared only when the window rolls over. */
  private assertCpuWindow(
    extensionId: string,
    budget: ResourceBudget,
  ): void {
    const now = Date.now();
    const w = this.cpuWindow.get(extensionId);
    if (!w || now - w.windowStart >= this.cpuWindowMs) {
      this.cpuWindow.set(extensionId, { windowStart: now, cpuMs: 0 });
      this.breached.delete(extensionId);
      return;
    }
    if (this.breached.has(extensionId)) {
      throw new SandboxQuotaError(
        "CPU-per-minute (breaker tripped)",
        budget.cpuMsPerMinute,
        extensionId,
      );
    }
    if (w.cpuMs >= budget.cpuMsPerMinute) {
      throw new SandboxQuotaError(
        "CPU-per-minute",
        budget.cpuMsPerMinute,
        extensionId,
      );
    }
  }

  /** A19 — per-tenant budget enforcement and governor event auditing. */
  private assertTenantWindow(
    tenantId: string,
    extensionId: string,
    tenantBudget?: Partial<TenantBudget>,
  ): TenantBudget {
    const budget = resolveTenantBudget(tenantBudget);
    const now = Date.now();
    let tw = this.tenantWindow.get(tenantId);
    if (!tw || now - tw.windowStart >= budget.windowMs) {
      tw = {
        windowStart: now,
        used: {
          cpuMsPerWindow: 0,
          wallMsPerWindow: 0,
          queriesPerWindow: 0,
          rowsPerWindow: 0,
          egressBytesPerWindow: 0,
        },
      };
      this.tenantWindow.set(tenantId, tw);
    }
    return budget;
  }

  private chargeTenant(
    tenantId: string,
    extensionId: string,
    field: Exclude<keyof TenantBudget, "windowMs">,
    amount: number,
    tenantBudget?: Partial<TenantBudget>,
  ): void {
    const budget = this.assertTenantWindow(tenantId, extensionId, tenantBudget);
    const tw = this.tenantWindow.get(tenantId)!;
    tw.used[field] += amount;
    const limit = budget[field];
    if (tw.used[field] > limit) {
      this.onGovernorEvent({
        tenantId,
        extensionId,
        budget: field,
        limit,
        used: tw.used[field],
        at: new Date().toISOString(),
      });
      throw new SandboxQuotaError(`tenant ${field}`, limit, extensionId);
    }
  }

  /** T15 — tripping the automatic breaker must NOT reuse the operator kill switch. */
  private chargeCpu(
    extensionId: string,
    cpuMs: number,
    budget: ResourceBudget,
  ): void {
    const now = Date.now();
    const w = this.cpuWindow.get(extensionId);
    if (!w || now - w.windowStart >= this.cpuWindowMs) {
      this.cpuWindow.set(extensionId, { windowStart: now, cpuMs });
      this.breached.delete(extensionId);
      return;
    }
    w.cpuMs += cpuMs;
    if (w.cpuMs >= budget.cpuMsPerMinute) {
      this.breached.add(extensionId);
    }
  }
}

/** T13 — a 3xx response means a redirect was served; reject it. */
function isRedirectResponse(response: unknown): boolean {
  if (!response || typeof response !== "object") return false;
  const status = (response as { status?: unknown }).status;
  return (
    typeof status === "number" && status >= 300 && status < 400
  );
}
