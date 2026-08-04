import * as vm from "vm";
import type { ExtensionContext, ExtensionFactory } from "@unerp/extension-api";

/**
 * ⚠ NOT A SECURITY BOUNDARY YET.
 *
 * This runner uses Node's built-in `vm` module. Node's own documentation states
 * plainly that "the vm module is not a security mechanism — do not use it to run
 * untrusted code." A context created by `vm.createContext` is escapable in one
 * expression:
 *
 *   this.constructor.constructor("return process")().mainModule.require("fs")
 *
 * which yields the host `process`, and from there the filesystem, environment
 * variables and network. There is also no memory cap, no CPU deadline and no
 * capability model here.
 *
 * `docs/PLATFORM_ARCHITECTURE.md` § 8.3 and TRD ADR-009 require Tier-3
 * extension code to run in a capability-scoped V8 isolate (`isolated-vm`), with
 * a frozen context exposing only the operations the manifest grants, plus
 * metered CPU/memory/query/egress budgets and a per-extension kill switch. That
 * work is not done.
 *
 * Until it is, this class refuses to execute anything unless the caller states
 * explicitly that the code is trusted first-party. Failing closed is the point:
 * the ordering constraint in § 8.3 is that the sandbox must exist BEFORE the
 * marketplace opens, because retrofitting isolation onto customer code already
 * running in-process is not a migration anyone has completed.
 */
export interface SandboxOptions {
  /**
   * Set only for first-party code shipped in this repository. Third-party or
   * customer-authored code must never be run through this implementation.
   */
  trustedFirstParty: boolean;
  /** Wall-clock limit for the script body. Does not bound async work. */
  timeoutMs?: number;
  /**
   * Sink for the `console` shim handed to extension code. Injected rather than
   * writing to the real console because `console.*` is banned platform-wide
   * (TRD § 3 — structured Pino logging only, correlation and tenant id on every
   * line). Defaults to discarding output.
   */
  logSink?: (level: "log" | "error", tenantId: string, args: unknown[]) => void;
}

export class SandboxRunner {
  async execute(
    code: string,
    context: ExtensionContext,
    options: SandboxOptions,
  ): Promise<ReturnType<ExtensionFactory>> {
    if (!options?.trustedFirstParty) {
      throw new Error(
        "SandboxRunner refuses to execute: this implementation uses node:vm, which is not " +
          "an isolation boundary (see ADR-009). Only trusted first-party code may run here, " +
          "and the caller must say so explicitly. Untrusted code requires the isolated-vm " +
          "capability sandbox described in PLATFORM_ARCHITECTURE § 8.3.",
      );
    }

    const sink = options.logSink ?? (() => {});
    const moduleShim: { exports: Record<string, unknown> } = { exports: {} };
    const sandboxContext = {
      console: {
        log: (...args: unknown[]) => sink("log", context.tenantId, args),
        error: (...args: unknown[]) => sink("error", context.tenantId, args),
      },
      module: moduleShim,
      exports: moduleShim.exports,
    };

    // Deny dynamic code generation inside the context. This does not make the
    // context safe — it only removes the easiest of several escape routes.
    vm.createContext(sandboxContext, {
      codeGeneration: { strings: false, wasm: false },
    });

    const script = new vm.Script(code);
    script.runInContext(sandboxContext, { timeout: options.timeoutMs ?? 1000 });

    // The sandbox writes an arbitrary value onto module.exports, so widen
    // through `unknown` before narrowing: it may be the factory itself (CommonJS
    // `module.exports = fn`) or a namespace with a `default` (ESM interop).
    const exported: unknown = moduleShim.exports;
    const factory: ExtensionFactory | undefined =
      typeof exported === "function"
        ? (exported as ExtensionFactory)
        : (exported as { default?: ExtensionFactory } | null)?.default;

    if (typeof factory !== "function") {
      throw new Error(
        "Extension entry point must export a default factory function.",
      );
    }

    return factory(context);
  }
}
