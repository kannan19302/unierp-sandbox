# THREAT MODEL — `@unerp/sandbox`

> **Phase A16.** Established 2026-08-07 · Amended, never replaced.
>
> This document exists because the sandbox carries the platform's highest-consequence claim:
> it is the only thing standing between one tenant's authored code and every other tenant's
> payroll and patient records. Thirty phases of the developer platform (Track G) are
> hard-blocked on it, and `A17` (hardening), `A18` (the escape suite) and `A19` (governor
> limits) are the work this document defines.
>
> **Every threat below is numbered. A17 must mitigate each one. A18 must contain one test per
> threat that fails when its mitigation is removed.** A threat here with no mitigation is a
> defect, filed, not a note.

---

## 0. What was assumed, and what is actually true

`docs/programme/00-BASELINE.md` and defect **D009** described this component as *"393 lines
carrying the platform's highest-consequence claim, unverified by any adversarial test."* Reading
it for this phase, **that framing was wrong in two ways and the record is corrected here rather
than quietly**:

| Assumed | Measured |
| :------ | :------- |
| "393 lines is not obviously enough to be that" | Line count was a poor proxy. The design is careful and deliberate: a real `isolated-vm` V8 isolate rather than `node:vm`, a capability model with **host-side** scope re-checks, no Prisma client or connection string or settable tenant id ever handed in, a frozen `unierp` global, and `finally { isolate.dispose() }`. |
| "unverified by any adversarial test" | `src/sandbox.spec.ts` has **18 targeted tests**, including one that specifically denies the `node:vm` escape one-liner the previous implementation allowed. |

**The real gap is narrower and more interesting than "it is thin".** The existing tests verify
the mitigations that were *designed*. They cannot verify mitigations that do not exist. Sections
2 and 3 below separate those two categories, and **nine threats currently have no mitigation at
all** — several of which matter more than the escapes that are covered.

`D009` is amended accordingly in the defect log. The severity stands; the reasoning changes.

---

## 1. The claims under test

`unierp-platform/ARCHITECTURE.md` step 6 states, verbatim:

> *"…its handler runs inside **`unierp-sandbox`** — a V8 isolate with no `process`, no
> `require`, no filesystem, and metered CPU, memory, query and egress budgets."*

That is seven distinct claims. `PLATFORM_ARCHITECTURE.md § 8.3` adds a kill switch reachable
from the Platform Admin Console, and egress restricted to manifest-declared, admin-approved
hosts. **A16's exit criterion is that every one of those claims maps to a numbered threat with a
stated mitigation.** The mapping:

| Claim | Threats | Status |
| :---- | :------ | :----- |
| V8 isolate (not a shared context) | T01 | ✅ mitigated, tested |
| no `process` | T02 | ✅ mitigated, tested |
| no `require` | T02 | ✅ mitigated, tested |
| no filesystem | T02, T13 | ⚠️ direct access blocked; reachable indirectly via SSRF — **T13** |
| metered **CPU** | T08, T09, T10 | ❌ **the meter measures the wrong quantity and is per-replica** |
| metered **memory** | T04, T11 | ⚠️ isolate heap capped; **host** heap is not — T11 |
| metered **query** | T06, T14 | ⚠️ query *count* capped; query *cost* is unbounded — T14 |
| metered **egress** | T07, T13 | ⚠️ count and hostname capped; **not SSRF-safe** — T13 |
| kill switch, console-reachable | T12, T15 | ❌ **per-process, and not persisted** |
| admin-approved hosts only | T07 | ✅ mitigated, tested |

Four of the nine claims are only partly true today, and two are materially false in a
multi-replica deployment. **None of that is visible from the tests, because the tests assert
what was built.**

---

## 2. Threats that ARE mitigated

Recorded so A17 does not weaken them and A18 keeps a test for each. Each row's mitigation is
present in `src/index.ts` and asserted in `src/sandbox.spec.ts`.

| # | Threat | Mitigation | Test |
| :- | :----- | :--------- | :--- |
| **T01** | **Context escape.** `this.constructor.constructor("return process")().mainModule.require("fs")` — the classic `node:vm` break-out, which works because `node:vm` shares a heap and a global object with the host. | A genuine `isolated-vm` isolate: separate heap, separate global. There is no `process` identifier to reach. | ✅ *"denies the node:vm escape that the previous implementation allowed"* |
| **T02** | **Ambient authority.** Reaching `require`, `fetch`, `process`, timers, or any host global. | Nothing is injected but a single `ivm.Reference` bridge. No `module`/`exports` shim is provided — deliberately, since a mutable host-shaped object is how ambient authority creeps back. | ✅ *"has no require, no fetch, no process and no host globals"* |
| **T03** | **Capability forgery / privilege escalation.** Calling a capability the installation does not grant, or reaching one by patching the API object. | Scope checked **on the host side** at call time in every bridge branch, not only inside the isolate. Scopes are the intersection of the manifest request and the installing admin's own permissions. | ✅ three tests, including *"re-checks the scope on the host side, not only in the isolate"* |
| **T04** | **Heap exhaustion inside the isolate.** Allocating until the process dies. | `new ivm.Isolate({ memoryLimit: budget.memoryMb })`, default 32 MB, hard cap 512. | ✅ *"enforces the isolate memory cap"* |
| **T05** | **Global tampering.** Replacing `unierp.data.read` with a shim to intercept or re-route. | `Object.freeze` on each sub-object and the root, plus `defineProperty(globalThis,'unierp',{writable:false,configurable:false})`. | ✅ *"freezes the unierp global so an extension cannot replace a capability"* |
| **T06** | **Query flooding.** Issuing unbounded reads/writes in one invocation. | `queriesPerInvocation`, default 50, hard cap 1,000, charged before the host call. | ✅ *"caps queries per invocation"* |
| **T07** | **Unapproved egress.** HTTP to a host the installing admin never approved. | `assertEgressAllowed` — hostname must be in the install-time approved set. A manifest cannot approve itself. | ✅ two tests, allow and deny |
| **T08a** | **Infinite loop.** `while(true){}`. | `timeout: budget.timeoutMs` on every `eval`/`run`/`apply`, default 1,000 ms, hard cap 30 s. Bounds a *single entry* — see T09 for what it does not bound. | ✅ *"enforces a wall-clock deadline on a runaway loop"* |
| **T09a** | **Tenant forgery.** Influencing which tenant's data a query reads. | The host re-derives tenant from the installation. The isolate has no way to set it; RLS then applies to extension queries exactly as to first-party ones. | ✅ *"never lets the isolate choose its own tenant"* |
| **T10a** | **Continuing after revocation.** | `disable()` marks dead, disposes, and every later call fails closed. | ✅ *"fails closed once the kill switch is thrown"* — but see **T12** |

---

## 3. Threats with NO mitigation — A17's actual scope

**These nine are the phase's real output.** Ordered by consequence.

### T11 · 🔴 Host heap exhaustion through the bridge — no payload size budget

Bridge arguments and results cross as JSON: `JSON.stringify(args)` in the isolate,
`JSON.parse(argsJson)` on the host, and the reverse on the way back. **Nothing caps the size of
either.**

An extension inside a 32 MB isolate can construct a ~30 MB string and pass it to `data.write`,
or return it from a hook. The host then parses it on the **host** heap, which has no per-extension
cap at all. Repeated across concurrent invocations this is an OOM on the API process — which
takes down every tenant, not just the offender.

> **A17 must add:** a byte budget on bridge arguments and results, charged before
> `JSON.parse` on the host side, and a budget field alongside `memoryMb`. The check must be on
> the *serialised* length, before parsing — checking after parsing is checking after the damage.

### T12 · 🔴 The kill switch is per-process, so it does not work

`disabled` and `cpuWindow` are instance fields on `SandboxRunner`:

```ts
private disabled = new Set<string>();
private cpuWindow = new Map<string, { windowStart: number; cpuMs: number }>();
```

In any deployment with more than one API replica — which is every production deployment — each
replica holds its own set. **Calling `disable()` on one replica leaves the extension running on
every other.** `PLATFORM_ARCHITECTURE § 8.3` requires the kill switch to be reachable from the
Platform Admin Console; an operator who uses it would see it succeed and the extension would
keep executing.

This is the single most dangerous finding in this document, because it is the control an operator
reaches for **during an incident**, and it would appear to work.

> **A17 must move revocation to shared state** (the database, or Redis with a database
> fallback) and fail **closed** when that state is unreachable. An extension whose status cannot
> be confirmed must not run.

### T13 · 🔴 The hostname allowlist is not SSRF protection

`assertEgressAllowed` resolves nothing — it compares `new URL(url).hostname` against a string
set. That leaves open:

- **DNS rebinding.** An approved hostname the extension's author controls, resolving to
  `169.254.169.254` (cloud instance metadata), `127.0.0.1`, or a private RFC 1918 address. The
  hostname check passes; the request reaches the host's own network.
- **Redirects.** The allowlist is checked once, on the initial URL. If `host.httpFetch` follows
  redirects, the final destination is unchecked.
- **The filesystem claim.** `ARCHITECTURE.md` says "no filesystem". A `file://` URL, or an
  approved host redirecting to one, would depend entirely on what `host.httpFetch` accepts —
  which the sandbox does not constrain. **The "no filesystem" claim is therefore true of the
  isolate and unproven of the egress path.**

> **A17 must:** resolve the hostname and reject non-public IP ranges *after* resolution and
> before connection, pin the resolved address for the request, disable redirect-following or
> re-check every hop, and allowlist schemes to `https:` only.

### T14 · 🟠 CPU is metered in wall-clock time, including time it did not use

```ts
const started = process.hrtime.bigint();
…
usage.cpuMs = Number(process.hrtime.bigint() - started) / 1e6;
```

`hrtime` is **wall clock**. The measured span includes every host callback the invocation waited
on — a slow database query, a 900 ms HTTP call. So:

- An extension that calls one slow API is billed CPU it never consumed, and can be
  auto-disabled by `chargeCpu` for someone else's latency.
- An extension doing genuine CPU work while awaiting nothing is measured correctly by accident.
- The field is named `cpuMs` and the budget `cpuMsPerMinute`, so every consumer of
  `InvocationUsage` — billing, alerting, circuit-breaking — inherits the error.

> **A17 must** either measure real CPU (`isolate.getHeapStatistics()` / isolated-vm's
> `cpuTime` and `wallTime`, which it exposes precisely for this) or rename the field and budget
> to `wallMs` and stop claiming CPU is metered. **Either is honest; the present state is not.**

### T15 · 🟠 The CPU budget is only enforced between invocations

`assertCpuWindow` runs at entry and `chargeCpu` after completion. Within one invocation the only
bound is `timeoutMs`. So a single call may consume up to 30 s (the hard cap) regardless of a
`cpuMsPerMinute` of 100, and the breaker trips only afterwards.

Worse, `chargeCpu` calls `this.disable(extensionId)` to trip the breaker — reusing the operator
kill switch as a rate limiter. An automatic breaker and a deliberate revocation become
indistinguishable, and `enable()` clears both.

> **A17 must** enforce the budget *during* execution (isolated-vm's execution timeout combined
> with a periodic CPU check), and **separate** the automatic breaker from the operator kill
> switch — two states, two reasons, two audit trails.

### T16 · 🟠 Revocation is not persisted

`disabled` is in-memory. A process restart re-enables every extension disabled by an operator
*and* every one auto-disabled by the breaker. A rolling deploy silently clears all revocations.

> **A17:** revocation is a persisted fact, re-read on start, fail-closed if unreadable. Same
> mechanism as T12.

### T17 · 🟠 Query cost is unbounded — only query *count* is capped

`dataRead(model, query)` charges one unit and forwards an arbitrary `query` object. Nothing
bounds what it asks for. Fifty queries is fifty full table scans, or fifty
`take: 1_000_000` reads, all inside the budget and all against a database shared with every
other tenant. This is the noisy-neighbour path **A20** exists for, arriving through the sandbox.

> **A17 must** bound result size and shape at the host boundary: a maximum `take`, a required
> index for any filter, a statement timeout on extension-issued queries, and a row-count budget
> alongside the query-count budget.

### T18 · 🟡 A poisoned `JSON.stringify` lets the isolate control what the host parses

The invoke wrapper serialises the hook's return value **inside** the isolate:

```js
const out = hooks[hookName].apply(undefined, JSON.parse(argsJson));
return JSON.stringify(out === undefined ? null : out);
```

An extension may redefine `JSON.stringify` on its own global before returning. The wrapper then
calls the attacker's function, which may emit any string at all. The host does
`JSON.parse(String(raw))` and trusts the shape.

This is not an escape — the isolate boundary holds — but it means **the host cannot trust the
structure of an extension's return value**, and anything downstream that assumes a shape
(a database write, a rendered template, an event payload) is receiving attacker-controlled data
in a place the type system says is safe.

> **A17 must** transfer results as structured values via isolated-vm's own copy semantics
> (`result: { copy: true }` is already used on `apply` — the inner `JSON.stringify` should be
> removed entirely) or validate the parsed result against the hook's declared output schema on
> the host side. Prefer both.

### T19 · 🟡 No cap on concurrent isolates

`run()` creates an isolate per invocation with no limit on how many exist at once. Each reserves
up to `memoryMb`. A tenant triggering many concurrent hooks can reserve arbitrary host memory
without any single isolate exceeding its cap — the per-isolate budget is enforced and the
aggregate is not.

> **A17:** a per-tenant and per-process concurrent-isolate cap, with queueing or rejection, and
> isolate reuse where it is safe.

---

## 4. Explicitly out of scope, with reasons

Stated so the boundary is a decision rather than an omission:

| Not defended against | Why |
| :------------------- | :-- |
| V8 zero-days | We inherit V8's boundary. Mitigation is patch latency, not design — which makes it an `A29`/dependency-update concern, not a sandbox one. |
| Spectre-class side channels | `SharedArrayBuffer` and high-resolution timers are not exposed to the isolate. Residual risk accepted; revisit if either is ever exposed. |
| A malicious *platform* operator | Outside the trust boundary by construction. The audit trail, not the sandbox, is the control (`C03`, `C04`). |
| Denial of service by legitimate volume | That is `A20`'s rate limiting, not the sandbox's budgets. The two must compose; **T17** is where they overlap. |

---

## 5. What A17, A18 and A19 must now deliver

**A17 — hardening.** Mitigate T11–T19. Do not weaken T01–T10.

**A18 — the escape suite.** One test per threat, T01 through T19. **Each test must fail when its
mitigation is removed** — a test that passes unconditionally is the defect this whole programme
exists to eliminate, and the current 18 tests have not been checked for it. A18 must verify that
too, for the existing tests as well as the new ones.

**A19 — governor limits.** T12, T14, T15, T16, T17 and T19 are all budget-enforcement, and they
are the direct analogue of Apex governor limits. A19 is what makes tenants trust running
third-party code, and it is why `01-PRIORITY-AND-SEQUENCING § 3` blocks all thirty Track G phases
on this stage rather than on the builders.

**The three that must not ship without a fix, in this order:**

1. **T12** — the kill switch does not work in production, and an operator would believe it did.
2. **T13** — the hostname allowlist reads as SSRF protection and is not.
3. **T11** — one tenant's extension can OOM the process serving every tenant.

---

## 6. Amendment log

| Date | Change | By |
| :--- | :----- | :- |
| 2026-08-07 | Established (A16). 19 threats; 10 mitigated and tested, 9 with no mitigation. Corrects D009's premise: the component is not thin or untested — it has 18 targeted tests — but the tests assert the mitigations that were designed, and nine threats were never designed for. T12 (per-process kill switch) and T13 (hostname allowlist mistaken for SSRF protection) are the findings that matter most. | Claude Code |
