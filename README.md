# unierp-sandbox

**Layer L2 — Runtime** of the [UniERP](../unierp-platform) platform.
Depends on: L0, L2.

## What this is

The capability-scoped V8 isolate that runs Tier-3 extension code and Studio scripts.

## The invariant this repository owns

**No ambient authority.** No `process`, no `require`, no `fetch`, no filesystem — the identifiers do not exist. Every host capability re-checks its scope on the host side, because a capability handed in is not a capability trusted. Its own repository so the isolation contract is reviewable independently of what runs inside it.

## The rule that applies everywhere

A repository may depend only on published artifacts of a **strictly lower
layer** — never sideways within a layer, never upward. A cycle is not
discouraged; it is unrepresentable, because the lower layer's package cannot
name the higher one.

See the [platform overview](../unierp-platform/README.md) for the full map, and
[`PLATFORM_ARCHITECTURE.md`](../ERPSys/docs/PLATFORM_ARCHITECTURE.md) § 4.2 for
the reasoning.

## Licence

AGPL-3.0.
