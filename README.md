# unierp-sandbox

**Layer L2** of the UniERP layered repository architecture
(`PLATFORM_ARCHITECTURE.md` § 4.2).

## Why it is its own repository

The capability-scoped V8 isolate that runs Tier-3 extension code and Studio scripts (ADR-009). Its own repository because the isolation contract must be reviewable independently of what runs inside it.

## The invariant

A repository may depend only on published artifacts of a strictly lower layer.
Never sideways within a layer. Never upward.

## Extraction status

Extracted from the `ERPSys` monorepo as § 14 Phase 3, with history preserved
via `git-filter-repo`, and packaged so it is genuinely installable: an explicit
`files` allowlist (npm otherwise falls back to `.gitignore` and omits `dist/`),
no `workspace:` specifiers, and a local tsconfig base so it typechecks
standalone.

The monorepo copy remains authoritative until consumers switch.
