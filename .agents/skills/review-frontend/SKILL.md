---
name: review-frontend
description: Performs a strict code review of the Svelte 5 frontend code (files, diffs, or snippets). Trigger whenever the user shares frontend code (Svelte, TypeScript, CSS) and asks for a review, feedback, or says "review this" — including partial snippets.
---

# Svelte Frontend Code Review

Review from the perspective of a principal engineer with deep expertise in Svelte 5 (runes), TypeScript, browser security, and SPA architecture. Explain findings clearly (as if the reader is a junior engineer): what to change, why it matters, and what breaks if left unaddressed.

## 0. Problem-Solution Fit

Ensure the code addresses a real issue or feature, not hypothetical future needs. Flag speculative abstractions, premature generalization, and unneeded indirection. Prefer the simplest design that solves the problem.

## 1. Project Standards

API Access: All backend calls must go through the generated client (`api.<tag>.<operation>(...)` from `$lib/generated/endpoints.ts`). Flag raw `fetch()` calls outside `lib/fetch.ts` and hand-written request/response types that duplicate generated ones.

Generated Code: Files under `src/lib/generated/` must never be hand-edited. If they changed without a matching `openapi.json` change, flag it.

State: Shared app state lives in `AppState.svelte.ts` using rune-based class fields (`$state`, `$derived`) with small setter methods. New global state should follow this pattern, not ad-hoc module-level variables or legacy stores.

Formatting & Checks: Code must pass `cargo -q xtask check frontend`. Flag `any` casts, `@ts-ignore`, and disabled lint rules without justification.

## 2. Svelte 5 Correctness

Runes: Use `$state`/`$derived`/`$effect` (no legacy `$:` reactive statements or `svelte/store` for new code). Derived values must use `$derived`, not manual synchronization in `$effect`.

Effects: `$effect` is a last resort — flag effects that merely compute state (use `$derived`), and effects missing cleanup for timers, subscriptions, or event listeners.

Reactivity Pitfalls: Watch for destructuring that breaks reactivity, stale closures in async callbacks, and mutation of non-reactive objects expected to trigger updates.

Async UI State: Every async operation needs loading and error states. Check for race conditions when a component fires overlapping requests (e.g., stale response overwriting newer state).

## 3. TypeScript Quality

Types come from the generated API definitions where applicable. `null` checks on API optionals must use `!== null` (OpenAPI `Option<T>` is `T | null`), never truthiness — zero and empty string are valid values.

No `any`, no unchecked casts, no non-null assertions (`!`) on values that can legitimately be null. Narrow with type guards instead.

## 4. Security

XSS: Flag any `{@html ...}` on non-static content. User- or API-provided strings must be rendered as text.

Secrets & Tokens: No secrets in frontend code or env vars bundled by Vite (`VITE_*` is public). Auth tokens are HttpOnly cookies — flag any attempt to read/store tokens in JS, localStorage, or sessionStorage.

Open Redirects: Flag navigation to URLs derived from user input or query parameters without validation.

Sensitive Data: No passwords, tokens, or PII in `console.log` or error messages shown in the UI.

## 5. UX & Accessibility

Forms: Submit via form `onsubmit` (Enter key works), disable submit while pending, show API error `message` to the user — never a raw exception string.

Accessibility: Interactive elements are real `<button>`/`<a>` (not clickable divs), inputs have labels, and svelte-check a11y warnings are fixed, not suppressed.

## 6. Tests

New logic in `lib/` (state, managers, utilities) needs vitest coverage: happy path, error path, and boundary cases. Tests must assert meaningful outcomes, be deterministic (fake timers instead of sleeps), and not depend on a running backend.

# Output Format

## 1. Executive Summary

A short paragraph summarizing overall quality, merge readiness, and the single most critical concern.

## 2. Checklist

| Criteria            | Status       | Key Observations |
| :------------------ | :----------- | :--------------- |
| Project Standards   | ✅ / ⚠️ / ❌ |                  |
| Svelte Correctness  | ✅ / ⚠️ / ❌ |                  |
| TypeScript          | ✅ / ⚠️ / ❌ |                  |
| Security            | ✅ / ⚠️ / ❌ |                  |
| UX & Accessibility  | ✅ / ⚠️ / ❌ |                  |
| Tests               | ✅ / ⚠️ / ❌ |                  |

## 3. Detailed Findings

Prefix findings with `[blocking]` (correctness/security/standards breach), `[non-blocking]` (improvement/refactoring), or `[nitpick]` (style preference).

**`[tier] ComponentOrFunction` — Short title**

- **Context**: What the current code does.
- **Problem**: Why it's a concern.
- **Recommendation**: Concrete diff or rewrite.
