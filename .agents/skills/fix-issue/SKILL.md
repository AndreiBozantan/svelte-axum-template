---
name: fix-issue
description: Fixes a bug, implements a missing feature, or implements one slice of a larger feature, starting from a GitHub issue link, number, or direct text description. Trigger when the user gives a GitHub issue URL/reference/description and asks to fix, implement, resolve, or work on it.
---

# Fix a GitHub Issue

Given a link, `#number`, or direct text description of a GitHub issue, resolve it end-to-end: understand the ask, verify it still applies, plan the change, implement it in small reviewable steps, and leave it ready for the user to test and commit.

## Process

1. **Fetch or accept the issue.** If the user provided the issue details or description directly, use that information. Otherwise, fetch the issue using `gh issue view <ref> --json number,title,body,labels,comments,state` — where `<ref>` accepts a full URL or a bare number when run inside this repo. Read title, body, and comments; comments often carry scope clarifications made after filing. If `gh` isn't authenticated, ask the user to paste the issue text instead of guessing its contents.

2. **Pull in linked context.** Per `code-review-findings/stabilization-plan.md`'s issue-authoring convention, issue bodies here are usually copied verbatim from a `code-review-findings/NN-*.md` finding and may point at a `docs/design/*.md` doc for the concrete spec — e.g. Stage B issues link `docs/design/authorization.md`'s `# Implementation Plan` section for schema/DDL/queries. Follow every link and file reference in the body before writing code. If the issue is one of the plan's numbered checkboxes, that entry is also useful context (dependencies, ordering, "Definition of done").

3. **Re-verify against current code — don't trust the issue text blindly.** Same discipline as triaging a review finding: read the actual current code first (`AGENTS.md`'s "verify the claim against the actual code first" rule). An issue can be stale — already fixed, the code moved, or the described mechanism no longer exists. If it no longer applies, say so and stop instead of manufacturing a change. If the issue's own "Recommendation" predates a later architectural decision (e.g. it assumes pre-Stage-B tenancy/auth), flag the conflict and propose the up-to-date approach instead of following it verbatim.

4. **Check dependencies.** If the issue names prerequisite issues or touches code that another in-flight change is mid-rewriting, confirm those have actually landed before proceeding. If not, flag it and ask before continuing.

5. **Scope the fix using this repo's structure.** Backend: pick the right layer (`_api.rs` / `_db.rs` / `_service.rs`, optionally `_tests.rs` / `_utils.rs`), use `backend/platform/identity/users/` as the template for a new subfeature, `validator::Validate` for inputs, structured lowercase/underscore log keys, method chaining, `use module;` + qualified types. Frontend: only call the API through the generated client (`$lib/generated/endpoints.ts`), never raw `fetch`. Tests go in `backend/test/`.

6. **Plan and pause.** For anything beyond a one-file, obvious fix: write the plan as small, individually reviewable steps (per `AGENTS.md`), and stop for approval before touching code. Ask clarifying questions instead of guessing when the issue is ambiguous. Use plan mode for multi-file or multi-step work.

7. **Implement one step at a time.** After approval, apply a single step, then run what's relevant to what changed before moving to the next:
   - `cargo clippy --workspace --all-targets` and `cargo test` for backend changes
   - `cargo xtask openapi` whenever an endpoint or DTO changed, and confirm the regenerated frontend client still compiles
   - frontend checks/tests (`svelte-check`, `vitest`) for frontend changes
   Stop after each step for review rather than delivering the whole issue as one big diff.

8. **Definition of done.** Before calling it finished, confirm (this applies to any issue, not just plan-sourced ones): new code has automated tests, `cargo clippy --workspace --all-targets` is clean, `cargo test` is green, frontend checks/tests are green if frontend files were touched, `cargo xtask openapi` was re-run if the API surface changed, and the change follows `docs/api/conventions.md` and `AGENTS.md`.

9. **Stop short of git.** Never run `git commit` or `git push` — summarize what changed and let the user test and commit. Do not edit `code-review-findings/stabilization-plan.md` (e.g. checking off the box) unless the user asks.

## Notes

- Accepted issue references: full URL (`https://github.com/OWNER/REPO/issues/N`), `#N`, bare `N` resolved against the current repo, or a direct description/text of the issue.
- "Fix" can mean a bug fix, a whole feature, or one slice of a larger staged feature (e.g. a single Stage B checklist item) — infer scope from the issue body and its acceptance criteria, not from the word "fix".
