---
name: triage-review-finding
description: Verifies and triages a code review finding (from an AI review, audit doc, or human reviewer) against the actual codebase. Trigger when the user pastes a review comment/finding and asks to check, analyze, or evaluate whether it makes sense.
---

# Triage a Code Review Finding

The user pastes a finding produced by a reviewer (often another AI model of varying quality). The job is to independently verify it before any code changes — findings may be outdated, overstated, wrong about the code, correct but with a bad suggested fix or have a bad problem-solution fit.

## Process

1. **Read the actual code first.** Locate the code the finding refers to (paths in the finding may be stale after refactoring — search by symbol name if the path doesn't exist). Understand the full flow, not just the quoted lines.

2. **Verify each claim independently.** Check the factual claims against the code as it is now. The finding may already be fixed, may misread the logic, or may describe a code path that cannot be reached. For claims about library behavior or security best practices, verify against documentation or a web search when falsifiable.

3. **Judge severity honestly.** Classify as: valid and important / valid but minor / partially valid (explain which parts) / invalid or outdated. An issue that is theoretically real but unreachable or irrelevant for this app's threat model should be labeled as such.

4. **Evaluate the suggested fix separately from the finding.** A real problem can come with a wrong or over-engineered fix. Propose the simplest fix that matches project conventions (see AGENTS.md), and mention meaningful alternatives with a recommendation.

5. **Explain, then stop.** Present the assessment: what the finding claims, what the code actually does, verdict, and proposed fix. Do NOT change code until the user agrees — unless they already said "fix it if it makes sense" in the same message. Plan the changes as a set of small commits.

6. **When implementing:** After the plan is approved, the commits should be done one-by-one, with user review. Add or extend tests that would have caught the issue (for race conditions, prefer a deterministic failing test before the fix). Run the relevant checks. Do not commit the changes.

## Output Format

**Verdict**: valid / partially valid / invalid — one line.

**What the code actually does**: short walkthrough of the relevant flow with `file:line` references.

**Assessment**: claim-by-claim check for multi-part findings; call out anything the finding got wrong or missed.

**Recommendation**: the proposed fix (or "no action needed" with justification), alternatives if relevant, and impact of leaving it unfixed.
