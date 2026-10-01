# Report contract

Write the report in English unless the user explicitly requests another language.
Use the following structure, replacing all bracketed instructions with observed
facts. Number only confirmed in-scope findings. Do not publish the template or
a hypothetical example as an actual assessment result.

## Assessment context

- Mode: changed code / whole repository.
- Reviewed revision and dirty state; for diff mode, resolved base and target.
- Runtime: Python version, package import path, relevant dependency versions.
- RFC source/status verification date and any source-access limitations.
- Coverage: RFC sections, code areas and probes/tests actually examined; distinguish
  Checked, Partially checked, Not checked, and Not applicable with reasons.
- Verification: commands run, outcomes, and any skipped or blocked checks.

## Issue 1

**Description:** The code in `[repository-relative/file.py]`, lines `[nn-mm]`,
`[misinterprets/drops/rejects the concrete header or MIME part]`. Under
`[RFC number, section and paragraph identified by its opening words]`
`[direct official section link]`, `[brief paraphrase of applicable requirement]`.
Therefore `[precise observable discrepancy and user impact]`.

**Classification:** RFC parsing violation / Forensic recovery gap.
For recovery gaps, state the malformed syntax and the separate repository-policy
expectation; do not describe a custom recovery policy as an RFC requirement.

**Change attribution:** \[Diff mode only: responsible hunk, baseline result and
target result, or clearly labeled static attribution if base execution is blocked.\]

**Concrete example:** A complete, copy-pasteable Python snippet that imports
`mailparser`, creates the minimal synthetic raw message, invokes a public parsing
entrypoint, prints actual/expected values, and asserts the expected outcome.
Include literal header/MIME bytes or deterministic construction. Use explicit
CRLF and harmless `.example` addresses. Include all required setup; no ellipses,
undefined variables, private mail files, or network dependencies.

Provide the exact command used to execute the snippet from the repository root.
Show observed output/exception and exit status, then explain the expected semantic
result and its RFC basis. Include the nearby valid control result. If byte loss is
the issue, expose bytes/hex/hash rather than relying on visual text comparison.

**Possible resolution:** \[Specific function/algorithm change and why it meets the
requirement, preserving raw evidence, valid neighbors and existing safeguards.\]
Add the regression cases and expected assertions that should accompany a fix.
Label the suggestion as untested unless implementation was separately authorized
and verified. Do not claim the suggested code is already fixed.

Repeat `Issue 2`, `Issue 3`, and so on for distinct confirmed root causes.

## Unverified candidates and limitations

List candidates lacking execution, normative evidence or diff attribution,
including what is missing and how to resolve it. Keep them outside the issue
count. State unexamined applicable areas, environment limitations, and remaining
coverage gaps. Omit this section only when there are none.

When there are zero confirmed issues, write:
"No confirmed RFC parsing issues were found in the examined scope."
Retain the coverage and limitations. Never translate that statement into a claim
of complete RFC compliance. If execution or source verification was blocked,
explicitly state that the assessment is incomplete.
