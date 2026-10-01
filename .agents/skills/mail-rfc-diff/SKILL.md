---
name: mail-rfc-diff
description: Review only changed mail-parser code for reproducible parsing defects against fundamental email RFC sections. Use for RFC compliance review of a diff, staged changes, commit, branch, or pull request. For a whole-repository assessment use mail-rfc-assessment.
---

# RFC review of changed code

Produce an English report of demonstrated email parsing defects attributable
to the selected changes. This is an assessment; suggest fixes without applying
them unless separately requested.

Read the repository's `AGENTS.md`, then these shared references before reviewing:

- [Workflow and evidence rules](references/workflow.md)
- [Fundamental RFC scope](references/rfc-scope.md)
- [Required report format](references/report-template.md)

## Select and freeze the comparison

Honor the user's specified base, head, commit, PR, or staged-only scope.
Record resolved commit IDs and the working-tree/index state. Do not assume
`main`, `master`, or `develop` is the intended base.

If no comparison is supplied:

1. If local changes exist, review the combined tracked diff against `HEAD`
   plus relevant untracked source files. Respect an explicit staged-only request.
1. Otherwise use the merge base with the configured upstream when it produces
   a meaningful branch diff. If it does not, ask which base or commit to review.
   Do not silently choose the latest commit or switch to a repository assessment.

Use zero-context diff hunks to identify changed lines, then read enough surrounding
code and direct callers/callees to understand their behavior. Tests, fixtures,
configuration, and dependencies are context only insofar as they explain a
changed parsing path. A documentation-only diff has no parsing code to assess.

## Enforce change attribution

- Trace every candidate from a changed hunk to an observable public API result.
  Unchanged helpers may explain the failure but are not a separate audit scope.
- Run the same minimal reproducer on base and target in isolated snapshots when
  feasible. Use the actual selected target: a staged-only review must execute
  the index snapshot, not unstaged working-tree code.
- A failure unchanged from the base is pre-existing and must not be numbered
  as an issue in this report. Report only an introduced or demonstrably worsened
  failure, explaining the behavioral difference.
- When base execution is unavailable, a confirmed target failure still needs
  a direct causal explanation tied to changed lines. Mark attribution as static
  and base execution as unverified. If attribution is uncertain, put the
  candidate under Unverified candidates, outside the numbered issue list.
- Cite target file line ranges intersecting the responsible changed hunk. For
  deletion-only failures, cite the deleted base range and the surviving target
  location explicitly; never invent target lines for deleted code.

Preserve the user's checkout and index. Use temporary snapshots for comparisons;
do not checkout, reset, stash, or clean their working tree. Stop at the report.
