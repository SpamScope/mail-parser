---
name: mail-rfc-assessment
description: Assess the entire mail-parser repository for reproducible parsing defects against fundamental email RFC sections, regardless of when code changed. Use for a repository-wide RFC compliance assessment. For changes-only review use mail-rfc-diff.
---

# Repository-wide RFC parsing assessment

Produce an English report of demonstrated email parsing defects across the
repository's current implementation. This is an assessment; suggest fixes
without applying them unless separately requested.

Read the repository's `AGENTS.md`, then these shared references before reviewing:

- [Workflow and evidence rules](references/workflow.md)
- [Fundamental RFC scope](references/rfc-scope.md)
- [Required report format](references/report-template.md)

## Assess the complete parsing surface

Record the branch, commit, dirty state, Python version, and imported package path.
Unless a revision was requested, assess the current working tree, including
relevant untracked source, and disclose that it is not just the committed revision.

Inventory the repository before selecting tests. Trace all public input factories
and output representations through header parsing, address recovery, dates,
MIME traversal, charset/transfer decoding, attachments, trace fields, and defects.
Include CLI and conversion adapters where they affect the resulting RFC message.
Use tests and documentation to establish the public contract; do not assume
passing existing tests proves that contract conforms to the RFCs.

Map every applicable row of the RFC scope to implementation locations and tests.
For each row, inspect the complete relevant path and exercise representative
valid, obsolete where applicable, and malformed cases. Do not stop after the
first issue or use a fixed issue quota. Group repeated symptoms of one root
cause into one issue, retaining distinct triggers in its example.

Record each applicable area as Checked, Partially checked, or Not checked, with
specific sections, paths, and test/probe evidence. Mark genuinely absent features
Not applicable and explain why. A feature promised by the public API but missing
in implementation is a candidate gap, not automatically Not applicable.

Existing defects are eligible regardless of commit history. Cite current source
line ranges. Do not label the entire repository RFC-compliant because sampled
cases pass. If any applicable area remains unexamined, state that the assessment
is incomplete and identify the remaining work. Stop at the report.
