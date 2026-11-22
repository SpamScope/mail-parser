# 03: Command-line flags and README

Type: task
Status: ready-for-human
Blocked by: 01, 02

## What to build

The two flags of the [spec](../spec.md#command-line):

- `-st`, `--structure` prints the drawing, in ASCII when the output
  encoding cannot represent box-drawing characters.
- `--mime-tree` prints `mime_tree_json` as its own JSON document,
  directly after the document of `--json` when both are given. No short
  form: `-mt` already means `-m -t`.

README: the new property, the function, the two flags and one example of
the drawing. `AGENTS.md`: the new module in the table of responsibilities
and the rule that message text reaches the drawing only through the
escaping function.

## Constraints

- `--json` alone prints exactly what it prints today. mail-parser-api
  reads the first JSON document of the output.

## Acceptance

- [x] `--stdin --json --mime-tree` prints two JSON documents that decode
  one after the other; the first equals the output of `--json` alone.
- [x] `--structure` prints the drawing and exits 0.
- [x] README and `AGENTS.md` updated; `make pre-commit` passes.

## Comments

- 2026-11-22: implemented on `feature/message-structure`, not committed. The
  short form `-mt` was dropped after the security review: argparse already
  reads it as `-m -t`, and adding it changed what an existing command
  prints.
