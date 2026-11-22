# 01: Publish the MIME tree

Type: task
Status: ready-for-human
Blocked by: None

## What to build

`MailParser.mime_tree` and `MailParser.mime_tree_json`, as the
[spec](../spec.md#the-mime-tree) defines them: one entry per MIME part, in
wire order, with `parent` and `depth` instead of nested children.

`parse()` records the roles, the attachment position and the defects as
it classifies each part, so they are the ones the parser really assigned,
not a second guess made afterwards. The entries are built from those
records the first time the tree is read.

## Constraints

- `mail`, `mail_json`, `mail_partial` and `attachments` do not change.
- No recursion over the parts: nesting depth is chosen by the sender.
- `mime_tree` is a computed name. A wire header called `Mime-Tree` must
  not replace it and must stay readable through `headers`.
- Declared values only; see rule 6 of the spec.

## Acceptance

- [x] Entry `i` has `index` `i`, and `parent` is a smaller index or null,
  for every mail in `tests/mails`.
- [x] `mail_json` is unchanged for every mail in `tests/mails`.
- [x] Tests for: conforming multipart, embedded message, `multipart/digest`
  default type, a part with no headers, named inline text (two roles), an
  attached container, an omitted container representation, an epilogue
  recovery, a `Mime-Tree` header, and several hundred levels of nesting.
- [x] Every defect category on an entry is also in `defects_categories`.

## Comments

- 2026-11-22: implemented on `feature/message-structure`, not committed.
  `mail_json`, `mail_partial_json` and `attachments` are identical to
  `develop` on `tests/mails`. Added after the security review: the boundary
  is escaped when an RFC 2231 charset decodes it to a lone surrogate (it
  broke `mime_tree_json`), the tree is built on first read from one small
  record per part, and reading it no longer adds defects to the message.
