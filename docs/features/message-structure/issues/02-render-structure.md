# 02: Draw the message structure as text

Type: task
Status: ready-for-human
Blocked by: 01

## What to build

`mailparser.render_structure(mail, ascii_only=False)` in a new module
`structure.py`, re-exported from the package. It returns the three sections
of the [spec](../spec.md#the-drawing): MESSAGE, DELIVERY PATH, MIME TREE.

## Constraints

- Every value that comes from the message goes through one function that
  makes control, ANSI, bidirectional, zero-width and line-separator
  characters visible and cuts long values. No other path to the output.
- Iterative drawing; parts deeper than 32 levels are counted, not drawn.
- A hop is marked only for a recorded defect. An unparsed trace header
  shows its raw text without a mark. Delays are printed as numbers.
- Standard library only. No colour.

## Acceptance

- [x] The drawing of a conforming multipart shows every part once, indented
  under its parent.
- [x] A file name with an ANSI escape, a carriage return and a
  right-to-left override is drawn with visible escapes; none of the three
  characters is in the output.
- [x] `ascii_only=True` returns text that encodes as ASCII, for a message
  with non-ASCII names and subject.
- [x] A message nested 400 levels deep is drawn without `RecursionError`,
  with one line stating how many parts were left out.
- [x] A hop whose trace header has a recorded defect is marked; a hop with
  a three-hour delay and no defect is not.
- [x] A message with no `Received`, no `From` and a single part draws
  without error.

## Comments

- 2026-11-22: implemented on `feature/message-structure`, not committed.
  Changed from the first wording: an unparsed trace header is shown without
  a mark, because RFC 5322 section 4.5.7 accepts obsolete trace forms. Added
  after the security review: characters that draw nothing or a blank are
  escaped too.
