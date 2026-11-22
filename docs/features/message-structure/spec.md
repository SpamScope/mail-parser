# Message structure

Branch: `feature/message-structure`. Agreed with the owner on 2026-11-22.
Terms are defined in the [glossary](../../../GLOSSARY.md#structure); the
shape of the tree is recorded in
[ADR 0002](../../adr/0002-mime-tree-as-flat-parent-indexed-list.md).

## Goal and boundaries

An analyst can see an email as a picture: its main headers, its delivery
path and its MIME tree. The library publishes the one piece of data that was
missing, the MIME tree, and draws the whole message structure as text for
the command line. Other tools draw their own picture from the same data.

- The only new data is the MIME tree. Headers and the delivery path are
  already published (`headers`, `received`); they are not copied into a
  second aggregate.
- Nothing existing changes. `mail`, `mail_json`, `mail_partial`,
  `attachments` and the output of every existing command-line flag stay
  exactly as they are.
- No payload, no hash and no content sniffing in the tree.
- No Mermaid output. Consumers read the tree as JSON; a second text format
  is added when a real use appears.
- No heuristics. A marker in the drawing means a defect the parser already
  recorded, never a judgement such as "this delay is suspicious".

## The MIME tree

`MailParser.mime_tree` is a list. Entry `i` describes MIME part `i`, the
same number defect messages quote as `part N`. `MailParser.mime_tree_json`
is the same list as indented JSON. A message that was not parsed has an
empty list. `parse()` keeps one small record per part and the entries are
built from them the first time the tree is read, so a caller that never
reads it pays almost nothing for it.

Parts appear in the order of the wire, parents before children. Every
entry has all of these keys:

| Key                         | Type          | Meaning                                                                                                                                                                         |
| --------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `index`                     | int           | Position in the list.                                                                                                                                                           |
| `parent`                    | int or null   | `index` of the enclosing part; null for the root.                                                                                                                               |
| `depth`                     | int           | 0 for the root, parent's depth plus one otherwise.                                                                                                                              |
| `content_type`              | string        | The type the parser acted on, lowercase. When the header is absent or unusable this is the default of RFC 2045 section 5.2 or RFC 2046 section 5.1.5, so read it with the next. |
| `content_type_raw`          | string / null | The literal value of the first `Content-Type` header; null when the part has none.                                                                                              |
| `content_transfer_encoding` | string / null | The declared encoding, trimmed and lowercase; null when absent. The default of RFC 2045 section 6.1 is not filled in.                                                           |
| `charset`                   | string / null | The declared `charset` parameter, lowercase.                                                                                                                                    |
| `content_disposition`       | string / null | The declared disposition type, lowercase (`inline`, `attachment` or an extension token).                                                                                        |
| `filename`                  | string / null | The declared file name, decoded. Never a name the parser invented for an attachment.                                                                                            |
| `content_id`                | string / null | The declared `Content-ID`.                                                                                                                                                      |
| `boundary`                  | string / null | The declared `boundary` parameter of a multipart.                                                                                                                               |
| `size`                      | int / null    | Octets of the leaf's content after transfer decoding; null for a container.                                                                                                     |
| `roles`                     | list          | How the parser classified the part: any of `container`, `body`, `attachment`.                                                                                                   |
| `attachment`                | int / null    | Position of the matching entry in `attachments`.                                                                                                                                |
| `defects`                   | list          | Sorted names of the defect categories recorded against this part.                                                                                                               |
| `recovered`                 | bool          | True for a part the parser recovered from an epilogue rather than found in the structure.                                                                                       |
| `embedded_headers`          | object / null | On the root part of a message enclosed in a `message/*` part: the literal `from`, `subject` and `date` of that message, each a string or null.                                  |

Rules:

1. The tree is the wire structure, containers included, annotated with the
   parser's interpretation. It is not the interpretation alone: a
   `text/html` leaf inside an attached container, or a named part declared
   `inline`, must stay visible as what it is.
1. `roles` holds zero or more values. Named inline text is both `body` and
   `attachment`; an attached multipart is both `container` and
   `attachment`. An empty list is a leaf the parser exposed neither as body
   text nor as an attachment.
1. `body` means the part's text reached `text_plain`, `text_html` or
   `text_not_managed`.
1. `attachment` is null on a part without the `attachment` role, and on an
   attached container whose representation was omitted for the resource
   limit of [ADR 0001](../../adr/0001-bounded-forensic-recovery.md); that
   part carries `ResourceLimitDefect`.
1. A recovered part is the last entry, with `parent` 0, `depth` 1 and
   `recovered` true. Its own sub-parts are not described.
1. Values are declared values. The tree never substitutes a default for an
   absent header, except in `content_type`, which is paired with
   `content_type_raw` for that reason.
1. `mime_tree` is a computed name: `parser.mime_tree` always returns the
   tree. A wire header of that name stays readable through `headers`.
1. Every string in the tree encodes as UTF-8. A boundary that an RFC 2231
   charset decodes to a lone surrogate is shown with a `\udXXX` escape and
   the part carries `MimeHeaderDefect`.
1. Reading the tree does not change the message: the defects that
   measuring a part would add to it are discarded.
1. When the transfer encoding cannot be undone, `size` is the size of what
   the email package returns in its place.

## The drawing

`mailparser.render_structure(mail, ascii_only=False)` returns the message
structure as text, in three sections.

- **MESSAGE**: From, Reply-To, Return-Path, To, Cc, Subject, Date,
  Message-ID and the defect categories. An absent header is omitted. A
  header that occurs more than once is not reduced to its first value:
  every occurrence of a plain header is listed, and an address header
  says how many more occurrences it has. An address header from which no
  mailbox was selected shows its literal value and says so.
- **DELIVERY PATH**: one line per hop, first hop first, with its UTC
  time, the sending and receiving names and the protocol, and between
  hops the delay from the previous one. A hop is marked only when the
  parser recorded a defect for that trace header. A trace header the
  parser could not split into clauses is shown as its raw text and is
  not marked for that alone: RFC 5322 section 4.5.7 accepts obsolete
  trace forms.
- **MIME TREE**: an indented tree, one line per part with its index, type,
  encoding, charset, size, roles, disposition and file name. Under the
  line: the recorded defects, a note when the part declares no
  `Content-Type` or declares a different one from the type acted on, the
  headers of an embedded message, and a recovered-part marker.

Drawing rules:

1. Text from the message is never printed raw. Control characters, ANSI
   escapes, bidirectional and zero-width formatting characters and line
   separators are replaced by a visible escape (`\x1b`, `\u202e`), and
   long values are cut with a mark. The evidence stays readable; it cannot
   move the cursor, hide a line or reorder text. A backslash is doubled so
   that an escape is never ambiguous. Header folding (RFC 5322 section
   2.2.3) is undone first and a tab is shown as a space; a line break that
   folds nothing is escaped.
1. Only a prefix of each value, sized by the column limit, is examined:
   the cost of a value does not grow with its length.
1. Parts deeper than 32 levels are not drawn. One line says how many were
   left out and the maximum depth reached. `mime_tree` still holds them
   all.
1. Box-drawing characters by default; `ascii_only=True` uses ASCII
   connectors and escapes every non-ASCII character. No colour.
1. Building and drawing are iterative. Nesting depth is chosen by the
   sender and must not be able to exhaust the stack.
1. Characters that draw nothing or a blank (fillers, variation selectors,
   private-use and unassigned code points) are escaped too. Marks that draw
   something are kept, so scripts that need them stay readable. Letters of
   different scripts that only look alike are not detected.

## Cost

Measured on a 2.7 MiB message of 400,000 empty parts (Python 3.13,
macOS): parsing takes 2.9 s and 281 MiB at its peak, against 2.7 s and
243 MiB before this feature; reading the tree then takes 1.7 s more and
produces 159 MiB of JSON, with a peak of 626 MiB. On the mails of
`tests/mails` the parsing time is unchanged. The tree is linear in the
number of parts, about 400 bytes of JSON per entry. The library does not
cap it: a consumer that stores or forwards the tree of untrusted mail
bounds the input or the number of entries.

## Command line

- `-st`, `--structure` prints the drawing. It falls back to
  `ascii_only` when the output encoding cannot represent box-drawing
  characters.
- `--mime-tree` prints `mime_tree_json`, as a JSON document of its own,
  directly after the document of `--json` when both are given. It has no
  short form: `-mt` already means `-m -t` and keeps that meaning.

`--json` alone prints what it prints today.

## Standards

- RFC 2045 sections 5.1, 5.2, 6.1 and 6.4: type names are not case
  sensitive; an absent or invalid `Content-Type` means `text/plain`; an
  absent encoding means `7bit`; composite types may only be `7bit`, `8bit`
  or `binary`.
- RFC 2046 sections 5.1, 5.1.1, 5.1.5 and 5.2.1: no header is required in
  a body part; preamble and epilogue are ignored by a conforming reader;
  the default type inside `multipart/digest` is `message/rfc822`.
- RFC 2183 sections 2, 2.8 and 2.9: disposition types are not case
  sensitive; the disposition of a multipart applies to the whole.
- RFC 5322 sections 3.6 and 3.6.7, with verified erratum 3979, and
  RFC 6854: occurrence limits of the headers shown, and the trace block.

The tree reports what a message declares, including what these sections
forbid for new messages. It does not correct, reject or label it.

## Consumers

Each has its own specification in its own repository, written from this
one. If they differ, this one is right.

- **mail-parser-api** runs `--stdin --json --mime-tree` and returns the
  tree as a new key beside `message`.
- **cloud-server** (the live parser page of spamscope.ai) draws the
  structure in HTML from the tree and `message.received`.
- **mailxray-backend** and **mailxray-frontend** carry and draw the tree
  in an analysis.

## Acceptance

1. `mail_json` of every mail in `tests/mails` is unchanged.
1. For every mail in `tests/mails`: entry `i` has `index` `i`; every
   `parent` is a smaller index or null; every `attachment` points at an
   existing entry of `attachments`.
1. Tests cover a conforming multipart, an embedded message, a
   `multipart/digest`, a part with no headers, named inline text, an
   attached container, an epilogue recovery, a header named `Mime-Tree`
   and a message nested hundreds of levels deep.
1. The drawing of a file name carrying an ANSI escape and a right-to-left
   override contains neither character.
1. `make check` and `make pre-commit` pass; the security review of
   `AGENTS.md` reports no High or Medium finding.
