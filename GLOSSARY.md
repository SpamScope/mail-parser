# Mail forensic evidence

Language used when describing the evidence recovered from an email.

## Language

**Original evidence**:
The message headers, MIME structure and payloads received for analysis, before
display decoding or recovery.

**Recovered value**:
A usable interpretation of damaged message content that remains distinguishable
from its original evidence.

**Container representation**:
A textual copy of the content enclosed by a multipart or attached message,
which can overlap the evidence in its child attachments.

**Partial recovery**:
A result containing the safely recovered content and explicit diagnostics for
representations that could not be produced within the analysis budget.

## Structure

**MIME part**:
One entity of the message body as delimited on the wire: either a container
enclosing other parts or a leaf carrying content.

**MIME tree**:
The nesting of the MIME parts of a message as found in the original evidence,
containers included, independent of how each part is later classified.
_Avoid_: Graph, body structure

**Hop**:
One transfer of the message between two servers, as declared by a single
trace header.

**Delivery path**:
The ordered sequence of hops a message declares, first hop first. It is the
sender's and relays' claim, not a verified route.
_Avoid_: Route, graph

**Message structure**:
The combined view of a message: its main headers, its delivery path and its
MIME tree. The delivery path and the MIME tree are separate structures with no
links between them.
_Avoid_: Graph, email graph

## Security

**Message defect**:
A violation of email standards found in the analysed message itself; it is
evidence to report, not a flaw in the library.
_Avoid_: Bug, vulnerability

**Parser vulnerability**:
A flaw in the library that lets attacker-controlled message content crash,
exhaust, mislead or escape the parser, including output that diverges from
the original evidence.
_Avoid_: Defect, security bug
