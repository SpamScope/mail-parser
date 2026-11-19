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
