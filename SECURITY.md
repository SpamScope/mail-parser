# Security Policy

mail-parser follows the coordinated vulnerability disclosure process described
in the [OpenSSF Vulnerability Disclosure Guide][openssf-guide], aligned with
ISO/IEC 29147 (vulnerability disclosure) and ISO/IEC 30111 (vulnerability
handling).

## Supported Versions

Security fixes are released only as a new version on top of the latest
release; older releases do not receive backports. Upgrade to the latest
release to receive them.

| Version            | Supported          |
| ------------------ | ------------------ |
| Latest release     | :white_check_mark: |
| Older 4.x releases | :x:                |
| \< 4.0             | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue, pull request or discussion for a
suspected vulnerability.**

Report it privately through one of these channels:

- **GitHub Private Vulnerability Reporting** (preferred for sensitive
  material): [open a draft advisory][report].
- **Email**: [info@spamscope.ai](mailto:info@spamscope.ai).

Please include as much of the following as you can:

- the affected version(s) and Python version;
- the affected API, module or CLI option;
- a minimal message (`.eml`/`.msg`) or code snippet that reproduces the issue;
- the observed impact (crash, resource exhaustion, wrong or missing output,
  file written outside the target directory, ...);
- any suggested fix or mitigation.

## Scope

mail-parser parses untrusted email. Every byte of a message — headers,
addresses, MIME structure, attachment names and payloads — is treated as
attacker-controlled. The calling application, its filesystem and `PATH` are
trusted.

In scope, when triggered by message content:

- crashes or exceptions that escape the documented exception hierarchy;
- denial of service, including ReDoS, super-linear parsing time and
  unbounded memory or output amplification;
- path traversal or unsafe file writes during attachment extraction;
- spoofed attribution, such as a sender-chosen IP address returned by
  `get_server_ipaddress()`;
- parser-differential evasion: output that silently diverges from the bytes
  actually in the message (dropped attachments, lost headers, hidden
  payloads), so that downstream security tools see something different from
  what the recipient sees.

Out of scope:

- attacks that require an already compromised caller, filesystem or `PATH`;
- vulnerabilities in third-party tools and libraries, such as `extract-msg`
  or `msgconvert` — report them to their maintainers;
- message defects without security impact: a message that violates email
  standards is evidence that mail-parser reports through `has_defects`, not a
  vulnerability. Report parsing or RFC-compliance bugs as regular
  [issues].

## Response Timeline

| Step                        | Target                                  |
| --------------------------- | --------------------------------------- |
| Acknowledgement of report   | within 5 business days                  |
| Triage and initial severity | within 14 days                          |
| Status updates to reporter  | at least every 14 days                  |
| Fix and public disclosure   | within 90 days, extendable by agreement |

mail-parser is maintained by a single maintainer; these are targets, not
contractual guarantees.

## What Happens Next

- **Accepted**: the vulnerability is fixed in a new release. A GitHub
  Security Advisory (GHSA) is published with a CVE identifier requested
  through GitHub, a severity rating, the affected and patched versions, and
  credit to the reporter unless they ask to remain anonymous. The release
  notes of the fixed version reference the GHSA and CVE identifiers.
- **Declined**: you receive an explanation of why the report is not
  considered a vulnerability, for example because it is out of scope. If it is
  still a bug, you may be asked to file it as a public issue.

The advisory is published together with the fixed release, or at the 90-day
deadline, whichever comes first. Please keep the details confidential until
then.

Published advisories are listed at
[github.com/SpamScope/mail-parser/security/advisories][advisories].

## Bug Bounty

mail-parser does not offer a bug bounty or monetary rewards.

## Safe Harbor

We will not pursue or support legal action against anyone who, in good
faith:

- follows this policy;
- tests only against their own installations and their own data;
- avoids privacy violations, data destruction and service disruption;
- gives us reasonable time to fix the issue before disclosing it.

[advisories]: https://github.com/SpamScope/mail-parser/security/advisories
[issues]: https://github.com/SpamScope/mail-parser/issues
[openssf-guide]: https://github.com/ossf/oss-vulnerability-guide
[report]: https://github.com/SpamScope/mail-parser/security/advisories/new
