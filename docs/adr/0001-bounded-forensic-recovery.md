# Bound container representations while preserving original evidence

Nested attached containers can require repeated copies of the same MIME
subtrees. Keep existing representations while they fit a per-message work
budget; omit expensive container representations with explicit diagnostics,
continue recovering children, and retain the original MIME tree. Do not return
empty or truncated attachment payloads. This preserves more evidence than
rejecting the entire message and avoids changing ordinary attachment semantics.

When an encoded-word cannot be decoded strictly, retain the complete literal
header value and diagnose the failure, including its occurrence and MIME part.
Do not discard undecodable bytes or combine a decoded prefix with the original
header. A recovered result does not imply RFC compliance or malicious intent.
