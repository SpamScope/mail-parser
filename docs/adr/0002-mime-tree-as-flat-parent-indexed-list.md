# Expose the MIME tree as a flat, parent-indexed list outside `mail`

The MIME tree is published as a list in which entry `i` describes MIME part
`i` and names its `parent` index and `depth`, not as nested `children`. A
sender controls nesting depth (about 800 levels parse today), so a nested
shape pushes recursion onto every builder, renderer and consumer; the flat
shape is built and drawn iteratively, and its index is the `part N` already
quoted by defect messages. Consumers that want nesting rebuild it from
`parent`.

The tree is reachable only through its own property and is not added to the
`mail` dictionary or to attachment entries. Existing consumers parse that
output, some through the command line, and must keep receiving exactly what
they receive today; a part links to its attachment by position instead of the
attachment gaining a field.
