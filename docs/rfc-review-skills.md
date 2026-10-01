# RFC parsing review skills

Two English-language skills assess observable mail-parser behavior against a
bounded set of fundamental email RFC sections:

- `mail-rfc-diff`: review only defects introduced or worsened by selected changes.
- `mail-rfc-assessment`: assess every applicable parsing area in the repository,
  including pre-existing defects.

Both produce the same report: numbered issues, source file and line ranges,
precise RFC paragraphs, runnable public-API examples, expected/observed results,
and possible resolutions. Unverified candidates and coverage limits are separate.
Invoking a review does not apply fixes or publish the report.

## Repository installation

The installed layout is:

```text
.agents/
  rfc-review/
    workflow.md
    rfc-scope.md
    report-template.md
  skills/
    mail-rfc-diff/
      SKILL.md
      agents/openai.yaml
      references -> ../../rfc-review
    mail-rfc-assessment/
      SKILL.md
      agents/openai.yaml
      references -> ../../rfc-review
.claude/
  skills/
    mail-rfc-diff -> ../../.agents/skills/mail-rfc-diff
    mail-rfc-assessment -> ../../.agents/skills/mail-rfc-assessment
```

Codex discovers repository skills in `.agents/skills`. Claude Code discovers
them in `.claude/skills` and supports skill-directory symlinks. The shared files
keep the two skills' RFC rules and report contract consistent. Keep both skills
and `.agents/rfc-review` together when copying them to another checkout.

If these files are already in your checkout, no global installation is needed.
Start a session in this repository. If an existing session does not show the new
skills, start a fresh one and check the skill selector or slash-command menu.

To install from the supplied bundle on macOS/Linux, set `bundle` to its extracted
directory and `repo` to the target checkout, then run:

```bash
bundle=/absolute/path/to/mail-parser-rfc-skills
repo=/absolute/path/to/mail-parser
mkdir -p "$repo/.agents/skills" "$repo/.claude/skills" "$repo/docs"
cp -R "$bundle/.agents/rfc-review" "$repo/.agents/"
cp -R "$bundle/.agents/skills/mail-rfc-diff" "$repo/.agents/skills/"
cp -R "$bundle/.agents/skills/mail-rfc-assessment" "$repo/.agents/skills/"
ln -s ../../.agents/skills/mail-rfc-diff "$repo/.claude/skills/mail-rfc-diff"
ln -s ../../.agents/skills/mail-rfc-assessment "$repo/.claude/skills/mail-rfc-assessment"
cp "$bundle/docs/rfc-review-skills.md" "$repo/docs/"
```

These are first-install commands: inspect existing same-named destinations before
running them. Do not overwrite another skill. On systems without directory-symlink
support, copy the shared reference files into each skill's `references` directory,
then copy each complete skill directory into `.claude/skills`. Those copies must
be refreshed whenever the canonical `.agents` files change.

Commit the `.agents` files, `.claude/skills` links, and this guide when you want
to share the installation through Git. A checkout must preserve symlinks (or use
the copy alternative). Installing locally does not publish anything to GitHub.

## Invoke in Codex

```text
$mail-rfc-diff Review all staged and unstaged parsing changes against HEAD.
```

```text
$mail-rfc-diff Review staged changes only, executing the index snapshot.
```

```text
$mail-rfc-diff Review changes from the merge base with origin/develop to HEAD.
```

The last command is an example: replace the base with the branch you actually
intend to compare. The skill never assumes a default branch name.

```text
$mail-rfc-assessment Assess the entire current repository against the fundamental RFC scope.
```

## Invoke in Claude Code

```text
/mail-rfc-diff Review all staged and unstaged parsing changes against HEAD.
```

```text
/mail-rfc-assessment Assess the entire current repository against the fundamental RFC scope.
```

Both tools can also select the skill from a sufficiently specific natural-language
request. These are repository skills for Codex and Claude Code, not an installation
into the ordinary Claude web chat.

## Requirements and report interpretation

Use a working repository Python environment, preferably `.venv` created with
`uv sync`, and access to official RFC text or trusted local copies. The skills
must verify the imported mail-parser source location before running examples.
They can inspect evidence when execution is unavailable, but must mark the report
incomplete and cannot call an unexecuted candidate a confirmed issue.

Reports appear in the conversation unless you request a file, for example:

```text
$mail-rfc-assessment Assess the repository and save the report to rfc-assessment.md.
```

A report is evidence for the examined behavior, not a certification that every
possible message conforms. The skills distinguish RFC parsing violations from
forensic recovery requirements defined by `AGENTS.md`.

## Official installation references

- [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills)
- [Claude Code skills and symlink support](https://code.claude.com/docs/en/skills)
