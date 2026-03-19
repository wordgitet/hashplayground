# Hash Playground Agent Notes

## Overview

Hash Playground is a Rojo-managed Roblox project for experimenting with
hashes, checksums, and key derivation.

The repository source tree is the source of truth. Roblox Studio should be
used for sync, testing, and previewing, not as the primary place to edit
source.

## Workflow

- Use the filesystem project in this repository as the main edit target.
- Use Rojo to sync local source into Roblox Studio.
- Keep repo-facing docs portable.
- Do not hardcode personal absolute paths into published files.

Typical local development flow:

```text
rojo serve
```

Then connect to the Rojo plugin in Roblox Studio and sync the project.

## Project Layout

- `src/client/HashGUI.client.lua`
  Main user interface and interaction logic.

- `src/shared/*.lua`
  Hash, checksum, HMAC, and PBKDF2 modules.

- `default.project.json`
  Rojo mapping for Studio sync.

## Documentation Style

- Keep the top-level `README` as plain text.
- Prefer concise, practical repository docs.
- Use portable command examples such as `rojo serve`.
- Avoid machine-specific paths like `/home/...` in committed docs.

## Licensing Notes

- The top-level repository license is MPL-2.0 unless otherwise noted.
- Some algorithm modules are adapted from upstream reference
  implementations and may carry different SPDX identifiers.
- Check `THIRD_PARTY_NOTICES` before changing license headers.
- Do not replace per-file SPDX identifiers casually.

## Commit Style

Use Linux-kernel-style commit messages, but distinguish between normal
commits and merge commits.

### Normal commits

Format:

```text
subsystem: imperative summary

Explain what changed and why.

Add more detail in wrapped paragraphs when needed.

Areas:
  subsystem: short note for another touched area
  subsystem: short note for another touched area

Signed-off-by: wordgitet <wordatet@linuxmail.org>
```

Rules:

- Use a subsystem-prefixed subject.
- Use imperative mood.
- Do not end the subject with a period.
- Keep the subject short.
- Leave one blank line after the subject.
- Wrap body text to about 72 columns.
- The body should explain both what changed and why.
- If the commit touches multiple meaningful areas, end the body with an
  `Areas:` section.
- Keep `Signed-off-by:` as the last trailer.
- Optional trailers such as `Test:` or `Upstream:` may appear above the
  sign-off when useful.

Example:

```text
tests: import yash POSIX suite

Import the POSIX-facing yash tests under test-posix/yash and add a local
runner that requires yash from PATH.

Exclude *-y.tst files because they cover yash-specific behavior rather than
generic POSIX shell semantics.

Areas:
  tests: vendor yash POSIX test files into test-posix/yash
  harness: run the imported test scripts with yash from PATH
  docs: document the local runner behavior

Signed-off-by: wordgitet <wordatet@linuxmail.org>
```

### Merge commits

Use the kernel-style merge summary format for merge commits.

Format:

```text
Merge branch 'topic-name'

Merge topic-name updates:

 - summary bullet
 - summary bullet
 - summary bullet

* branch 'topic-name':
  subsystem: first commit subject
  subsystem: second commit subject
  subsystem: third commit subject
```

For pulled tags or remote branches, use:

```text
Merge tag 'tag-name' of <repo-url>

Pull <topic> updates:

 - summary bullet
 - summary bullet

* tag 'tag-name' of <repo-url>:
  subsystem: first commit subject
  subsystem: second commit subject
```

Rules:

- Do not add `Signed-off-by:` to merge commits unless explicitly required.
- Summarize the merged branch or tag in short bullets.
- List the merged commit subjects at the end.
- Keep the tone close to the Linux kernel examples.

### Preference

If a commit is not a merge commit, use the normal commit format above.
