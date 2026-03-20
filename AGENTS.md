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

## Release Policy

- Commit whenever a change is logically complete and would make sense to
  keep or revert on its own.
- Push often, especially after changes have been synced into Roblox
  Studio, so the repository stays close to the live experience state.
- Do not create a new tag for every Roblox update or small commit.
- Use tags only for meaningful milestones such as:
  - a public release
  - a notable feature addition
  - a visible batch of polish or fixes
  - a version that would be useful for others to download or reference
- Treat Roblox publishing as a rolling live build and Git tags as named
  milestones.

## Tool Selection

- Prefer repository files plus Rojo for all source edits.
- Treat Roblox Studio as a preview, sync, and test target rather than the
  canonical source tree.
- Use shell tools for code search, Git work, file inspection, and release
  prep.
- Use Roblox MCP tools for Studio-only tasks such as:
  - checking whether the bridge is alive
  - reading place info and project structure
  - inspecting object trees, properties, selections, and playtest output
  - capturing screenshots or verifying runtime behavior
- Do not use Roblox MCP script-editing tools as the default way to change
  code when the same change can be made in `src/` and synced through Rojo.
- Only use Roblox MCP edits for emergency Studio-side fixes or inspection
  tasks that cannot be handled cleanly through the repository.
- If a Studio-side hotfix is ever applied through MCP, mirror the same
  change back into the repository immediately so Rojo remains the source of
  truth.
- Before starting substantial work in a new conversation, confirm which of
  these is needed:
  - repository edit
  - Rojo sync or setup help
  - Roblox MCP inspection or playtest help
  - release, Git, or documentation work

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
