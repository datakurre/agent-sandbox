---
name: commit
description: Use when creating or amending Git commits; require an Assisted-by trailer naming the active tool and model.
---

# Commit messages

Before writing the subject line, inspect recent commits in the current repository with `git log -10 --oneline`. Match their first-line style, including any scope or prefix, and keep the subject concise.

Trailer `Co-Authored-By:` is against our policy and must not be included.

Instead, every commit you create or amend must include only this trailer as the final non-empty line of its commit message:

```text
Assisted-by: <tool> (<model>)
```

Replace both placeholders with the active tool and model identifiers. Keep a blank line between the commit message and the trailer. Before committing, inspect the full message to confirm the trailer is present and correctly formatted.
