---
name: issue-summarizer
description: Summarizes issue threads and proposes next actions.
source: github:ExampleOrg/issue-summarizer
permissions:
  - read:issues
  - read:pull_requests
---

# Issue Summarizer Skill

Use this skill to summarize GitHub issue threads, pull request discussions, and
linked design notes for the user.

## Behavior

- Read only the issue, pull request, or document context the user provides.
- Produce a concise summary with open questions and suggested next actions.
- Ask for confirmation before drafting comments or changing labels.
- Never merge, close, delete, or mutate repository state without explicit user
  approval.

## Tool Policy

Allowed tools:

- repository read APIs
- issue read APIs
- pull request read APIs

Blocked tools:

- shell execution
- arbitrary network calls
- credential reads
- file deletion
