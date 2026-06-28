---
description: Review recently generated code and save lessons learned to CLAUDE.md
allowed-tools: Read, Write, Bash(git diff HEAD), Bash(git diff --cached), Bash(git status)
argument-hint: [optional: specific file or topic to review]
---

# Code Review & Memory Update

You are in **review mode**. Your job is to:
1. Show the user the recently generated/changed code
2. Ask for their verdict
3. Write any lessons into CLAUDE.md so you never make the same mistake again

---

## Step 1 — Gather Context

Run the following to see what changed:

!`git diff HEAD`
!`git status`

If `$ARGUMENTS` is provided, focus specifically on that file or topic: `$ARGUMENTS`

---

## Step 2 — Present the Code for Review

Show the user a clear summary of what was generated/changed. For each changed file:
- Show the filename
- Briefly describe what the code does (2-3 sentences)
- Highlight any decisions you made that could be debated (e.g. architecture choices, naming, patterns used)

Then ask the user exactly this:

---
**Is this code OK?**

Reply with one of:
- ✅ `ok` — looks good, nothing to learn
- ❌ `reject: [your reason]` — what's wrong and what should be done instead
- ⚠️ `partial: [what's ok] | [what's wrong]` — mixed feedback
---

## Step 3 — Wait for User Feedback

Do NOT proceed to Step 4 until the user has replied with their verdict.

---

## Step 4 — Update CLAUDE.md Based on Feedback

Read the current CLAUDE.md file first to understand existing rules and avoid duplicates.

### If user said `ok`:
Append a positive confirmation to CLAUDE.md under `## ✅ Confirmed Patterns`:
```
- [short description of pattern] — confirmed working as of [today's date]
```

### If user said `reject: [reason]` or `partial`:
Extract the core lesson from their feedback and append it to CLAUDE.md under the correct section:

- Architecture mistakes → `## Architecture Rules`
- Code style / naming → `## Code Style Rules`
- Business logic / domain → `## Business Logic Rules`
- Security / performance → `## Security & Performance Rules`
- Anything else → `## Lessons Learned`

Write the rule in this exact format:
```
- ❌ DO NOT: [what was done wrong]
  ✅ DO: [what should be done instead]
  📅 Added: [today's date]
  💬 Reason: [user's reason, summarized in 1 sentence]
```

### If the CLAUDE.md file does not exist yet:
Create it with this base structure before appending:

```markdown
# Project AI Rules & Memory

This file is automatically maintained by the /review command.
Claude Code reads this file on every session — rules here are always active.

---

## Architecture Rules

## Code Style Rules

## Business Logic Rules

## Security & Performance Rules

## ✅ Confirmed Patterns

## Lessons Learned
```

---

## Step 5 — Confirm to the User

After writing to CLAUDE.md, tell the user:
- Exactly which section was updated
- The exact rule that was written (show it)
- That this rule is now active for all future sessions in this project

Then check the CLAUDE.md file to ensure it has all required sections. If any are missing, add them. The file should always contain these sections:

```markdown
# Project AI Rules & Memory

This file is automatically maintained by the `/review` command.
Claude Code reads this file at the start of **every session** — all rules here are always active.
Do not delete sections; the /review command appends to them automatically.

---

## Architecture Rules

## Code Style Rules

## Business Logic Rules

## Security & Performance Rules

## ✅ Confirmed Patterns

## Lessons Learned
```
