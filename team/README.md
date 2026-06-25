# Shiki Team — Centralized Agent Architecture

> One team. Cross-project growth. Per-project adaptation.

## 3-Layer Memory Model

```
Layer 1: AGENT IDENTITY (Shiki-level, cross-project)
  shiki/team/<agent>.md
  → Who the agent is, what they've learned across ALL projects
  → Grows over time as patterns emerge from real work
  → Never project-specific, always transferable

Layer 2: PROJECT ADAPTER (per-project config)
  <project>/.claude/project-adapter.md
  → Tech stack, conventions, commands, active checklists
  → Tells agents HOW to apply their expertise here
  → Template: shiki-process/project-adapter-template.md

Layer 3: PROJECT STATE (per-project memory)
  <project>/memory/backlog.md, features/, planner-state.md
  → What's happening in this project right now
  → Decisions, features, PRs, bugs, roadmap
  → Ephemeral relative to agent identity
```

## How It Works

When @Sensei reviews code:
1. Reads `team/sensei.md` → knows architecture patterns from ALL projects
2. Reads `project-adapter.md` → adapts to THIS project's Swift/TS/Python stack
3. Reads project state → understands current feature context

The same @Sensei who learned "never use force unwraps in Swift" on WabiSabi
also knows "always use strict TypeScript" from Shiki,
and applies both when reviewing a new project.

## Agent Growth Protocol

After significant work on any project, update the agent's identity file:
- New patterns confirmed across 2+ projects
- Debugging insights that transcend a single codebase
- Process improvements discovered during real work
- Anti-patterns observed repeatedly

Do NOT add:
- Project-specific details (those go in project-adapter.md)
- Session-specific context (those go in project state)
- Unverified conclusions from a single file

## Team Roster

| Agent | Identity File | Role |
|-------|--------------|------|
| @Sensei | `sensei.md` | CTO / Technical Architect |
| @Hanami | `hanami.md` | Product Designer / UX Lead |
| @Kintsugi | `kintsugi.md` | Philosophy & Repair |
| @Enso | `enso.md` | Brand Identity & Mindfulness |
| @Tsubaki | `tsubaki.md` | Content & Copywriting |
| @Shogun | `shogun.md` | Competitive Intelligence |
| @Ronin | `ronin.md` | Adversarial Reviewer |
| @Daimyo | — | Founder (human, no growth file) |

## Adding New Agents

1. Create `team/<name>.md` with: Role, Cross-Project Learnings (empty), Known Patterns
2. Add persona to `shiki-process/agents.md`
3. Reference from team README

## Directory

```
shiki/team/
  README.md          ← This file (architecture doc)
  sensei.md          ← @Sensei cross-project knowledge
  hanami.md          ← @Hanami cross-project knowledge
  kintsugi.md        ← @Kintsugi cross-project knowledge
  enso.md            ← @Enso cross-project knowledge
  tsubaki.md         ← @Tsubaki cross-project knowledge
  shogun.md          ← @Shogun cross-project knowledge
  ronin.md           ← @Ronin cross-project knowledge
```
