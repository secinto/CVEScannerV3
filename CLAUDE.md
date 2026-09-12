# CVEScannerV3

CPE-to-CVE matching with distro-backport suppression. Owns the curated disposition overlay.

Part of the CheckFix tool group under `/checkfix/tools`. Build and test commands live in
this repo's `README.md` / `Makefile`; document them here as they stabilise.

## Session Completion (Landing the Plane)

When ending a work session, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** — `bd create` for anything that needs follow-up
2. **Run quality gates** (if code changed) — Tests, linters, builds
3. **PUSH TO REMOTE** — This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
   If beads issues changed, `bd dolt push` as well.
4. **Clean up** — Clear stashes, prune remote branches
5. **Verify** — All changes committed AND pushed
6. **Hand off** — Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing — that leaves work stranded locally
- NEVER say "ready to push when you are" — YOU must push
- If push fails, resolve and retry until it succeeds

## Issue Tracking (Beads)

This project uses **bd (beads)** for issue tracking. Run `bd prime` for the full command reference.

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd create --title="..." --type=bug|task|feature --priority=0..4
```

- Use `bd` for ALL task tracking — not TodoWrite, not markdown TODO lists.
- Use `bd remember` for persistent project knowledge — not ad hoc memory files.
- Issues live in a local Dolt DB; sync uses `refs/dolt/data` on the git remote, and `.beads/issues.jsonl` is a passive export.

**On session-close precedence:** *Session Completion (Landing the Plane)* above is the
only session protocol for this repo. `bd prime` injects a more conservative one at
session start ("do not commit or push unless explicitly asked"); it previously also
wrote that protocol into this file, which left two contradictory rules ~75 lines apart.
Where they differ, this file wins — push is mandatory here.

## Commit Message Conventions

Every commit message must start with a recognized prefix followed by `: `:

- `feat:` / `feature:` — New user-visible capability or behaviour. Appears in release notes under **Features**.
- `fix:` — Corrects defective or incorrect behaviour. Appears in release notes under **Bug Fixes**.
- `bug:` — Same category as `fix:`; use specifically when addressing a known or previously tracked defect. Appears in release notes under **Bug Fixes**.
- `docs:` — Documentation-only change, no code logic affected. Appears in release notes under **Documentation**.
- `chore:` — Maintenance tasks: version bumps, dependency updates, CI tweaks. Not included in release notes.
- `refactor:` — Code restructuring with no behaviour change. Not included in release notes.
- `test:` — Adding or fixing tests only. Not included in release notes.

## Code Quality

The repo-group rule in `/checkfix/tools/CLAUDE.md` applies: improve the lines you already
have reason to edit for the current task, and surface anything out of scope as a
follow-up (`bd create`) rather than fixing it inline. Keeps diffs reviewable while
still compounding quality on code that is actively being worked on.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

## Issue tracking (beads): bootstrap, never init

`.beads/` is committed, but the issue data lives in the git ref `refs/dolt/data`,
which a normal `git clone` does not fetch. The canonical database is maintained
on **balrog**; every other checkout (app, test-two, build, phishy, bifrost, …)
is a replica of the same Dolt history.

- **New checkout, or `.beads/embeddeddolt` missing: run `bd bootstrap`.**
  Never `bd init` here. A second init creates an unrelated Dolt history that can
  never be pushed or pulled again ("no common ancestor"); that happened across
  these repos in September 2026 and had to be repaired by hand.
- Start of a session: `bd dolt pull`. Session close: `bd dolt push`.
- If a push fails with "no common ancestor", do not force-push and do not
  bootstrap over your data. Repair: `bd export > /tmp/mine.jsonl`, move
  `.beads/embeddeddolt` aside, `bd bootstrap`, `bd import /tmp/mine.jsonl`,
  then push.
- `git ls-remote origin refs/dolt/data` shows whether a remote history exists.
