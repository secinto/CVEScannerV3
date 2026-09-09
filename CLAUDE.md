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
