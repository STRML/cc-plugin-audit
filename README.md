# cc-plugin-audit

Supply-chain security for Claude Code plugins. Detects when marketplace plugins auto-update and surfaces security-relevant diffs at session start.

## What it does

On every `SessionStart`, this plugin:

1. Scans `~/.claude/plugins/cache/` for all installed marketplace plugins
2. Hashes each plugin's latest version directory
3. Compares against a saved manifest (`~/.claude/plugin-audit/manifest.json`)
4. If a plugin changed:
   - Diffs security-relevant files (hooks, scripts, configs, skills, MCP servers)
   - Saves full diff to `~/.claude/plugin-audit/diffs/`
   - Injects a warning into your session context

## What counts as "security-relevant"

- **Hook scripts** (`.sh`, `.py`, `.js`, `.ts`) — arbitrary code execution
- **Hook config** (`hooks.json`) — what events trigger code
- **Plugin manifest** (`plugin.json`) — permissions, MCP servers
- **MCP config** (`.mcp.json`) — network access, external tools
- **Skills/instructions** (`SKILL.md`, `CLAUDE.md`) — behavioral manipulation

## Install

```
/plugin marketplace add STRML/cc-plugin-audit
/plugin install cc-plugin-audit@cc-plugin-audit-dev
```

Or for local development:

```
/plugin marketplace add ~/git/oss/cc-plugin-audit
/plugin install cc-plugin-audit@cc-plugin-audit-dev
```

Then restart Claude Code.

## First run

The first session after install seeds the manifest silently — no warnings. Subsequent sessions will flag any changes.

## State files

| Path | Purpose |
|------|---------|
| `~/.claude/plugin-audit/manifest.json` | Content hashes per plugin |
| `~/.claude/plugin-audit/diffs/` | Saved diffs when updates are detected |

## Reset

To re-baseline (mark all current versions as trusted):

```bash
rm ~/.claude/plugin-audit/manifest.json
```

Next session will re-seed silently.

## License

MIT
