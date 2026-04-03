---
description: Review installed plugin security status — shows inventory, recent changes, and any pending audit diffs
---

# Plugin Security Audit

Run the plugin audit script to check current status, then review any flagged changes.

## Steps

1. **Show current inventory** by running:
   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/plugin-audit.py" --status
   ```

2. **Check for any saved diffs** in `~/.claude/plugin-audit/diffs/`. If diffs exist, read the most recent ones and summarize the security-relevant changes.

3. **For each diff found**, assess whether the changes are benign (version bumps, docs, formatting) or concerning (new hook scripts, MCP server changes, network access, exfiltration patterns, obfuscated code).

4. **Report your findings** to the user in this format:
   - Number of tracked plugins
   - Any recent updates with a security assessment
   - Recommendation: safe / review recommended / suspicious

5. If the user wants to **re-baseline** (trust all current versions), run:
   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/plugin-audit.py" --reset
   ```
