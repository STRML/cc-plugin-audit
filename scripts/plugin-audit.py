#!/usr/bin/env python3
"""
cc-plugin-audit — SessionStart hook
Detects plugin marketplace updates and flags security-relevant changes.
"""
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
STATE_DIR = Path.home() / ".claude" / "plugin-audit"
MANIFEST = STATE_DIR / "manifest.json"
DIFF_DIR = STATE_DIR / "diffs"

# Files/patterns that can execute code or alter Claude's behavior
SEC_EXTENSIONS = {".sh", ".py", ".js", ".ts", ".mjs", ".cjs"}
SEC_FILENAMES = {
    "hooks.json", "plugin.json", ".mcp.json", "mcp.json",
    "SKILL.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
}


def hash_dir(dirpath: Path) -> str:
    h = hashlib.sha256()
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in sorted(dirs) if d != ".git"]
        for fname in sorted(files):
            if fname == ".DS_Store":
                continue
            fpath = Path(root) / fname
            try:
                h.update(str(fpath.relative_to(dirpath)).encode())
                h.update(fpath.read_bytes())
            except (PermissionError, FileNotFoundError):
                continue
    return h.hexdigest()


def semver_key(v: str):
    parts = []
    for p in v.replace("-", ".").split("."):
        try:
            parts.append((0, int(p)))
        except ValueError:
            parts.append((1, p))
    return parts


def latest_version(plugin_dir: Path) -> str | None:
    versions = [d.name for d in plugin_dir.iterdir() if d.is_dir()]
    if not versions:
        return None
    versions.sort(key=semver_key)
    return versions[-1]


def previous_version(plugin_dir: Path, current: str) -> str | None:
    versions = sorted(
        [d.name for d in plugin_dir.iterdir() if d.is_dir()],
        key=semver_key,
    )
    try:
        idx = versions.index(current)
    except ValueError:
        return None
    return versions[idx - 1] if idx > 0 else None


def is_sec_relevant(relpath: str) -> bool:
    name = os.path.basename(relpath)
    if name in SEC_FILENAMES:
        return True
    _, ext = os.path.splitext(name)
    return ext in SEC_EXTENSIONS


def collect_sec_files(dirpath: Path) -> list[str]:
    result = []
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in sorted(dirs) if d != ".git"]
        for fname in sorted(files):
            relpath = str((Path(root) / fname).relative_to(dirpath))
            if is_sec_relevant(relpath):
                result.append(relpath)
    return result


def diff_file(old: Path, new: Path) -> str:
    old_arg = str(old) if old.exists() else "/dev/null"
    new_arg = str(new) if new.exists() else "/dev/null"
    try:
        r = subprocess.run(
            ["diff", "-u", old_arg, new_arg],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout
    except Exception:
        return ""


def audit_plugin(key: str, plugin_dir: Path, ver: str, prev_entry: dict) -> dict | None:
    """Returns a change record if the plugin changed, else None."""
    latest_dir = plugin_dir / ver
    content_hash = hash_dir(latest_dir)

    prev_hash = prev_entry.get("hash", "")
    if content_hash == prev_hash:
        return None

    prev_ver_name = prev_entry.get("version", "")
    old_ver = previous_version(plugin_dir, ver)

    change = {
        "plugin": key,
        "old_version": prev_ver_name or "(new)",
        "new_version": ver,
        "hash": content_hash,
        "is_new": not prev_hash,
    }

    if old_ver and not change["is_new"]:
        old_dir = plugin_dir / old_ver
        # Collect security-relevant files from both sides
        old_sec = set(collect_sec_files(old_dir))
        new_sec = set(collect_sec_files(latest_dir))
        all_sec = sorted(old_sec | new_sec)

        diffs = []
        for relpath in all_sec:
            d = diff_file(old_dir / relpath, latest_dir / relpath)
            if d.strip():
                diffs.append(f"--- {relpath} ---\n{d}")

        if diffs:
            change["sec_diff"] = "\n".join(diffs)
        else:
            change["sec_diff"] = "(no changes in security-relevant files)"

        # Save full diff
        date_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_key = key.replace("/", "-")
        diff_file_path = DIFF_DIR / f"{date_str}-{safe_key}.diff"
        try:
            summary = subprocess.run(
                ["diff", "-rq", str(old_dir), str(latest_dir)],
                capture_output=True, text=True, timeout=10,
            ).stdout
        except Exception:
            summary = "(diff failed)"

        diff_file_path.write_text(
            f"Plugin: {key}\n"
            f"Old: {old_ver}  New: {ver}\n"
            f"Date: {datetime.now().isoformat()}\n\n"
            f"{'=' * 60}\nFILE CHANGES:\n{summary}\n"
            f"{'=' * 60}\nSECURITY-RELEVANT DIFF:\n{change.get('sec_diff', '')}\n"
        )
        change["diff_file"] = str(diff_file_path)

    return change


def main():
    if not CACHE_DIR.is_dir():
        sys.exit(0)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    DIFF_DIR.mkdir(parents=True, exist_ok=True)

    # Load previous manifest
    prev: dict = {}
    if MANIFEST.is_file():
        try:
            prev = json.loads(MANIFEST.read_text())
        except json.JSONDecodeError:
            pass

    first_run = not prev

    current: dict = {}
    changes: list[dict] = []
    new_plugins: list[str] = []

    for marketplace_dir in sorted(CACHE_DIR.iterdir()):
        if not marketplace_dir.is_dir() or marketplace_dir.name.startswith("temp_"):
            continue
        for plugin_dir in sorted(marketplace_dir.iterdir()):
            if not plugin_dir.is_dir():
                continue
            key = f"{marketplace_dir.name}/{plugin_dir.name}"
            ver = latest_version(plugin_dir)
            if not ver:
                continue

            prev_entry = prev.get(key, {})
            change = audit_plugin(key, plugin_dir, ver, prev_entry)

            if change:
                if change["is_new"]:
                    new_plugins.append(f"{key}@{ver}")
                else:
                    changes.append(change)
                current[key] = {"version": ver, "hash": change["hash"]}
            else:
                # Unchanged — carry forward
                current[key] = prev_entry if prev_entry else {
                    "version": ver,
                    "hash": hash_dir(plugin_dir / ver),
                }

    # Save manifest
    MANIFEST.write_text(json.dumps(current, indent=2) + "\n")

    # First run: seed silently
    if first_run:
        sys.exit(0)

    if not changes and not new_plugins:
        sys.exit(0)

    # Build context
    parts = []
    if changes:
        parts.append(
            "PLUGIN UPDATE DETECTED — review security-relevant changes below:"
        )
        for c in changes:
            parts.append(f"\n  {c['plugin']}: {c['old_version']} -> {c['new_version']}")
            if c.get("diff_file"):
                parts.append(f"  Full diff: {c['diff_file']}")
            sec_diff = c.get("sec_diff", "")
            if sec_diff and sec_diff != "(no changes in security-relevant files)":
                truncated = sec_diff[:4000]
                if len(sec_diff) > 4000:
                    truncated += "\n... (truncated — see diff file)"
                parts.append(f"  Security-relevant changes:\n{truncated}")
            elif sec_diff:
                parts.append(f"  {sec_diff}")

    if new_plugins:
        parts.append("\nNew plugins detected (first seen):")
        for p in new_plugins:
            parts.append(f"  {p}")

    output = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "\n".join(parts),
        }
    }
    print(json.dumps(output))
    sys.exit(0)


if __name__ == "__main__":
    main()
