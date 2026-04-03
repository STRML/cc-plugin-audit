#!/usr/bin/env python3
"""
cc-plugin-audit — SessionStart hook
Detects plugin marketplace updates and flags security-relevant changes.
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
STATE_DIR = Path.home() / ".claude" / "plugin-audit"
MANIFEST = STATE_DIR / "manifest.json"
DIFF_DIR = STATE_DIR / "diffs"

HASH_CHUNK_SIZE = 65536

SEC_EXTENSIONS = {".sh", ".py", ".js", ".ts", ".mjs", ".cjs", ".cmd", ".bat", ".ps1"}
SEC_FILENAMES = {
    "hooks.json", "plugin.json", ".mcp.json", "mcp.json",
    "SKILL.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
}
SEC_MD_DIRS = {"commands", "agents", "skills"}


def walk_dir(dirpath: Path):
    """Yield (relpath_str, full_path) for all files, excluding .git and .DS_Store."""
    for root_str, dirs, files in __import__("os").walk(dirpath):
        dirs[:] = [d for d in sorted(dirs) if d != ".git"]
        root = Path(root_str)
        for fname in sorted(files):
            if fname == ".DS_Store":
                continue
            fpath = root / fname
            yield str(fpath.relative_to(dirpath)), fpath


def hash_dir(dirpath: Path) -> str:
    h = hashlib.sha256()
    for relpath, fpath in walk_dir(dirpath):
        h.update(relpath.encode())
        try:
            with open(fpath, "rb") as f:
                while chunk := f.read(HASH_CHUNK_SIZE):
                    h.update(chunk)
        except (PermissionError, FileNotFoundError):
            continue
    return h.hexdigest()


def sorted_versions(plugin_dir: Path) -> list[str]:
    """Return version directory names sorted by semver."""
    versions = [d.name for d in plugin_dir.iterdir() if d.is_dir()]
    versions.sort(key=_semver_key)
    return versions


def _semver_key(v: str):
    parts = []
    for p in v.replace("-", ".").split("."):
        try:
            parts.append((0, int(p)))
        except ValueError:
            parts.append((1, p))
    return parts


def is_sec_relevant(relpath: str) -> bool:
    p = Path(relpath)
    if p.name in SEC_FILENAMES:
        return True
    if p.suffix in SEC_EXTENSIONS:
        return True
    if p.suffix == ".md" and p.parts and p.parts[0] in SEC_MD_DIRS:
        return True
    return False


def collect_sec_files(dirpath: Path) -> list[str]:
    return [rel for rel, _ in walk_dir(dirpath) if is_sec_relevant(rel)]


def run_diff(args: list[str], timeout: int = 5) -> str:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except Exception:
        return ""


def audit_plugin(key: str, plugin_dir: Path, ver: str, prev_entry: dict) -> dict | None:
    """Returns a change record if the plugin changed, else None."""
    latest_dir = plugin_dir / ver

    # Fast path: if version string matches, plugin hasn't been updated
    if prev_entry.get("version") == ver and prev_entry.get("hash"):
        content_hash = hash_dir(latest_dir)
        if content_hash == prev_entry["hash"]:
            return None
    else:
        content_hash = hash_dir(latest_dir)
        if content_hash == prev_entry.get("hash", ""):
            return None

    versions = sorted_versions(plugin_dir)
    try:
        idx = versions.index(ver)
    except ValueError:
        idx = -1
    old_ver = versions[idx - 1] if idx > 0 else None

    change = {
        "plugin": key,
        "old_version": prev_entry.get("version") or None,
        "new_version": ver,
        "hash": content_hash,
        "is_new": not prev_entry.get("hash"),
    }

    if old_ver and not change["is_new"]:
        old_dir = plugin_dir / old_ver
        all_sec = sorted(set(collect_sec_files(old_dir)) | set(collect_sec_files(latest_dir)))

        diffs = []
        for relpath in all_sec:
            old_arg = str(old_dir / relpath) if (old_dir / relpath).exists() else "/dev/null"
            new_arg = str(latest_dir / relpath) if (latest_dir / relpath).exists() else "/dev/null"
            d = run_diff(["diff", "-u", old_arg, new_arg])
            if d.strip():
                diffs.append(f"--- {relpath} ---\n{d}")

        change["sec_diff"] = "\n".join(diffs) if diffs else None

        now = datetime.now()
        safe_key = key.replace("/", "-")
        diff_file_path = DIFF_DIR / f"{now.strftime('%Y%m%d-%H%M%S')}-{safe_key}.diff"
        summary = run_diff(["diff", "-rq", str(old_dir), str(latest_dir)], timeout=10)

        diff_file_path.write_text(
            f"Plugin: {key}\n"
            f"Old: {old_ver}  New: {ver}\n"
            f"Date: {now.isoformat()}\n\n"
            f"{'=' * 60}\nFILE CHANGES:\n{summary}\n"
            f"{'=' * 60}\nSECURITY-RELEVANT DIFF:\n{change['sec_diff'] or '(none)'}\n"
        )
        change["diff_file"] = str(diff_file_path)

    return change


def load_manifest() -> dict:
    if not MANIFEST.is_file():
        return {}
    try:
        data = json.loads(MANIFEST.read_text())
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def scan_plugins(prev: dict) -> tuple[dict, list[dict], list[str], list[str]]:
    """Scan cache, return (current_manifest, changes, new_plugins, removed_plugins)."""
    current: dict = {}
    changes: list[dict] = []
    new_plugins: list[str] = []
    seen_keys: set[str] = set()

    for marketplace_dir in sorted(CACHE_DIR.iterdir()):
        if not marketplace_dir.is_dir() or marketplace_dir.name.startswith("temp_"):
            continue
        for plugin_dir in sorted(marketplace_dir.iterdir()):
            if not plugin_dir.is_dir():
                continue
            key = f"{marketplace_dir.name}/{plugin_dir.name}"
            seen_keys.add(key)

            versions = sorted_versions(plugin_dir)
            if not versions:
                continue
            ver = versions[-1]

            prev_entry = prev.get(key, {})

            # Fast path: version string unchanged → skip hashing entirely
            if prev_entry.get("version") == ver and prev_entry.get("hash"):
                current[key] = prev_entry
                continue

            change = audit_plugin(key, plugin_dir, ver, prev_entry)
            if change:
                if change["is_new"]:
                    new_plugins.append(f"{key}@{ver}")
                else:
                    changes.append(change)
                current[key] = {"version": ver, "hash": change["hash"]}
            else:
                current[key] = {"version": ver, "hash": prev_entry.get("hash", "")}

    removed = sorted(set(prev.keys()) - seen_keys)
    return current, changes, new_plugins, removed


def cmd_status():
    manifest = load_manifest()
    if not manifest:
        print("No manifest found. Run a session to seed it.")
        return
    print(f"Tracking {len(manifest)} plugins:\n")
    for key in sorted(manifest):
        entry = manifest[key]
        print(f"  {key}  v{entry['version']}  {entry['hash'][:12]}...")
    print(f"\nManifest: {MANIFEST}")
    print(f"Diffs:    {DIFF_DIR}")
    diffs = sorted(DIFF_DIR.glob("*.diff")) if DIFF_DIR.is_dir() else []
    if diffs:
        print(f"\nRecent diffs ({len(diffs)} total):")
        for d in diffs[-5:]:
            print(f"  {d.name}")


def cmd_reset():
    if MANIFEST.is_file():
        MANIFEST.unlink()
        print("Manifest deleted. Next session will re-seed.")
    else:
        print("No manifest to reset.")


def main():
    if "--status" in sys.argv:
        cmd_status()
        return
    if "--reset" in sys.argv:
        cmd_reset()
        return

    if not CACHE_DIR.is_dir():
        sys.exit(0)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    DIFF_DIR.mkdir(parents=True, exist_ok=True)

    prev = load_manifest()
    first_run = not prev

    current, changes, new_plugins, removed = scan_plugins(prev)

    MANIFEST.write_text(json.dumps(current, indent=2) + "\n")

    if first_run:
        sys.exit(0)

    if not changes and not new_plugins and not removed:
        sys.exit(0)

    parts = []
    if changes:
        parts.append("PLUGIN UPDATE DETECTED — review security-relevant changes below:")
        for c in changes:
            old = c["old_version"] or "(new)"
            parts.append(f"\n  {c['plugin']}: {old} -> {c['new_version']}")
            if c.get("diff_file"):
                parts.append(f"  Full diff: {c['diff_file']}")
            sec_diff = c.get("sec_diff")
            if sec_diff:
                truncated = sec_diff[:4000]
                if len(sec_diff) > 4000:
                    truncated += "\n... (truncated — see diff file)"
                parts.append(f"  Security-relevant changes:\n{truncated}")
            else:
                parts.append("  (no changes in security-relevant files)")

    if removed:
        parts.append("\nPlugins removed since last session:")
        for r in removed:
            parts.append(f"  {r}")

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
