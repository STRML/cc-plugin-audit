#!/usr/bin/env python3
"""
cc-plugin-audit — SessionStart hook
Detects plugin marketplace updates and flags security-relevant changes.
"""
# Lazy annotations (PEP 563): keeps PEP 604 unions like `dict | None` from being
# evaluated at def-time, so the hook imports cleanly under Python 3.9 too. Without
# this, `-> dict | None` raised "unsupported operand type(s) for |: 'type' and
# 'NoneType'" at SessionStart whenever the hook's python3 resolved to <3.10.
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from threat_patterns import scan_files, format_indicators

CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
STATE_DIR = Path.home() / ".claude" / "plugin-audit"
MANIFEST = STATE_DIR / "manifest.json"
DIFF_DIR = STATE_DIR / "diffs"
SKIP_DIRS = {".git", ".in_use"}

HASH_CHUNK_SIZE = 65536

SEC_EXTENSIONS = {".sh", ".py", ".js", ".ts", ".mjs", ".cjs", ".cmd", ".bat", ".ps1"}
SEC_FILENAMES = {
    "hooks.json", "plugin.json", ".mcp.json", "mcp.json",
    "SKILL.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
}
SEC_MD_DIRS = {"commands", "agents", "skills"}

# Known-good path prefixes excluded from threat scanning. These are trusted
# doc trees that legitimately mention scanner trigger strings (e.g. the
# built-in claude-api skill docs reference ANTHROPIC_BASE_URL and show
# curl-to-api.anthropic.com examples).
IGNORE_PATHS = (
    "skills/claude-api/",
)


def walk_dir(dirpath: Path):
    """Yield (relpath_str, full_path) for all plugin files.

    Skips .git, .DS_Store, and .in_use: Claude Code writes an .in_use/<pid>
    marker into every loaded plugin per session, so counting it made every
    enabled plugin look updated at every start.
    """
    import os
    for root_str, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in sorted(dirs) if d not in SKIP_DIRS]
        root = Path(root_str)
        for fname in sorted(files):
            if fname == ".DS_Store":
                continue
            fpath = root / fname
            yield str(fpath.relative_to(dirpath)), fpath


def newest_mtime(dirpath: Path) -> float:
    """Return the newest file mtime in the directory tree."""
    max_mt = 0.0
    for _, fpath in walk_dir(dirpath):
        try:
            mt = fpath.stat().st_mtime
            if mt > max_mt:
                max_mt = mt
        except (PermissionError, FileNotFoundError):
            continue
    return max_mt


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
    if any(relpath.startswith(prefix) for prefix in IGNORE_PATHS):
        return False
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


def read_sec_files(dirpath: Path) -> dict[str, str]:
    """Read contents of all security-relevant files. Returns {relpath: content}."""
    result = {}
    for rel in collect_sec_files(dirpath):
        fpath = dirpath / rel
        try:
            result[rel] = fpath.read_text(errors="replace")
        except (PermissionError, OSError):
            pass
    return result


def run_diff(args: list[str], timeout: int = 5) -> str:
    # diff exit codes: 0 same, 1 differ, >=2 trouble. Trouble must be VISIBLE in
    # the output — an empty sec_diff reads as "no changes", and for an audit tool
    # a swallowed failure is a silent miss.
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if r.returncode >= 2:
            return f"[diff error rc={r.returncode}: {r.stderr.strip()[:200]}]"
        return r.stdout
    except Exception as e:
        return f"[diff error: {e}]"


def report_dir() -> Path:
    """Where full audit detail goes. Derived from STATE_DIR so tests can patch it."""
    return STATE_DIR / "reports"


def allowlist_path() -> Path:
    return STATE_DIR / "allowlist.json"


def load_allowlist() -> dict:
    """Per-plugin indicators that are expected and must not be reported.

    Shape: {"marketplace/plugin": ["name", {"name": "name", "path": "hooks/x.py"}]}.
    An entry without "path" covers every file; with "path" it covers that
    relative path prefix. A first-party plugin whose job is detecting a
    pattern (endpoint override, settings writes, permission bypass) matches
    that pattern in its own source, so an unallowlisted scan reports the
    detector as an attack. The path form keeps the allowlist narrow enough
    that a real payload elsewhere in the same plugin still shows up.
    """
    path = allowlist_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict = {}
    for key, entries in data.items():
        if not isinstance(entries, list):
            continue
        rules = []
        for entry in entries:
            if isinstance(entry, str):
                rules.append((entry, None))
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                rules.append((entry["name"], entry.get("path")))
        out[key] = rules
    return out


def is_expected(indicator, rules: list) -> bool:
    for name, path in rules:
        if indicator.name != name:
            continue
        if path is None or indicator.file.startswith(path):
            return True
    return False


def count_severities(indicators: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0}
    for ind in indicators:
        counts[ind.severity] = counts.get(ind.severity, 0) + 1
    return counts


def format_counts(counts: dict) -> str:
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium") if counts.get(s)]
    return ", ".join(parts)


def write_report(sections: list[str]) -> str | None:
    """Write full detail to disk; return its path."""
    if not sections:
        return None
    rdir = report_dir()
    rdir.mkdir(parents=True, exist_ok=True)
    out = rdir / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-plugin-update.md"
    out.write_text("\n\n".join(sections) + "\n")
    return str(out)


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

    # Scan new version for threat indicators. Expected matches for this plugin
    # (its own detectors matching their own patterns) are dropped here, so the
    # session context and the counts never carry them.
    sec_contents = read_sec_files(latest_dir)
    indicators = scan_files(sec_contents)
    rules = load_allowlist().get(key, [])
    suppressed = [i for i in indicators if is_expected(i, rules)]
    indicators = [i for i in indicators if not is_expected(i, rules)]
    change["threats"] = format_indicators(indicators) if indicators else None
    change["threat_counts"] = count_severities(indicators)
    change["suppressed"] = len(suppressed)

    if change["is_new"]:
        # First-seen: report security-relevant file inventory
        if sec_contents:
            contents = [f"--- {rel} ---\n{text}" for rel, text in sec_contents.items()]
            change["sec_inventory"] = "\n".join(contents)
        else:
            change["sec_inventory"] = None
    elif old_ver:
        old_dir = plugin_dir / old_ver
        all_sec = sorted(set(collect_sec_files(old_dir)) | set(collect_sec_files(latest_dir)))

        diffs = []
        # Empty sentinel instead of /dev/null for added/deleted files: some
        # sandboxes deny diff(1) access to /dev/null, which silently emptied
        # every new-file diff.
        with tempfile.NamedTemporaryFile(suffix=".empty") as empty:
            for relpath in all_sec:
                old_arg = str(old_dir / relpath) if (old_dir / relpath).exists() else empty.name
                new_arg = str(latest_dir / relpath) if (latest_dir / relpath).exists() else empty.name
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
            latest_dir = plugin_dir / ver

            # Fast path: version + mtime unchanged → skip hashing
            if prev_entry.get("version") == ver and prev_entry.get("hash"):
                current_mtime = newest_mtime(latest_dir)
                if current_mtime <= prev_entry.get("mtime", 0):
                    current[key] = prev_entry
                    continue

            change = audit_plugin(key, plugin_dir, ver, prev_entry)
            if change:
                mtime = newest_mtime(latest_dir)
                if change["is_new"]:
                    new_plugins.append(change)
                else:
                    changes.append(change)
                current[key] = {"version": ver, "hash": change["hash"], "mtime": mtime}
            else:
                mtime = newest_mtime(latest_dir)
                current[key] = {
                    "version": ver,
                    "hash": prev_entry.get("hash", ""),
                    "mtime": mtime,
                }

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
        mt = entry.get("mtime", 0)
        mt_str = datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M") if mt else "unknown"
        print(f"  {key}  v{entry['version']}  {entry['hash'][:12]}...  mtime={mt_str}")
    print(f"\nManifest: {MANIFEST}")
    print(f"Diffs:    {DIFF_DIR}")
    diffs = sorted(DIFF_DIR.glob("*.diff")) if DIFF_DIR.is_dir() else []
    if diffs:
        print(f"\nRecent diffs ({len(diffs)} total):")
        for d in diffs[-5:]:
            print(f"  {d.name}")
    rdir = report_dir()
    reports = sorted(rdir.glob("*-plugin-update.md")) if rdir.is_dir() else []
    if reports:
        print(f"\nRecent reports ({len(reports)} total):")
        for r in reports[-5:]:
            print(f"  {r}")


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
    sections = []
    MAX_INLINE_PLUGINS = 5

    # Everything verbose (indicator text, diffs, file inventories) goes to a
    # report file. The session context carries one line per plugin: a hook that
    # dumps 15KB of CVE and "API key exfiltration" prose into every SessionStart
    # both burns context and makes the session look like a security incident to
    # the model provider's classifiers.
    for c in changes + new_plugins:
        body = [f"## {c['plugin']} {c.get('old_version') or '(new)'} -> {c['new_version']}"]
        if c.get("threats"):
            body.append(c["threats"])
        if c.get("suppressed"):
            body.append(f"({c['suppressed']} expected indicator(s) suppressed by allowlist)")
        if c.get("sec_diff"):
            body.append(f"### security-relevant diff\n{c['sec_diff']}")
        elif c.get("sec_inventory"):
            body.append(f"### security-relevant files\n{c['sec_inventory']}")
        if c.get("diff_file"):
            body.append(f"Full diff file: {c['diff_file']}")
        sections.append("\n".join(body))

    report = write_report(sections)

    listed = (changes + new_plugins)[:MAX_INLINE_PLUGINS]
    hidden = len(changes) + len(new_plugins) - len(listed)

    if listed:
        parts.append("PLUGIN UPDATE AUDIT — act only if a count below looks wrong:")
        for c in listed:
            old = c["old_version"] or "(new)"
            tag = "NEW " if c.get("is_new") else ""
            counts = c.get("threat_counts") or {}
            detail = format_counts(counts) or "no threat indicators"
            if c.get("suppressed"):
                detail += f" ({c['suppressed']} expected, allowlisted)"
            parts.append(f"  {tag}{c['plugin']} {old} -> {c['new_version']}: {detail}")
        if hidden > 0:
            parts.append(f"  +{hidden} more changed plugin(s)")
        if report:
            parts.append(f"Details and diffs: {report}")

    if removed:
        parts.append("PLUGINS REMOVED: " + ", ".join(removed))

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
