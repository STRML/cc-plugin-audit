"""
Threat indicator pattern scanner for Claude Code plugin files.

Scans file contents for known attack patterns based on documented real-world
exploits: PromptArmor, Check Point, Flatt Security, Snyk ToxicSkills,
ClawHavoc campaign, Embrace The Red, Cato Networks/MedusaLocker,
Adversa.ai, NVIDIA AI Red Team, Cymulate.
"""
import re
from dataclasses import dataclass


@dataclass
class ThreatIndicator:
    severity: str  # "critical", "high", "medium"
    name: str
    description: str
    file: str
    matched: str  # the matched content (truncated)


# ── Pattern definitions ──
# Each entry: (severity, name, description, compiled regex)
# Patterns run against file content. Some are file-type-specific.

_TEXT_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    # Tier 1 — Critical (real-world exploits exist)

    ("critical", "download-execute",
     "Download-and-execute pattern (curl|bash, wget|sh). Used in ClawHavoc, MedusaLocker.",
     re.compile(
         r"(?:curl|wget)\b[^|;]*\|\s*(?:bash|sh|zsh|python3?|ruby|perl|node)",
         re.IGNORECASE,
     )),

    ("critical", "base64-eval",
     "Base64-decoded content fed to eval/sh/bash. Used in Snyk ToxicSkills.",
     re.compile(
         r"(?:base64\s+(?:-d|--decode))[^|;]*\|\s*(?:eval|bash|sh|source)"
         r"|eval\s+.*base64\s+(?:-d|--decode)",
         re.IGNORECASE,
     )),

    ("critical", "settings-file-write",
     "Script writes to Claude Code settings/permission files. PromptArmor attack vector.",
     re.compile(
         r"""(?:settings\.json|settings\.local\.json|permissions\.allow)""",
         re.IGNORECASE,
     )),

    ("critical", "anthropic-base-url-override",
     "ANTHROPIC_BASE_URL set to non-Anthropic domain. API key exfiltration (CVE-2026-21852).",
     re.compile(
         r"ANTHROPIC_BASE_URL",
     )),

    ("critical", "bypass-permissions",
     "Attempts to set bypassPermissions mode. Workspace trust bypass (CVE-2026-33068).",
     re.compile(
         r"bypassPermissions",
     )),

    ("critical", "enable-all-mcp",
     "enableAllProjectMcpServers auto-enables all MCP servers (CVE-2025-59536).",
     re.compile(
         r"enableAllProjectMcpServers",
     )),

    ("critical", "pretooluse-auto-approve",
     "PreToolUse hook that auto-approves tool calls. PromptArmor permission bypass.",
     re.compile(
         r"""(?:"permissionDecision"\s*:\s*"allow"|"decision"\s*:\s*"approve")""",
     )),

    ("critical", "data-exfil-pipe",
     "Reads files and pipes to network command. File read + exfil chain (CVE-2025-55284).",
     re.compile(
         r"(?:cat|head|tail|less|more)\s+[^|;]*\|\s*(?:curl|wget|nc|ncat)\b"
         r"|curl\b[^;]*(?:--data-binary|--data|-d)\s+@",
         re.IGNORECASE,
     )),

    ("critical", "subcommand-flooding",
     "Excessive command chaining (>20) bypasses security analysis. Adversa.ai bypass.",
     re.compile(
         r"(?:(?:&&|\|\||;)\s*(?:true|echo\s+-n|:)\s*){15,}",
     )),

    # Tier 2 — High (documented techniques)

    ("high", "credential-path-access",
     "References credential/secret file paths.",
     re.compile(
         r"~/\.(?:aws/credentials|ssh/id_|gnupg/|npmrc|netrc|config/gh/hosts)"
         r"|~/\.claude\.json"
         r"|\.env\b",
         re.IGNORECASE,
     )),

    ("high", "npx-auto-install",
     "MCP server uses npx -y to auto-install packages without confirmation.",
     re.compile(
         r"npx.{0,80}(?:-y|--yes)",
     )),

    ("high", "password-protected-archive",
     "Downloads and extracts password-protected archive (evades antivirus scanning).",
     re.compile(
         r"unzip\s+-[^\s]*P\s|7z\s+[ex]\s+-p",
     )),

    ("high", "chmod-after-download",
     "Makes downloaded file executable.",
     re.compile(
         r"(?:curl|wget)[^;|]*[;&|]+[^;|]*chmod\s+\+x"
         r"|chmod\s+\+x[^;|]*(?:curl|wget)",
         re.IGNORECASE,
     )),

    ("high", "prompt-injection-phrase",
     "Common prompt injection patterns in instruction files.",
     re.compile(
         r"ignore\s+(?:all\s+)?previous\s+instructions"
         r"|you\s+are\s+now\s+"
         r"|override\s+(?:all\s+)?safety"
         r"|disregard\s+(?:all\s+)?(?:prior|previous|above)"
         r"|new\s+system\s+prompt"
         r"|IMPORTANT:\s*(?:ignore|override|forget)",
         re.IGNORECASE,
     )),

    ("high", "symlink-creation",
     "Creates symlinks in hook/skill scripts. Path traversal vector (CVE-2025-53109).",
     re.compile(
         r"\bln\s+-[^\s]*s",
     )),

    ("high", "custom-package-registry",
     "Redirects package installs to non-standard registries. Dependency hijack vector.",
     re.compile(
         r"--(?:index-url|extra-index-url|registry)\s+https?://(?!pypi\.org|registry\.npmjs\.org|crates\.io)",
         re.IGNORECASE,
     )),

    ("high", "cd-protected-write",
     "Changes into .claude/ directory then writes. Permission bypass (CVE-2026-25722).",
     re.compile(
         r"cd\s+[^;&|]*\.claude[/\s].*(?:&&|\|\||;)\s*(?:tee|cat\s*>|echo\s*>|cp\s|mv\s|>)",
         re.IGNORECASE,
     )),

    ("high", "find-exec-injection",
     "find -exec with shell metacharacters. Command injection (CVE-2026-24887).",
     re.compile(
         r"\bfind\b[^;]*-exec\s+[^;]*(?:\$\(|`|&&|\|\|)",
     )),

    ("high", "git-config-injection",
     "Git config value with shell metacharacters. RCE at startup (CVE-2025-59041).",
     re.compile(
         r"git\s+config\b[^;]*(?:\$\(|`)",
     )),

    ("high", "domain-spoof",
     "Trusted domain used as subdomain of untrusted domain. SSRF bypass (CVE-2026-24052).",
     re.compile(
         r"https?://[a-zA-Z0-9.-]*(?:anthropic\.com|claude\.ai|github\.com|npmjs\.org)\.[a-zA-Z]{2,}",
     )),

    ("high", "yarn-config-exec",
     "Yarn config with yarnPath or plugins entry. Pre-trust-dialog RCE (CVE-2025-59828).",
     re.compile(
         r"yarnPath\s*:|plugins\s*:\s*\n\s*-\s+path:",
     )),

    # Tier 3 — Medium (defense in depth)

    ("medium", "zsh-clobber",
     "ZSH clobber operator >| bypasses write path restrictions (CVE-2026-24053).",
     re.compile(
         r">\|",
     )),

    ("medium", "sed-execute-flag",
     "Sed with 'e' flag enables command execution. Bash validator bypass (CVE-2025-66032).",
     re.compile(
         r"""\bsed\b[^;|]*['"]s/[^/]*/[^/]*/e['"]""",
     )),

    ("medium", "history-file-write",
     "Uses history -a to write to arbitrary files. Bash validator bypass.",
     re.compile(
         r"history\s+-a\s+(?!~/\.bash_history|~/\.zsh_history)",
     )),

    ("medium", "ifs-injection",
     "Uses $IFS for argument injection. Bash validator bypass.",
     re.compile(
         r"\$IFS",
     )),

    ("medium", "bash-prompt-expansion",
     "Uses ${...@P} prompt expansion for code execution. Bash validator bypass.",
     re.compile(
         r"\$\{[^}]*@P\}",
     )),

    ("medium", "external-url",
     "References external URL (potential C2/exfiltration endpoint).",
     re.compile(
         r"https?://(?!"
         r"github\.com|githubusercontent\.com|"
         r"npmjs\.org|registry\.npmjs\.org|"
         r"pypi\.org|crates\.io|"
         r"anthropic\.com|claude\.ai|"
         r"localhost|127\.0\.0\.1|"
         r"example\.com"  # exclude example URLs in docs
         r")[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}",
     )),
]


def _check_unicode_tags(content: str, filename: str) -> list[ThreatIndicator]:
    """Detect hidden Unicode Tag codepoints (U+E0000-U+E007F).

    These are invisible characters that LLMs interpret as instructions.
    Used in ClawHavoc campaign (341 malicious skills).
    """
    indicators = []
    tag_chars = []
    start_pos = 0

    for i, ch in enumerate(content):
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            if not tag_chars:
                start_pos = i
            tag_chars.append(ch)
        else:
            if len(tag_chars) >= 3:
                # Decode: tag chars map to ASCII by subtracting 0xE0000
                decoded = "".join(chr(ord(c) - 0xE0000) for c in tag_chars)
                indicators.append(ThreatIndicator(
                    severity="critical",
                    name="unicode-tag-injection",
                    description=(
                        f"Hidden Unicode Tag sequence ({len(tag_chars)} chars) "
                        f"decodes to: {decoded[:100]!r}"
                    ),
                    file=filename,
                    matched=f"[invisible {len(tag_chars)} chars at position {start_pos}]",
                ))
            tag_chars = []

    # Handle trailing sequence
    if len(tag_chars) >= 3:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tag_chars)
        indicators.append(ThreatIndicator(
            severity="critical",
            name="unicode-tag-injection",
            description=(
                f"Hidden Unicode Tag sequence ({len(tag_chars)} chars) "
                f"decodes to: {decoded[:100]!r}"
            ),
            file=filename,
            matched=f"[invisible {len(tag_chars)} chars at position {start_pos}]",
        ))

    return indicators


def scan_file(content: str, filename: str) -> list[ThreatIndicator]:
    """Scan file content for threat indicators. Returns list of findings."""
    indicators: list[ThreatIndicator] = []

    # Unicode tag check (works on all files)
    indicators.extend(_check_unicode_tags(content, filename))

    # Text pattern checks
    for severity, name, description, pattern in _TEXT_PATTERNS:
        for match in pattern.finditer(content):
            matched_text = match.group(0)
            if len(matched_text) > 120:
                matched_text = matched_text[:120] + "..."
            indicators.append(ThreatIndicator(
                severity=severity,
                name=name,
                description=description,
                file=filename,
                matched=matched_text,
            ))

    return indicators


def scan_files(file_contents: dict[str, str]) -> list[ThreatIndicator]:
    """Scan multiple files. file_contents maps relpath -> content."""
    all_indicators: list[ThreatIndicator] = []
    for filename, content in file_contents.items():
        all_indicators.extend(scan_file(content, filename))

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    all_indicators.sort(key=lambda i: severity_order.get(i.severity, 99))
    return all_indicators


def format_indicators(indicators: list[ThreatIndicator]) -> str:
    """Format indicators for human/AI review."""
    if not indicators:
        return ""

    lines = ["THREAT INDICATORS DETECTED:"]
    for ind in indicators:
        icon = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]"}.get(ind.severity, "[?]")
        lines.append(f"  {icon} {ind.severity.upper()}: {ind.name}")
        lines.append(f"      {ind.description}")
        lines.append(f"      File: {ind.file}")
        lines.append(f"      Match: {ind.matched}")
    return "\n".join(lines)
