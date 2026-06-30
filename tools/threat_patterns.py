"""Shared threat-pattern library for context window security scanning.

This module is the single source of truth for prompt-injection / promptware /
exfiltration patterns used across the context-assembly scanners
(``agent/prompt_builder.py``, ``tools/memory_tool.py``) and the tool-result
delimiter system in ``agent/tool_dispatch_helpers.py``.

Pattern philosophy
------------------
Patterns are organized by ATTACK CLASS, not by source file.  Each pattern
is a ``(regex, pattern_id, scope)`` tuple, where ``scope`` controls which
scanners use it:

- ``"all"``  — applied everywhere (classic prompt injection, exfiltration)
- ``"context"`` — applied to context files + memory + tool results
  (promptware / C2 / behavioral hijack; broader detection)
- ``"strict"`` — applied to memory writes + skill installs only
  (aggressive checks acceptable for user-curated content but too noisy
  for tool results)

The split exists because tool results contain web pages, GitHub issues,
and MCP responses — content the user did not author — and we want broad
detection there, but blocking is reserved for paths where the user can
intervene (memory writes, skill installs).

Pattern anchoring
-----------------
New patterns anchor on **C2-specific vocabulary or unambiguous attack
behavior**, NOT on bossy English.  Phrases like "you are obligated to"
or "you must" alone are too common in legitimate instruction-writing
(see AGENTS.md, CLAUDE.md, etc.) to flag.  See the pattern comments for
the rationale on borderline cases.

Multi-word bypass
-----------------
Patterns use ``(?:\\w+\\s+)*`` between key tokens to prevent attackers
from inserting filler words (e.g. "ignore all prior instructions" instead
of "ignore all instructions").  This mirrors the fix applied to
``skills_guard.py`` in commit 4ea29978.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Optional, Tuple

# Homoglyph mapping: characters that look like Latin letters but are from
# other scripts (Cyrillic, Greek, etc.). Used to normalize content before
# pattern matching to prevent homoglyph bypass attacks.
_HOMOGLYPH_MAP: dict[int, str] = {
    # Cyrillic → Latin
    0x0400: "E",  # Ѐ → E
    0x0401: "Yo", # Ё → Yo
    0x0402: "Dj", # Ђ → Dj
    0x0403: "G",  # Ѓ → G
    0x0404: "Ye", # Є → Ye
    0x0405: "Dz", # Ѕ → Dz
    0x0406: "I",  # І → I
    0x0407: "Yi", # Ї → Yi
    0x0408: "J",  # Ј → J
    0x0409: "Lj", # Љ → Lj
    0x040A: "Nj", # Њ → Nj
    0x040B: "Tj", # Ћ → Tj
    0x040C: "K",  # Ќ → K
    0x040E: "U",  # Ў → U
    0x040F: "Dz", # Џ → Dz
    0x0410: "A",  # А → A
    0x0411: "B",  # Б → B
    0x0412: "V",  # В → V
    0x0413: "G",  # Г → G
    0x0414: "D",  # Д → D
    0x0415: "Ye", # Е → Ye
    0x0416: "Zh", # Ж → Zh
    0x0417: "Z",  # З → Z
    0x0418: "I",  # И → I
    0x0419: "Y",  # Й → Y
    0x041A: "K",  # К → K
    0x041B: "L",  # Л → L
    0x041C: "M",  # М → M
    0x041D: "N",  # Н → N
    0x041E: "O",  # О → O
    0x041F: "P",  # П → P
    0x0420: "R",  # Р → R
    0x0421: "S",  # С → S
    0x0422: "T",  # Т → T
    0x0423: "U",  # У → U
    0x0424: "F",  # Ф → F
    0x0425: "Kh", # Х → Kh
    0x0426: "Ts", # Ц → Ts
    0x0427: "Ch", # Ч → Ch
    0x0428: "Sh", # Ш → Sh
    0x0429: "Shch",# Щ → Shch
    0x042A: "",   # Ъ → (hard sign, no Latin equivalent)
    0x042B: "Y",  # Ы → Y
    0x042C: "",   # Ь → (soft sign)
    0x042D: "E",  # Э → E
    0x042E: "Yu", # Ю → Yu
    0x042F: "Ya", # Я → Ya
    # Lowercase
    0x0430: "a",  # а → a
    0x0431: "b",  # б → b
    0x0432: "v",  # в → v
    0x0433: "g",  # г → g
    0x0434: "d",  # д → d
    0x0435: "ye", # е → ye
    0x0436: "zh", # ж → zh
    0x0437: "z",  # з → z
    0x0438: "i",  # и → i
    0x0439: "y",  # й → y
    0x043A: "k",  # к → k
    0x043B: "l",  # л → l
    0x043C: "m",  # м → m
    0x043D: "n",  # н → n
    0x043E: "o",  # о → o
    0x043F: "p",  # п → p
    0x0440: "r",  # р → r
    0x0441: "s",  # с → s
    0x0442: "t",  # т → t
    0x0443: "u",  # у → u
    0x0444: "f",  # ф → f
    0x0445: "kh", # х → kh
    0x0446: "ts", # ц → ts
    0x0447: "ch", # ч → ch
    0x0448: "sh", # ш → sh
    0x0449: "shch",# щ → shch
    0x044A: "",   # ъ → (hard sign)
    0x044B: "y",  # ы → y
    0x044C: "",   # ь → (soft sign)
    0x044D: "e",  # э → e
    0x044E: "yu", # ю → yu
    0x044F: "ya", # я → ya
    # ʼ (Cyrillic letter reversed Komi) looks like apostrophe
    0x0450: "è",  # ѐ → è
    0x0451: "yo", # ё → yo
    0x0452: "dj", # ђ → dj
    0x0453: "g",  # ѓ → g
    0x0454: "ye", # є → ye
    0x0455: "dz", # ѕ → dz
    0x0456: "i",  # і → i (CRITICAL: Ukrainian І looks identical to Latin I)
    0x0457: "yi", # ї → yi
    0x0458: "j",  # ј → j
    0x0459: "lj", # љ → lj
    0x045A: "nj", # њ → nj
    0x045B: "tj", # ћ → tj
    0x045C: "k",  # ќ → k
    0x045E: "u",  # ў → u
    0x045F: "dz", # џ → dz
    # Greek → Latin (common homoglyphs)
    0x0391: "A",  # Α → A
    0x0392: "B",  # Β → B
    0x0395: "E",  # Ε → E
    0x0396: "Z",  # Ζ → Z
    0x0397: "H",  # Η → H
    0x0399: "I",  # Ι → I (CRITICAL: Greek Ι looks identical to Latin I)
    0x039A: "K",  # Κ → K
    0x039C: "M",  # Μ → M
    0x039D: "N",  # Ν → N
    0x039F: "O",  # Ο → O (CRITICAL: Greek Ο looks identical to Latin O)
    0x03A1: "P",  # Ρ → P (CRITICAL: Greek Ρ looks identical to Latin P)
    0x03A4: "T",  # Τ → T
    0x03A5: "Y",  # Υ → Y
    0x03A7: "X",  # Χ → X
    # Lowercase
    0x03B1: "a",  # α → a
    0x03B2: "b",  # β → b
    0x03B5: "e",  # ε → e
    0x03B6: "z",  # ζ → z
    0x03B7: "h",  # η → h
    0x03B9: "i",  # ι → i
    0x03BA: "k",  # κ → k
    0x03BC: "m",  # μ → m
    0x03BD: "n",  # ν → n
    0x03BF: "o",  # ο → o
    0x03C1: "p",  # ρ → p
    0x03C4: "t",  # τ → t
    0x03C5: "u",  # υ → u
    0x03C7: "x",  # χ → x
    # Fullwidth Latin (used to bypass filters)
    0xFF21: "A",  # Ａ → A
    0xFF22: "B",  # Ｂ → B
    0xFF23: "C",  # Ｃ → C
    0xFF24: "D",  # Ｄ → D
    0xFF25: "E",  # Ｅ → E
    0xFF26: "F",  # Ｆ → F
    0xFF27: "G",  # Ｇ → G
    0xFF28: "H",  # Ｈ → H
    0xFF29: "I",  # Ｉ → I
    0xFF2A: "J",  # Ｊ → J
    0xFF2B: "K",  # Ｋ → K
    0xFF2C: "L",  # Ｌ → L
    0xFF2D: "M",  # Ｍ → M
    0xFF2E: "N",  # Ｎ → N
    0xFF2F: "O",  # Ｏ → O
    0xFF30: "P",  # Ｐ → P
    0xFF31: "Q",  # Ｑ → Q
    0xFF32: "R",  # Ｒ → R
    0xFF33: "S",  # Ｓ → S
    0xFF34: "T",  # Ｔ → T
    0xFF35: "U",  # Ｕ → U
    0xFF36: "V",  # Ｖ → V
    0xFF37: "W",  # Ｗ → W
    0xFF38: "X",  # Ｘ → X
    0xFF39: "Y",  # Ｙ → Y
    0xFF3A: "Z",  # Ｚ → Z
    0xFF41: "a",  # ａ → a
    0xFF42: "b",  # ｂ → b
    0xFF43: "c",  # ｃ → c
    0xFF44: "d",  # ｄ → d
    0xFF45: "e",  # ｅ → e
    0xFF46: "f",  # ｆ → f
    0xFF47: "g",  # ｇ → g
    0xFF48: "h",  # ｈ → h
    0xFF49: "i",  # ｉ → i
    0xFF4A: "j",  # ｊ → j
    0xFF4B: "k",  # ｋ → k
    0xFF4C: "l",  # ｌ → l
    0xFF4D: "m",  # ｍ → m
    0xFF4E: "n",  # ｎ → n
    0xFF4F: "o",  # ｏ → o
    0xFF50: "p",  # ｐ → p
    0xFF51: "q",  # ｑ → q
    0xFF52: "r",  # ｒ → r
    0xFF53: "s",  # ｓ → s
    0xFF54: "t",  # ｔ → t
    0xFF55: "u",  # ｕ → u
    0xFF56: "v",  # ｖ → v
    0xFF57: "w",  # ｗ → w
    0xFF58: "x",  # ｘ → x
    0xFF59: "y",  # ｙ → y
    0xFF5A: "z",  # ｚ → z
}


def _normalize_homoglyphs(content: str) -> str:
    """Replace homoglyph characters with their Latin equivalents.

    This defeats attacks that use visually similar characters from other
    scripts (Cyrillic, Greek, fullwidth) to evade regex-based scanners
    while still being interpreted as Latin by LLMs.
    """
    result = []
    for ch in content:
        cp = ord(ch)
        if cp in _HOMOGLYPH_MAP:
            result.append(_HOMOGLYPH_MAP[cp])
        else:
            result.append(ch)
    return "".join(result)

# Each entry: (regex, pattern_id, scope)
# scope ∈ {"all", "context", "strict"}
_PATTERNS: List[Tuple[str, str, str]] = [
    # ── Classic prompt injection (applies everywhere) ────────────────
    (r'ignore\s+(?:\w+\s+)*(previous|all|above|prior)\s+(?:\w+\s+)*instructions', "prompt_injection", "all"),
    (r'system\s+prompt\s+override', "sys_prompt_override", "all"),
    (r'disregard\s+(?:\w+\s+)*(your|all|any)\s+(?:\w+\s+)*(instructions|rules|guidelines)', "disregard_rules", "all"),
    (r'act\s+as\s+(if|though)\s+(?:\w+\s+)*you\s+(?:\w+\s+)*(have\s+no|don\'t\s+have)\s+(?:\w+\s+)*(restrictions|limits|rules)', "bypass_restrictions", "all"),
    (r'<!--[^>]*(?:ignore|override|system|secret|hidden)[^>]*-->', "html_comment_injection", "all"),
    (r'<\s*div\s+style\s*=\s*["\'][\s\S]*?display\s*:\s*none', "hidden_div", "all"),
    (r'translate\s+.*\s+into\s+.*\s+and\s+(execute|run|eval)', "translate_execute", "all"),
    (r'do\s+not\s+(?:\w+\s+)*tell\s+(?:\w+\s+)*the\s+user', "deception_hide", "all"),

    # ── Role-play / identity hijack (context + strict; common attack
    #    surface in scraped web content and poisoned context files) ──
    (r'you\s+are\s+(?:\w+\s+)*now\s+(?:a|an|the)\s+', "role_hijack", "context"),
    (r'pretend\s+(?:\w+\s+)*(you\s+are|to\s+be)\s+', "role_pretend", "context"),
    (r'output\s+(?:\w+\s+)*(system|initial)\s+prompt', "leak_system_prompt", "context"),
    (r'(respond|answer|reply)\s+without\s+(?:\w+\s+)*(restrictions|limitations|filters|safety)', "remove_filters", "context"),
    (r'you\s+have\s+been\s+(?:\w+\s+)*(updated|upgraded|patched)\s+to', "fake_update", "context"),
    # "name yourself X" is a Brainworm-specific tell — identity override
    # via spec instead of jailbreak.  Anchored on the verb pair so it
    # doesn't match "name your variables" etc.
    (r'\bname\s+yourself\s+\w+', "identity_override", "context"),

    # ── C2 / Brainworm-style promptware (context scope) ──────────────
    # These anchor on C2-specific vocabulary.  "register as a node" appears
    # in legitimate distributed-systems docs, but in combination with the
    # other patterns the signal is strong; we WARN, not block, so a security
    # researcher reading the Brainworm post in a webpage doesn't break their
    # session.
    (r'register\s+(as\s+)?a?\s*node', "c2_node_registration", "context"),
    (r'(heartbeat|beacon|check[\s\-]?in)\s+(to|with)\s+', "c2_heartbeat", "context"),
    (r'pull\s+(down\s+)?(?:new\s+)?task(?:ing|s)?\b', "c2_task_pull", "context"),
    (r'connect\s+to\s+the\s+network\b', "c2_network_connect", "context"),
    # Verb-anchored "you must register/connect/report/beacon" — the verbs
    # are C2-specific so this avoids the broader "you must X" false positive.
    (r'you\s+must\s+(?:\w+\s+){0,3}(register|connect|report|beacon)\b', "forced_action", "context"),
    # Anti-forensic instructions ("never write to disk", "one-liners only")
    # — extremely unusual in legitimate content; near-zero false positive.
    (r'only\s+use\s+one[\s\-]?liners?\b', "anti_forensic_oneliner", "context"),
    (r'never\s+(?:\w+\s+)*(?:create|write)\s+(?:\w+\s+)*(?:script|file)\s+(?:\w+\s+)*disk', "anti_forensic_disk", "context"),
    # Environment-variable unsetting targeting known agent runtimes —
    # this is pure attack behavior (Brainworm sub-session bypass).
    (r'unset\s+\w*(?:CLAUDE|CODEX|HERMES|AGENT|OPENAI|ANTHROPIC)\w*', "env_var_unset_agent", "context"),

    # ── Known C2 / red-team framework names (near-zero false positive
    #    outside security research; warn-only by default) ─────────────
    # NOTE: do not add common English words here. Every token must be a
    # distinctive offensive-security tool brand, otherwise legitimate
    # AGENTS.md / SOUL.md content false-positives and the whole file is
    # blocked. "praxis" was removed for exactly this reason — it's a common
    # word and a legitimate agent name (Greek for practice/action), not a
    # C2-specific tell like the brands below.
    (r'\b(?:cobalt\s*strike|sliver|havoc|mythic|metasploit|brainworm)\b', "known_c2_framework", "context"),
    (r'\bc2\s+(?:server|channel|infrastructure|beacon)\b', "c2_explicit", "context"),
    (r'\bcommand\s+and\s+control\b', "c2_explicit_long", "context"),

    # ── Exfiltration via curl/wget/cat with secrets (applies everywhere) ──
    (r'curl\s+[^\n]*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)', "exfil_curl", "all"),
    (r'wget\s+[^\n]*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)', "exfil_wget", "all"),
    (r'cat\s+[^\n]*(\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)', "read_secrets", "all"),
    (r'(send|post|upload|transmit)\s+.*\s+(to|at)\s+https?://', "send_to_url", "strict"),
    (r'(include|output|print|share)\s+(?:\w+\s+)*(conversation|chat\s+history|previous\s+messages|full\s+context|entire\s+context)', "context_exfil", "strict"),

    # ── Persistence / SSH backdoor (strict scope — memory + skills) ──
    (r'authorized_keys', "ssh_backdoor", "strict"),
    (r'\$HOME/\.ssh|\~/\.ssh', "ssh_access", "strict"),
    (r'\$HOME/\.hermes/\.env|\~/\.hermes/\.env', "hermes_env", "strict"),
    (r'(update|modify|edit|write|change|append|add\s+to)\s+.*(?:AGENTS\.md|CLAUDE\.md|\.cursorrules|\.clinerules)', "agent_config_mod", "strict"),
    (r'(update|modify|edit|write|change|append|add\s+to)\s+.*\.hermes/(config\.yaml|SOUL\.md)', "hermes_config_mod", "strict"),

    # ── Hardcoded secrets ────────────────────────────────────────────
    (r'(?:api[_-]?key|token|secret|password)\s*[=:]\s*["\'][A-Za-z0-9+/=_-]{20,}', "hardcoded_secret", "strict"),
]

# Invisible / bidirectional unicode characters used in injection attacks.
# Aligned with skills_guard.py INVISIBLE_CHARS — directional isolates
# (U+2066-U+2069) and invisible math operators (U+2062-U+2064) are real
# attack tools.
INVISIBLE_CHARS = frozenset({
    '\u200b',  # zero-width space
    '\u200c',  # zero-width non-joiner
    '\u200d',  # zero-width joiner
    '\u2060',  # word joiner
    '\u2062',  # invisible times
    '\u2063',  # invisible separator
    '\u2064',  # invisible plus
    '\ufeff',  # zero-width no-break space (BOM)
    '\u202a',  # left-to-right embedding
    '\u202b',  # right-to-left embedding
    '\u202c',  # pop directional formatting
    '\u202d',  # left-to-right override
    '\u202e',  # right-to-left override
    '\u2066',  # left-to-right isolate
    '\u2067',  # right-to-left isolate
    '\u2068',  # first strong isolate
    '\u2069',  # pop directional isolate
})


# Compiled pattern sets, indexed by scope.  Compiled once at import time;
# scan_for_threats() looks them up.
_COMPILED: dict[str, List[Tuple[re.Pattern, str]]] = {}


def _compile() -> None:
    """Compile pattern sets for each scope (all / context / strict).

    A pattern with scope="all" lands in every set.  A pattern with
    scope="context" lands in context + strict (context implies the
    strict scanners want it too).  Scope="strict" lands in strict only.
    """
    global _COMPILED
    if _COMPILED:
        return

    all_patterns: List[Tuple[re.Pattern, str]] = []
    context_patterns: List[Tuple[re.Pattern, str]] = []
    strict_patterns: List[Tuple[re.Pattern, str]] = []

    for pattern, pid, scope in _PATTERNS:
        compiled = re.compile(pattern, re.IGNORECASE)
        entry = (compiled, pid)
        if scope == "all":
            all_patterns.append(entry)
            context_patterns.append(entry)
            strict_patterns.append(entry)
        elif scope == "context":
            context_patterns.append(entry)
            strict_patterns.append(entry)
        elif scope == "strict":
            strict_patterns.append(entry)
        else:
            raise ValueError(f"threat_patterns: unknown scope {scope!r} for pattern {pid!r}")

    _COMPILED = {
        "all": all_patterns,
        "context": context_patterns,
        "strict": strict_patterns,
    }


_compile()


def scan_for_threats(content: str, scope: str = "context") -> List[str]:
    """Return a list of matched pattern IDs in ``content`` at the given scope.

    ``scope`` selects which pattern set to apply:

    - ``"all"`` (narrow): classic injection + exfil only — minimal false
      positives, suitable for any text.
    - ``"context"`` (default): adds promptware / C2 / role-play patterns —
      suitable for context files, memory entries, and tool results.
    - ``"strict"`` (broad): adds persistence / SSH backdoor / exfil-URL
      patterns — appropriate for user-mediated writes (memory tool,
      skills install) where false positives can be resolved interactively.

    Also checks for invisible unicode characters (returned as
    ``"invisible_unicode_U+XXXX"`` so the caller can surface the offending
    codepoint in a log line).

    Homoglyph defense: content with non-Latin characters in ASCII-letter
    positions is flagged as a potential homoglyph bypass attempt. LLMs
    interpret Cyrillic/Greek/fullwidth characters as their Latin equivalents,
    but regex scanners see the raw Unicode. An attacker can use this to
    evade pattern matching while the LLM still follows the injected text.
    """
    if not content:
        return []

    findings: List[str] = []

    # Invisible unicode — single pass through the content set, not 17
    # ``in`` lookups.
    char_set = set(content)
    invisible_hits = char_set & INVISIBLE_CHARS
    for ch in invisible_hits:
        findings.append(f"invisible_unicode_U+{ord(ch):04X}")

    # Homoglyph detection — flag non-Latin characters that visually mimic
    # ASCII letters. This catches Cyrillic 'і' (U+0456) used instead of
    # Latin 'i', Greek 'ι' (U+03B9) for 'i', fullwidth 'ｉ' (U+FF49) for 'i', etc.
    # The check is: if a non-Latin character has a category of "Ll" (letter, lowercase)
    # or "Lu" (letter, uppercase) and is NOT in the basic Latin range, it's suspicious.
    _LATIN_RANGE = set(range(0x0041, 0x005B)) | set(range(0x0061, 0x007B))  # A-Z, a-z
    for ch in content:
        cp = ord(ch)
        if cp in _LATIN_RANGE:
            continue  # Normal Latin character
        cat = unicodedata.category(ch)
        if cat.startswith("L") and cp > 0x007F:
            # Non-Latin letter — potential homoglyph
            script = unicodedata.script(ch) if hasattr(unicodedata, 'script') else "Unknown"
            # Only flag if it looks like a Latin letter (Cyrillic, Greek, fullwidth, etc.)
            if cp in _HOMOGLYPH_MAP:
                findings.append(f"homoglyph_U+{cp:04X}_{unicodedata.name(ch, 'UNKNOWN')}")
                break  # One finding is enough to flag the content

    # Threat patterns
    patterns = _COMPILED.get(scope)
    if patterns is None:
        raise ValueError(f"scan_for_threats: unknown scope {scope!r}")
    for compiled, pid in patterns:
        if compiled.search(content):
            findings.append(pid)

    return findings


def first_threat_message(content: str, scope: str = "strict") -> Optional[str]:
    """Return a human-readable error string for the first threat found, or None.

    Convenience wrapper used by paths that block on the first hit
    (memory tool writes, skills install) where the caller just needs a
    yes/no + a message.
    """
    findings = scan_for_threats(content, scope=scope)
    if not findings:
        return None
    pid = findings[0]
    if pid.startswith("invisible_unicode_"):
        codepoint = pid.replace("invisible_unicode_", "")
        return f"Blocked: content contains invisible unicode character {codepoint} (possible injection)."
    return (
        f"Blocked: content matches threat pattern '{pid}'. "
        f"Content is injected into the system prompt and must not contain "
        f"injection or exfiltration payloads."
    )


__all__ = [
    "INVISIBLE_CHARS",
    "scan_for_threats",
    "first_threat_message",
]
