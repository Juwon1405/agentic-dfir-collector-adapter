"""
Map Velociraptor artifact names to evidence_root subdirectories.

Classification rules are checked in order; the first match wins.
Order from most-specific to most-generic. Patterns use word-boundary
anchors where possible to avoid false positives.
"""
from __future__ import annotations

import re

# Target evidence_root subdirectory names.
EVIDENCE_LAYOUT: dict[str, str] = {
    "prefetch":   "Prefetch",
    "amcache":    "Amcache",
    "registry":   "Registry",
    "eventlog":   "EventLogs",
    "browser":    "Browser",
    "mft":        "MFT",
    "weblog":     "WebLogs",
    "auth":       "AuthLogs",
    "memory":     "Memory",
    "lnk":        "LNK",
    "jumplist":   "JumpLists",
    "usnjrnl":    "USNJournal",
    "powershell": "PowerShell",
    "other":      "Other",
}


# Order is significant. Specific file-extension and path patterns first.
_CLASSIFIERS: list[tuple[str, re.Pattern[str]]] = [
    # ── extensions (most specific) ────────────────────────────────────────
    ("prefetch",   re.compile(r"\.pf$",                          re.IGNORECASE)),
    ("eventlog",   re.compile(r"\.evtx?$",                       re.IGNORECASE)),
    ("memory",     re.compile(r"\.(mem|dmp|vmem|raw)$",          re.IGNORECASE)),
    ("lnk",        re.compile(r"\.lnk$",                         re.IGNORECASE)),
    ("jumplist",   re.compile(r"(automaticDestinations|customDestinations)-ms$", re.IGNORECASE)),

    # ── browser paths must come before bare-name registry rules ───────────
    ("browser",    re.compile(r"(Chrome|Edge|Firefox|Safari|Brave|Opera|Chromium).*?(History|Cookies|Cache|Login\s?Data|Web\s?Data|Bookmarks|Top\s?Sites)\b", re.IGNORECASE)),
    ("browser",    re.compile(r"\bplaces\.sqlite\b",             re.IGNORECASE)),
    ("browser",    re.compile(r"(Mozilla|Firefox)/Profiles",     re.IGNORECASE)),

    # ── named files (exact basename match anchored to end of path) ────────
    ("amcache",    re.compile(r"(^|/)Amcache\.hve$",             re.IGNORECASE)),
    ("registry",   re.compile(r"(^|/)(NTUSER\.DAT|UsrClass\.dat|SOFTWARE|SECURITY|SYSTEM|SAM|DEFAULT)$", re.IGNORECASE)),
    ("registry",   re.compile(r"(^|/)Shellbags?\b",              re.IGNORECASE)),
    ("mft",        re.compile(r"(^|/)\$MFT$",                    re.IGNORECASE)),
    ("usnjrnl",    re.compile(r"\$UsnJrnl",                      re.IGNORECASE)),
    ("powershell", re.compile(r"ConsoleHost_history\.txt$",      re.IGNORECASE)),

    # ── memory dump path hints ────────────────────────────────────────────
    ("memory",     re.compile(r"memory[._-]?dump",               re.IGNORECASE)),

    # ── log files (extension + context) ───────────────────────────────────
    ("weblog",     re.compile(r"u_ex\d+\.log$",                  re.IGNORECASE)),  # IIS
    ("weblog",     re.compile(r"/(access|http)[A-Za-z0-9._-]*\.log$",
                                                                 re.IGNORECASE)),
    ("weblog",     re.compile(r"/(nginx|apache2?|httpd)/[^/]*\.log$",
                                                                 re.IGNORECASE)),
    ("auth",       re.compile(r"/(auth\.log|secure|wtmp|btmp|lastlog)(\.\d+)?(\.gz)?$",
                                                                 re.IGNORECASE)),
]


def classify_artifact(member_name: str) -> str:
    """
    Pick a category name (key of EVIDENCE_LAYOUT) for the given ZIP member path.
    Falls back to "other" when nothing matches.
    """
    for category, pattern in _CLASSIFIERS:
        if pattern.search(member_name):
            return category
    return "other"
