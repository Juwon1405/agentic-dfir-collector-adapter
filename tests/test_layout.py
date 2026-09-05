"""Tests for layout.classify_artifact() — the dispatcher."""
from dfir_collector_adapter.layout import classify_artifact, EVIDENCE_LAYOUT


def test_prefetch_classified_as_prefetch():
    assert classify_artifact("uploads/auto/C:/Windows/Prefetch/SVCHOST.EXE-123.pf") == "prefetch"


def test_amcache_classified_as_amcache():
    assert classify_artifact("uploads/auto/C:/Windows/AppCompat/Programs/Amcache.hve") == "amcache"


def test_security_hive_classified_as_registry():
    assert classify_artifact("uploads/auto/C:/Windows/System32/config/SECURITY") == "registry"


def test_sam_hive_classified_as_registry():
    assert classify_artifact("uploads/auto/C:/Windows/System32/config/SAM") == "registry"


def test_evtx_classified_as_eventlog():
    assert classify_artifact("uploads/auto/C:/Windows/System32/winevt/Logs/Security.evtx") == "eventlog"


def test_chrome_history_classified_as_browser():
    assert classify_artifact("uploads/auto/C:/Users/x/AppData/Local/Google/Chrome/User Data/Default/History") == "browser"


def test_firefox_places_sqlite_classified_as_browser():
    assert classify_artifact("uploads/auto/C:/Users/x/AppData/Roaming/Mozilla/Firefox/Profiles/abc/places.sqlite") == "browser"


def test_lnk_classified_as_lnk():
    assert classify_artifact("uploads/auto/C:/Users/x/Recent/foo.lnk") == "lnk"


def test_jumplist_classified_as_jumplist():
    assert classify_artifact(
        "uploads/auto/C:/Users/x/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/abc.automaticDestinations-ms"
    ) == "jumplist"


def test_iis_log_classified_as_weblog():
    assert classify_artifact("uploads/auto/inetpub/logs/LogFiles/W3SVC1/u_ex240509.log") == "weblog"


def test_nginx_log_classified_as_weblog():
    assert classify_artifact("uploads/auto/var/log/nginx/access_2024.log") == "weblog"


def test_linux_auth_classified_as_auth():
    assert classify_artifact("uploads/auto/var/log/auth.log") == "auth"


def test_memory_dump_classified_as_memory():
    assert classify_artifact("uploads/memory.dmp") == "memory"
    assert classify_artifact("uploads/memory_dump.raw") == "memory"


def test_unknown_falls_back_to_other():
    assert classify_artifact("uploads/random/unknown.bin") == "other"


def test_every_category_is_reachable_from_a_sample_name():
    """
    Every category declared in EVIDENCE_LAYOUT must be reachable from at least
    one realistic Velociraptor member name. Catches the case where a key is
    added to the layout map but no classifier ever produces it.
    """
    samples_per_category = {
        "prefetch":   "uploads/auto/C:/Windows/Prefetch/CMD.EXE-1.pf",
        "amcache":    "uploads/auto/C:/Windows/AppCompat/Programs/Amcache.hve",
        "registry":   "uploads/auto/C:/Windows/System32/config/SYSTEM",
        "eventlog":   "uploads/auto/C:/Windows/System32/winevt/Logs/System.evtx",
        "browser":    "uploads/auto/C:/Users/x/AppData/Local/Google/Chrome/User Data/Default/History",
        "mft":        "uploads/auto/C:/$MFT",
        "weblog":     "uploads/auto/var/log/nginx/access.log",
        "auth":       "uploads/auto/var/log/auth.log",
        "memory":     "uploads/memory.dmp",
        "lnk":        "uploads/auto/C:/Users/x/Recent/foo.lnk",
        "jumplist":   "uploads/auto/Recent/AutomaticDestinations/abc.automaticDestinations-ms",
        "usnjrnl":    "uploads/auto/C:/$Extend/$UsnJrnl",
        "powershell": "uploads/auto/C:/Users/x/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt",
        "other":      "uploads/auto/random/unknown.bin",
    }
    assert set(samples_per_category) == set(EVIDENCE_LAYOUT), (
        "samples_per_category must cover exactly the EVIDENCE_LAYOUT keys; "
        "if you added a new category, add a sample here too."
    )
    for category, sample_name in samples_per_category.items():
        assert classify_artifact(sample_name) == category, (
            f"sample {sample_name!r} did not classify to {category}"
        )
