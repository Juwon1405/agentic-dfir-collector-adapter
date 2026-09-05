#!/usr/bin/env python3
"""
Generate architecture PNGs for agentic-dfir-collector-adapter README.

Style brief: quiet luxury · dark theme · matches GitHub canvas-dark
(#0d1117) and the author's site palette.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from pathlib import Path

# Palette: quiet luxury / GitHub canvas-dark
BG          = "#0d1117"
BOX_FILL    = "#161b22"
TEXT_PRI    = "#e6edf3"
TEXT_SEC    = "#8b949e"

HOST        = "#c97064"   # muted coral
ADAPTER     = "#79a6dc"   # muted blue
ROOT        = "#7fb88f"   # muted green
DFIR_GREEN        = "#6db17b"   # muted green
MANIFEST    = "#b88dd3"   # muted purple

OUT = Path(__file__).parent.parent / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)


def _box(ax, x, y, w, h, color, *, title, lines, title_size=11.5, body_size=9.5):
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.25,rounding_size=0.6",
        linewidth=1.4, edgecolor=color, facecolor=BOX_FILL,
    )
    ax.add_patch(rect)
    ax.text(x + w/2, y + h - 2.0, title, ha="center", va="top",
            fontsize=title_size, fontweight="bold", color=color)
    start_y = y + h - 5.5
    for i, line in enumerate(lines):
        ax.text(x + w/2, start_y - i*2.0, line, ha="center", va="top",
                fontsize=body_size, color=TEXT_PRI)


def _arrow(ax, x1, y1, x2, y2, color=TEXT_SEC, label=None, label_offset=1.4):
    arr = FancyArrowPatch((x1, y1), (x2, y2),
        arrowstyle="-|>", mutation_scale=20,
        linewidth=1.8, color=color)
    ax.add_patch(arr)
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mx, my + label_offset, label, ha="center", va="bottom",
                fontsize=8.5, color=color, style="italic", fontweight="bold")


def _zone(ax, x, y, w, h, color, title, subtitle):
    rect = FancyBboxPatch((x, y), w, h,
        boxstyle="round,pad=0.5,rounding_size=1.0",
        linewidth=1.2, edgecolor=color, facecolor="none", linestyle="--")
    ax.add_patch(rect)
    ax.text(x + w/2, y + h - 1.6, title, ha="center", va="top",
            fontsize=12, fontweight="bold", color=color)
    ax.text(x + w/2, y + h - 4.0, subtitle, ha="center", va="top",
            fontsize=9, color=TEXT_SEC, style="italic")


def diagram_arch():
    fig, ax = plt.subplots(figsize=(16, 9), facecolor=BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 56)
    ax.axis("off")

    ax.text(50, 53.5, "agentic-dfir-collector-adapter  ·  end-to-end flow",
            ha="center", va="top", fontsize=16, fontweight="bold", color=TEXT_PRI)
    ax.text(50, 50.5, "incident host  ->  this adapter (analysis server)  ->  Agentic-DFIR",
            ha="center", va="top", fontsize=10.5, color=TEXT_SEC, style="italic")

    _zone(ax, 1.5, 7, 22, 41, HOST, "1. Incident host", "short-lived, no install")
    _box(ax, 3.5, 26, 18, 14, HOST, title="Velociraptor agent",
         lines=["OS-matched binary", "Win · Linux · macOS",
                "1x execution", "no agent install"])
    _box(ax, 3.5, 10, 18, 12, "#a8856a", title="evidence.zip",
         lines=["Velociraptor", "offline-collector", "output format"])
    _arrow(ax, 12.5, 26, 12.5, 22, color=TEXT_SEC)

    _zone(ax, 26, 7, 46, 41, ADAPTER, "2. Analysis server",
          "Linux or macOS · install once")
    _box(ax, 28, 26, 19, 14, ADAPTER, title="dfir-collector-adapter",
         lines=["classify artifacts", "safe-path stream copy",
                "SHA-256 each file", "write manifest.json"])
    _box(ax, 51, 26, 19, 14, ROOT, title="evidence_root/",
         lines=["Prefetch   Amcache", "Registry   EventLogs",
                "Browser    WebLogs", "MFT  LNK  Other"])
    _arrow(ax, 47, 33, 51, 33, color=ADAPTER, label="layout", label_offset=1.5)
    _box(ax, 28, 11, 42, 11, MANIFEST, title="manifest 1.2  +  SHA-256 index",
         lines=["chain-of-custody seed",
                "case_id  ·  source  ·  source_members",
                "consumed by Agentic-DFIR as audit entry 0"])
    _arrow(ax, 37, 26, 37, 22, color=MANIFEST)
    _arrow(ax, 60, 26, 60, 22, color=MANIFEST)
    _arrow(ax, 23.5, 33, 28, 33, color=HOST,
           label="SCP / SMB / USB", label_offset=1.5)

    _zone(ax, 74.5, 7, 24, 41, DFIR_GREEN, "3. Agentic-DFIR", "same analysis server")
    _box(ax, 76.5, 26, 20, 14, DFIR_GREEN, title="dfir_agent",
         lines=["reads evidence_root", "runs playbook v3",
                "typed read-only MCP tools", "SHA-256 audit chain"])
    _box(ax, 76.5, 10, 20, 14, "#9bb87f", title="findings.json",
         lines=["report.md", "audit.jsonl",
                "extends chain-of-custody", "from manifest seed"])
    _arrow(ax, 86.5, 26, 86.5, 24, color=DFIR_GREEN)
    _arrow(ax, 72, 33, 76.5, 33, color=DFIR_GREEN, label="read", label_offset=1.5)

    ax.text(50, 4.0,
            "the adapter installs ONCE on the analysis server  ·  "
            "Velociraptor binaries shipped to each incident host on demand",
            ha="center", va="top", fontsize=10, color=TEXT_SEC, style="italic")
    ax.text(50, 1.5,
            "no incident-host install  ·  stdlib-only Python  ·  full test suite  ·  MIT",
            ha="center", va="top", fontsize=9, color=TEXT_SEC)

    plt.tight_layout()
    out = OUT / "arch.png"
    plt.savefig(out, dpi=150, bbox_inches="tight",
                facecolor=BG, edgecolor="none")
    plt.close()
    print(f"  ok  {out.name}")


def diagram_roadmap():
    fig, ax = plt.subplots(figsize=(15, 4.5), facecolor=BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 32)
    ax.axis("off")

    ax.text(50, 29.5, "agentic-dfir-collector-adapter  ·  phase roadmap",
            ha="center", va="top", fontsize=15, fontweight="bold", color=TEXT_PRI)

    phases = [
        ("v1.0.1", "current",
         ["Velociraptor ZIP", "  to evidence_root",
          "manifest 1.2", "source-member provenance"],
         ADAPTER, True),
        ("v1.1", "next",
         ["sidecar generation", "PECmd · AmcacheParser",
          "EvtxECmd auto-invoke", "when available locally"],
         "#5bc4b8", False),
        ("v1.2", "later",
         ["Velociraptor results/", "parsed-artifact JSON",
          "merged into manifest"],
         MANIFEST, False),
        ("v1.3", "later",
         ["macOS + Linux", "artifact coverage",
          "parity with Windows"],
         TEXT_SEC, False),
    ]

    x_start = 4
    box_w = 22
    gap = 2

    for i, (ver, status, lines, color, is_current) in enumerate(phases):
        x = x_start + i * (box_w + gap)
        title_bar = FancyBboxPatch((x, 18), box_w, 5,
            boxstyle="round,pad=0.1,rounding_size=0.4",
            linewidth=0, facecolor=color)
        ax.add_patch(title_bar)
        ax.text(x + box_w/2, 20.5, f"{ver}  ·  {status}",
                ha="center", va="center", fontsize=11.5,
                fontweight="bold", color="#0d1117")
        body_fill = BOX_FILL if not is_current else "#1d2733"
        body = FancyBboxPatch((x, 5), box_w, 12,
            boxstyle="round,pad=0.2,rounding_size=0.5",
            linewidth=1.0, edgecolor=color, facecolor=body_fill)
        ax.add_patch(body)
        for j, line in enumerate(lines):
            ax.text(x + box_w/2, 14.5 - j*1.9, line,
                    ha="center", va="top",
                    fontsize=9.5, color=TEXT_PRI)
        if i < len(phases) - 1:
            _arrow(ax, x + box_w + 0.2, 20.5,
                   x + box_w + gap - 0.2, 20.5, color=TEXT_SEC)

    ax.text(50, 1.5,
            "adapter is intentionally narrow — one clear job, plus thin parser sidecar invocation later",
            ha="center", va="top", fontsize=9.5, color=TEXT_SEC, style="italic")

    plt.tight_layout()
    out = OUT / "roadmap.png"
    plt.savefig(out, dpi=150, bbox_inches="tight",
                facecolor=BG, edgecolor="none")
    plt.close()
    print(f"  ok  {out.name}")


if __name__ == "__main__":
    print("[generating dark-theme adapter diagrams]")
    diagram_arch()
    diagram_roadmap()
    print(f"\ndone -> {OUT}")
