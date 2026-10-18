"""Remove the [PROBE-TRACE] diagnostics added while wiring #5, restoring the
two modules by re-applying their .pre-probefix backups (which contain neither the
trace lines nor any real fix), then re-applying the real probe fix.

The real fixes that must survive:
  - build_snowsword.py PATCHES: ModCUI.ParseArgv, DispatchOrchestrator
    (GetOriginalDispatchFunctionAddr/CoreModulePoolReset/CoreLoadModule),
    ModKernel.GetDriverDispatchFunctionList
  - ModCUI.Inc inlined --diag-log strip
  - FrmMain.frm + Release64 generated form: MyLog.Stop()

Usage: python _wddm_probe\\revert_traces.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(r"D:\GitHub Project\SnowSword")
SUFFIX = ".pre-probefix"

# (backup source, live target)
RESTORE = [
    (ROOT / "ring3/modules/ModCUI.Inc", ROOT / "ring3/modules/ModCUI.Inc" + SUFFIX),
    (ROOT / "ring3/forms/FrmMain.frm", ROOT / "ring3/forms/FrmMain.frm" + SUFFIX),
]

# files that only carry traces; restored from their own .pre-probefix if present,
# otherwise the trace lines are stripped textually.
TRACE_ONLY = [
    ROOT / "ring3/modules/KernelHook/DispatchOrchestrator.inc",
    ROOT / "ring3/modules/ModKernel.Inc",
]


def load(p: Path) -> tuple[str, str, bool]:
    raw = p.read_bytes()
    bom = raw.startswith(b"\xef\xbb\xbf")
    body = raw[3:] if bom else raw
    try:
        text = body.decode("utf-8")
        enc = "utf-8-sig" if bom else "utf-8"
    except UnicodeDecodeError:
        text = body.decode("gbk", "surrogateescape")
        enc = "gbk"
    return text.replace("\r\n", "\n"), enc, "\r\n" in text


def save(p: Path, lf: str, enc: str, crlf: bool) -> None:
    p.write_bytes((lf.replace("\n", "\r\n") if crlf else lf).encode(enc, "surrogateescape"))


def strip_traces(path: Path) -> int:
    """Remove every line whose comment or string literal carries the trace tag,
    plus the multi-line PrintLog statements that reference it."""
    text, enc, crlf = load(path)
    lines = text.split("\n")
    out: list[str] = []
    removed = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        tagged = "'[PROBE-TRACE]" in line or "PROBE-TRACE" in line or "[T" in line and "PrintLog" in line
        if tagged:
            # drop the whole statement: a comment line, or a PrintLog statement
            # possibly continued over the next lines with a trailing '_'
            removed += 1
            while out and out[-1].strip() == "" and len(out) > 1 and out[-2].strip() == "":
                break
            while i + 1 < len(lines) and lines[i].rstrip().endswith("_"):
                i += 1
                removed += 1
            i += 1
            continue
        out.append(line)
        i += 1
    save(path, "\n".join(out), enc, crlf)
    return removed


def main() -> int:
    # 1. restore the two files wholesale from their backups
    for live, backup in RESTORE:
        if not backup.exists():
            print(f"no backup for {live.name}, skipped")
            continue
        shutil.copy2(backup, live)
        print(f"restored {live.parent.name}/{live.name}")

    # 2. strip traces from the trace-only files
    for path in TRACE_ONLY:
        if not path.exists():
            print(f"missing {path}")
            continue
        n = strip_traces(path)
        print(f"stripped {n} trace line(s) from {path.name}")

    print("\nNow re-apply the real probe fix:")
    print(f"  python {Path(__file__).resolve().parent / 'apply_probe_fix.py'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
