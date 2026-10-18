"""Fix the two defects that make the --diag-log probe unusable.

Defect 1 (blocking): ModLog's InitLog reads "--diag-log <dir>" out of the raw
    command line but never removes it. ParseArgv then sees the flag as a
    top-level argument and the run dies with
    "Unknown argument '--diag-log'. Use '<category> <action> --help' for usage."
    Fix: strip the option from g_SingleCommand inside ParseArgv, right after the
    -c string was captured. InitLog runs later and reads Command(), so it still
    sees the flag and still resolves the log directory.

Defect 2 (silent, but costs the whole measurement): the single-shot branch calls
    ExitProcess() without stopping the logger's background thread, so the log
    file is created and left empty.
    Fix: MyLog.Stop() before ExitProcess.

Propagation model (learned the hard way -- do not "simplify" this):

  * build_snowsword.py deletes ring3/dsh_build and re-copies it from
    ring3/Release64 on EVERY build. Anything patched only in dsh_build is lost.
  * ModCUI.Inc's ParseArgv is added to build_snowsword.py's PATCHES, so the
    generated module is refreshed from the source on each build.
  * FrmMain_Shown must NEVER go through PATCHES: the IDE-generated form qualifies
    control references (ListView1.hWnd -> FrmMain.ListView1.hWnd), so copying the
    .frm procedure verbatim fails with "Variable not declared, ListView1". Its
    edit is therefore applied directly to the generated copy in
    ring3/Release64/CODEGEN_SnowSword_FrmMain_FORM.inc, which the build then
    copies forward.

Encoding and line endings are detected per file. Matching happens on
LF-normalized text and the original line ending is restored on write.

Usage:
  python _wddm_probe\\apply_probe_fix.py            # apply
  python _wddm_probe\\apply_probe_fix.py --revert   # restore from .pre-probefix
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(r"D:\GitHub Project\SnowSword")
RELEASE = ROOT / "ring3/Release64"
BUILD = ROOT / "ring3/dsh_build"
BACKUP_SUFFIX = ".pre-probefix"

MODCUI_SRC = ROOT / "ring3/modules/ModCUI.Inc"
FRMMAIN_SRC = ROOT / "ring3/forms/FrmMain.frm"
FRMMAIN_GEN = RELEASE / "CODEGEN_SnowSword_FrmMain_FORM.inc"
FRMMAIN_GEN_BUILD = BUILD / "CODEGEN_SnowSword_FrmMain_FORM.inc"

# ---------------------------------------------------------------------------
# Defect 1. The strip logic is INLINED into ParseArgv rather than living in a
# helper Sub. build_snowsword.py appends a "new" procedure to the END of the
# generated module, and FreeBASIC resolves Subs in file order (plus VFB hoists no
# forward declarations for them), so a helper called from ParseArgv -- which sits
# near the top -- cannot compile. Inlining keeps the edit inside one procedure.
# Locals carry a probe prefix so they cannot collide with a name already used in
# ParseArgv.
# ---------------------------------------------------------------------------
STRIP_INLINE = '''                ' [PROBE-FIX] 剥掉 --diag-log <目录>。
                ' ModLog.InitLog 会用 Command() 原文里的该字面量定位日志目录，但不会把它
                ' 从命令行里去掉；-c 字符串的分词器随后会把它判成未知参数
                ' ("Unknown argument '--diag-log'")，整次运行直接退出。这里在捕获之后、
                ' 任何分词发生之前删除它。InitLog 读的是 Command() 原文，仍能取到目录。
                Dim probePos As Integer = InStr(LCase(g_SingleCommand), "--diag-log")
                While probePos > 0
                    Dim probeHead As String = Left(g_SingleCommand, probePos - 1)
                    Dim probeTail As String = LTrim(Mid(g_SingleCommand, probePos + Len("--diag-log")))
                    Dim probeSp As Integer = InStr(probeTail, " ")
                    Dim probeRest As String
                    If probeSp > 0 Then
                        probeRest = Mid(probeTail, probeSp + 1)
                    Else
                        probeRest = ""
                    End If
                    If Len(probeHead) > 0 AndAlso Right(probeHead, 1) = " " Then probeHead = RTrim(probeHead)
                    If Len(probeRest) > 0 Then
                        g_SingleCommand = probeHead & " " & LTrim(probeRest)
                    Else
                        g_SingleCommand = probeHead
                    End If
                    probePos = InStr(LCase(g_SingleCommand), "--diag-log")
                Wend
'''

EDITS: list[tuple[Path, str, str]] = [
    # 1. strip the option from the captured -c string.
    (MODCUI_SRC,
     "\n                g_CuiMode = True\n                i += 1\n            End If\n",
     "\n                g_CuiMode = True\n" + STRIP_INLINE + "                i += 1\n            End If\n"),
]

# 2. flush the logger's background thread before the process dies.
FLUSH_OLD = ("        If IsDriverLoaded Then UninitDriver()\n        \n"
             "        ExitProcess(exitCode)")
FLUSH_NEW = ("        If IsDriverLoaded Then UninitDriver()\n        \n"
             "        ' [PROBE-FIX] 单次模式下 ExitProcess 会直接终止进程，后台日志线程来不及\n"
             "        ' 落盘，日志文件会被创建但内容为空。先安全停止日志线程再退出。\n"
             "        MyLog.Stop()\n        \n        ExitProcess(exitCode)")
for _p in (FRMMAIN_SRC, FRMMAIN_GEN, FRMMAIN_GEN_BUILD):
    EDITS.append((_p, FLUSH_OLD, FLUSH_NEW))


def load(path: Path) -> tuple[str, str, bool]:
    raw = path.read_bytes()
    bom = raw.startswith(b"\xef\xbb\xbf")
    body = raw[3:] if bom else raw
    try:
        text = body.decode("utf-8")
        enc = "utf-8-sig" if bom else "utf-8"
    except UnicodeDecodeError:
        text = body.decode("gbk", "surrogateescape")
        enc = "gbk"
    crlf = "\r\n" in text
    return text.replace("\r\n", "\n"), enc, crlf


def save(path: Path, lf_text: str, enc: str, crlf: bool) -> None:
    path.write_bytes((lf_text.replace("\n", "\r\n") if crlf else lf_text)
                     .encode(enc, "surrogateescape"))


def revert() -> int:
    seen: set[Path] = set()
    for path, _old, _new in EDITS:
        if path in seen:
            continue
        seen.add(path)
        dest = path.with_name(path.name + BACKUP_SUFFIX)
        if not dest.exists():
            print(f"  no backup for {path.name} ({path.parent.name}), skipped")
            continue
        shutil.copy2(dest, path)
        print(f"  restored {path.parent.name}/{path.name}")
    print("revert done -- rebuild before running anything")
    return 0


def main() -> int:
    if "--revert" in sys.argv:
        return revert()

    backups_done: set[Path] = set()
    changed = 0
    for path, old, new in EDITS:
        if not path.exists():
            print(f"{path.name} ({path.parent.name}): absent, skipped")
            continue
        text, enc, crlf = load(path)
        if new in text:
            print(f"{path.name} ({path.parent.name}): already applied, skipped")
            continue
        n = text.count(old)
        if n != 1:
            raise SystemExit(
                f"{path.name} ({path.parent.name}): anchor matched {n} times (expected 1) "
                f"-- source changed since this script was written. No edits made to this file."
            )
        if path not in backups_done:
            dest = path.with_name(path.name + BACKUP_SUFFIX)
            if not dest.exists():
                shutil.copy2(path, dest)
                print(f"  backup written: {dest.parent.name}/{dest.name}")
            else:
                print(f"  backup already present, kept: {dest.parent.name}/{dest.name}")
            backups_done.add(path)
        save(path, text.replace(old, new, 1), enc, crlf)
        print(f"{path.name} ({path.parent.name}): patched [{enc}, {'CRLF' if crlf else 'LF'}]")
        changed += 1

    if changed == 0:
        print("nothing to do (all edits already applied)")
    else:
        print(f"\n{changed} edit(s) applied.")
        print("Next: python validation\\build_snowsword.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
