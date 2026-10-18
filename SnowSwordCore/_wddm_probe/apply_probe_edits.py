"""Prepare the Phase 2 WDDM coverage probe (one-shot, idempotent, minimal).

Two edits, both in D:\\GitHub Project\\SnowSword:

1. ring3/modules/ModLog.Inc -- [DIAG-PROBE] block. `InitLog()` gains a single
   opt-in branch: if the command line contains the literal
   `--diag-log <dir>` marker, the logger's existing file sink is switched on.
   Without the marker the branch is not taken and behaviour is unchanged.
   The whole block is self-contained inside InitLog()'s body on purpose: VFB
   hoists top-level Const/Dim/Declare into CODEGEN_SnowSword_DECLARES.inc, and
   staying inside a procedure means no DECLARES edit is needed.
   Encoding preserved: UTF-8 with BOM, CRLF.
   A .pre-diagprobe backup is written next to it.

2. validation/build_snowsword.py -- add the missing source->CODEGEN propagation:
   - DispatchWddm.inc  (19 procedures)  <-- the gap that would otherwise make a
     source edit invisible to the CLI build (false regression)
   - ModLog.Inc        (InitLog)        <-- carries the DIAG-PROBE block

Idempotent: re-running reports "already present" instead of duplicating.
Run with --check to only report, changing nothing.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(r'D:\GitHub Project\SnowSword')
MODLOG = ROOT / 'ring3/modules/ModLog.Inc'
BUILDER = ROOT / 'validation/build_snowsword.py'
BACKUP_SUFFIX = '.pre-diagprobe'

WDDM_PROCS = [
    ('Sub', 'ClearWddmBaselineCandidate'),
    ('Function', 'WddmMajorOffsetToIndex'),
    ('Sub', 'ClearWddmDispatchBaseline'),
    ('Function', 'SameWddmBaselineTargets'),
    ('Function', 'ScoreWddmBaselineTieBreaker'),
    ('Sub', 'ConsiderWddmBaselineCandidate'),
    ('Sub', 'ApplyWddmUniformDefault'),
    ('Function', 'IsKnownKmdodVersion'),
    ('Function', 'DetectWddmDriver'),
    ('Sub', 'ScanWddmReachableFunction'),
    ('Function', 'ScanCallbackTableReferences'),
    ('Function', 'ScanForDxgkrnlImport'),
    ('Function', 'RecoverDxgkrnlDispatchBaseline'),
    ('Function', 'ScanDxgkrnlRuntimeFunctionsForBaseline'),
    ('Sub', 'TrackDriverObjectRegister'),
    ('Function', 'ScanDxgkrnlBaselineFunction'),
    ('Function', 'ScoreWddmBaselineCandidate'),
    ('Sub', 'MergeWddmDispatchBaseline'),
    ('Sub', 'MergeWddmDispatchResult'),
]

OLD_INITLOG = """    MyLog.SetFilterLevel(LOG_DEBUG)

    ' \u6240\u6709 PrintLog \u90fd\u77ac\u95f4\u5b8c\u6210\uff0c\u4e0d\u5f71\u54cd\u6027\u80fd"""

NEW_INITLOG = """    MyLog.SetFilterLevel(LOG_DEBUG)

    ' [DIAG-PROBE] \u4ec5\u5728\u663e\u5f0f\u8bf7\u6c42\u65f6\u989d\u5916\u5199\u6587\u4ef6\uff08\u9ed8\u8ba4\u8def\u5f84\u4e0d\u8fdb\u5165\u672c\u5206\u652f\uff09
    Dim diagCmd As String = Command()
    Dim diagMarker As String = "--diag-log "
    Dim diagPos As Integer = InStr(LCase(diagCmd), diagMarker)
    If diagPos > 0 Then
        Dim diagRest As String = Trim(Mid(diagCmd, diagPos + Len(diagMarker)))
        Dim diagSpace As Integer = InStr(diagRest, " ")
        Dim diagDir As String
        If diagSpace > 0 Then
            diagDir = Left(diagRest, diagSpace - 1)
        Else
            diagDir = diagRest
        End If
        If Len(diagDir) > 0 Then
            If Dir(diagDir, 16) = "" Then MkDir diagDir
            If Dir(diagDir, 16) <> "" Then
                MyLog.SetLogPath diagDir
                MyLog.SetAppend True
                MyLog.SetOutput(True, True)
            End If
        End If
    End If

    ' \u6240\u6709 PrintLog \u90fd\u77ac\u95f4\u5b8c\u6210\uff0c\u4e0d\u5f71\u54cd\u6027\u80fd"""

BUILDER_ANCHOR = """    ('ring3/modules/KernelHook/DispatchOrchestrator.inc',
     'CODEGEN_SnowSword_DispatchOrchestrator_MODULE.inc',
     [('Function', 'GetOriginalDispatchFunctionAddr'),
      ('Sub', 'CoreModulePoolReset'), ('Function', 'CoreLoadModule')]),
]"""


def builder_addition() -> str:
    lines = ["    ('ring3/modules/KernelHook/DispatchWddm.inc',",
             "     'CODEGEN_SnowSword_DispatchWddm_MODULE.inc',",
             "     ["]
    for index, (kind, name) in enumerate(WDDM_PROCS):
        comma = ',' if index < len(WDDM_PROCS) - 1 else ']),'
        lines.append(f"      ('{kind}', '{name}'){comma}")
    lines.append("    ('ring3/modules/ModLog.Inc', 'CODEGEN_SnowSword_ModLog_MODULE.inc',")
    lines.append("     [('Sub', 'InitLog')]),")
    lines.append("]")
    return '\n'.join(lines)


def patch_modlog(check: bool) -> str:
    raw = MODLOG.read_bytes()
    bom = raw.startswith(b'\xef\xbb\xbf')
    text = raw.decode('utf-8-sig')
    if 'DIAG-PROBE' in text:
        return 'ModLog.Inc: DIAG-PROBE already present (no change)'
    # The source files are CRLF; the literals above are LF.  Normalise before
    # matching, and restore CRLF on write.
    text = text.replace('\r\n', '\n')
    if OLD_INITLOG not in text:
        return 'ModLog.Inc: FAILED -- InitLog() body anchor not found (no change)'
    if check:
        return 'ModLog.Inc: would insert the DIAG-PROBE block into InitLog()'
    new_text = text.replace(OLD_INITLOG, NEW_INITLOG, 1)
    backup = MODLOG.with_name(MODLOG.name + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(MODLOG, backup)
    MODLOG.write_bytes((b'\xef\xbb\xbf' if bom else b'') +
                       new_text.replace('\n', '\r\n').encode('utf-8'))
    return (f'ModLog.Inc: DIAG-PROBE block inserted into InitLog() '
            f'(backup {backup.name})')


def patch_builder(check: bool) -> str:
    text = BUILDER.read_text(encoding='utf-8')
    if 'DispatchWddm.inc' in text and "'InitLog'" in text:
        return 'build_snowsword.py: WDDM + ModLog propagation already present (no change)'
    if BUILDER_ANCHOR not in text:
        return 'build_snowsword.py: FAILED -- PATCHES anchor not found (no change)'
    if check:
        return 'build_snowsword.py: would add DispatchWddm.inc (19 procs) + ModLog.Inc'
    backup = BUILDER.with_name(BUILDER.name + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(BUILDER, backup)
    BUILDER.write_text(text.replace(BUILDER_ANCHOR, builder_addition(), 1),
                       encoding='utf-8')
    return f'build_snowsword.py: added DispatchWddm.inc (19 procs) + ModLog.Inc (backup {backup.name})'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--revert', action='store_true')
    args = parser.parse_args()

    if args.revert:
        for target in (MODLOG, BUILDER):
            backup = target.with_name(target.name + BACKUP_SUFFIX)
            if backup.exists():
                shutil.copy2(backup, target)
                print(f'reverted {target.name} from {backup.name}')
            else:
                print(f'no backup for {target.name}')
        return 0

    results = [patch_modlog(args.check), patch_builder(args.check)]
    failed = False
    for line in results:
        print('  ' + line)
        if 'FAILED' in line:
            failed = True
    print('OK' if not failed else 'INCOMPLETE')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
