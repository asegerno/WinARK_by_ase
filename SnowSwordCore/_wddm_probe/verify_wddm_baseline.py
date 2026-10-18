"""Static (kernel-free) oracle for the production WDDM *baseline* backend.

Answers, for one target driver image plus dxgkrnl.sys:

    DETECT    is_wddm / confidence / reason
    BASELINE  accepted? hits / confidence / writer RVA / dxgkrnl base
    SLOT n    each dxgkrnl baseline slot the backend recovers (RVA + source)

It runs the repository's real code: DetectWddmDriver, RecoverDxgkrnlDispatchBaseline
and everything they pull in, plus the production PE/disasm helpers.

The only host facility replaced is kernel-module address resolution
(`GetKernelModuleBase`): the harness answers it from the image's own PE
OptionalHeader (ImageBase / SizeOfImage), which is the "static harness"
convention already used by verify_dispatch_real.py.  LoadDispatchModuleContext
looks for dxgkrnl.sys at %SystemRoot%\\System32\\drivers\\dxgkrnl.sys, so the
caller must copy the real dxgkrnl.sys into a scratch %SystemRoot% first --
see run_wddm_baseline_probe.ps1 -- otherwise the baseline is rejected with
"[WDDM-BASELINE] Failed to load dxgkrnl.sys".

Usage:
    python _wddm_probe/verify_wddm_baseline.py <target.sys> [--no-build]

Scratch tooling for Phase 2; lives in _wddm_probe/ because the DSH file sandbox
only allows writes inside the SnowSwordCore workspace.
"""
from pathlib import Path
import argparse
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_common import (DEFAULT_FBC, ROOT, compile_program, declarations,
                          names, procedures, read)

OUT = Path(__file__).resolve().parent
WDDM = 'ring3/modules/KernelHook/DispatchWddm.inc'

PROLOGUE = r'''#include once "windows.bi"
#include once "crt/string.bi"
#include once "udis86.bi"
#include once "DispatchTypes_probe.bi"
Type TestLogger
    dummy As Integer
    Declare Sub PrintInfo(ByVal a As String, ByVal b As String, ByVal c As String)
    Declare Sub PrintLog(ByVal lvl As Integer, ByVal a As String, ByVal b As String, ByVal c As String)
    Declare Sub PrintWin32Error(ByVal a As String, ByVal b As String, ByVal c As String)
End Type
Sub TestLogger.PrintInfo(ByVal a As String, ByVal b As String, ByVal c As String)
    ' Only lines that answer the coverage question are surfaced.
    If InStr(c, "[WDDM-BASELINE]") OrElse InStr(c, "[MERGE]") OrElse _
       InStr(c, "[LOAD]") OrElse InStr(c, "[REJECT]") Then
        Print "  LOG " & c
    End If
End Sub
Sub TestLogger.PrintLog(ByVal lvl As Integer, ByVal a As String, ByVal b As String, ByVal c As String)
End Sub
Sub TestLogger.PrintWin32Error(ByVal a As String, ByVal b As String, ByVal c As String)
End Sub
Dim Shared MyLog As TestLogger

Function IRP_MJ_ToString(ByVal i As Integer) As String
    Return Str(i)
End Function

' ---- host facility replaced: kernel module base lookup -------------------
Const PROBE_MODULES_MAX = 8
Dim Shared g_probeModuleName(0 To PROBE_MODULES_MAX - 1) As String
Dim Shared g_probeModuleBase(0 To PROBE_MODULES_MAX - 1) As ULONG_PTR
Dim Shared g_probeModuleSize(0 To PROBE_MODULES_MAX - 1) As ULong
Dim Shared g_probeModuleCount As Integer = 0

Sub ProbeRegisterModule(ByVal modName As String, ByVal modBase As ULONG_PTR, ByVal modSize As ULong)
    If g_probeModuleCount >= PROBE_MODULES_MAX Then Return
    g_probeModuleName(g_probeModuleCount) = LCase(modName)
    g_probeModuleBase(g_probeModuleCount) = modBase
    g_probeModuleSize(g_probeModuleCount) = modSize
    g_probeModuleCount += 1
End Sub

Declare Function GetKernelModuleBase(ByVal ModuleName As WString Ptr, ByRef ModuleSize As ULong) As PVOID
Function GetKernelModuleBase(ByVal ModuleName As WString Ptr, ByRef ModuleSize As ULong) As PVOID
    Dim wanted As String = LCase(*ModuleName)
    For k As Integer = 0 To g_probeModuleCount - 1
        If g_probeModuleName(k) = wanted Then
            ModuleSize = g_probeModuleSize(k)
            Return Cast(PVOID, g_probeModuleBase(k))
        End If
    Next
    ModuleSize = 0
    Return NULL
End Function

' Loads an image and reports its PE ImageBase / SizeOfImage.
Declare Function ProbeLoadImage(ByVal imgPath As String, imgBuf() As UByte, _
    ByRef imgBase As ULONG_PTR, ByRef imgSize As ULong) As Boolean
Function ProbeLoadImage(ByVal imgPath As String, imgBuf() As UByte, _
    ByRef imgBase As ULONG_PTR, ByRef imgSize As ULong) As Boolean

    If Dir(imgPath) = "" Then Return False
    Dim h As Integer = FreeFile
    Open imgPath For Binary Access Read As #h
    Dim n As LongInt = LOF(h)
    If n < &H100 OrElse n > &H8000000 Then Close #h: Return False
    ReDim imgBuf(0 To n - 1)
    Get #h, , imgBuf()
    Close #h

    Dim dos As IMAGE_DOS_HEADER Ptr = Cast(IMAGE_DOS_HEADER Ptr, @imgBuf(0))
    If dos->e_magic <> &H5A4D Then Return False
    Dim nt As IMAGE_NT_HEADERS64 Ptr = _
        Cast(IMAGE_NT_HEADERS64 Ptr, @imgBuf(0) + dos->e_lfanew)
    If nt->Signature <> &H4550 Then Return False
    imgBase = Cast(ULONG_PTR, nt->OptionalHeader.ImageBase)
    imgSize = nt->OptionalHeader.SizeOfImage
    Return True
End Function
'''

EPILOGUE = r'''
' ============================ main ============================
Dim targetPath As String = Command(1)
If Dir(targetPath) = "" Then Print "missing target image: " & targetPath: End 2

Dim targetBuf() As UByte
Dim targetBase As ULONG_PTR
Dim targetSize As ULong
If ProbeLoadImage(targetPath, targetBuf(), targetBase, targetSize) = False Then
    Print "cannot load target image": End 2
End If

Dim dxgPath As String = Environ("SystemRoot") & "\System32\drivers\dxgkrnl.sys"
Dim dxgBuf() As UByte
Dim dxgBase As ULONG_PTR
Dim dxgSize As ULong
If ProbeLoadImage(dxgPath, dxgBuf(), dxgBase, dxgSize) = False Then
    Print "cannot load dxgkrnl.sys from " & dxgPath: End 2
End If

Dim targetName As String = targetPath
Dim slashPos As Integer = InStrRev(targetName, "\")
If slashPos > 0 Then targetName = Mid(targetName, slashPos + 1)

ProbeRegisterModule "dxgkrnl.sys", dxgBase, dxgSize
ProbeRegisterModule targetName, targetBase, targetSize

Print "TARGET " & targetPath
Print "  image_base=0x" & Hex(targetBase) & " image_size=0x" & Hex(targetSize)
Print "DXGKRNL " & dxgPath & " image_base=0x" & Hex(dxgBase) & _
      " image_size=0x" & Hex(dxgSize)

Dim ctx As DRIVER_DISPATCH_RECOVERY_CONTEXT
memset(@ctx, 0, SizeOf(ctx))
ctx.pDump = @targetBuf(0)
Dim targetLen As ULong = CULng(UBound(targetBuf))
ctx.FileSize = targetLen + 1
ctx.ImageBase = targetBase
ctx.ImageSize = targetSize
ctx.ModuleName = targetPath
ctx.IopInvalidDeviceRequest = 0
ctx.ModelKind = DispatchModelGenericWdm
ctx.ModelConfidence = 30

Dim isWddm As Boolean = DetectWddmDriver(ctx, ctx.ModelInfo)
Print "DETECT is_wddm=" & Str(isWddm) & _
      " confidence=" & Str(ctx.ModelInfo.Confidence) & _
      " reason=[" & ctx.ModelInfo.Reason & "] owner=[" & ctx.ModelInfo.FrameworkOwner & "]"

If isWddm Then
    ctx.ModelKind = DispatchModelWddm
    ctx.ModelConfidence = CULng(ctx.ModelInfo.Confidence)
End If

Dim recOut As DRIVER_DISPATCH_RECOVERY_OUTPUT
memset(@recOut, 0, SizeOf(recOut))
recOut.ModelKind = ctx.ModelKind
recOut.FrameworkKind = ctx.FrameworkKind
recOut.ModelConfidence = ctx.ModelConfidence

Dim baseline As WDDM_DISPATCH_BASELINE_OUTPUT
Dim accepted As Boolean = RecoverDxgkrnlDispatchBaseline(ctx, recOut, baseline)

Print "BASELINE accepted=" & Str(accepted) & _
      " hits=" & Str(baseline.HitCount) & _
      " confidence=" & Str(baseline.Confidence) & _
      " dxg_base=0x" & Hex(baseline.DxgkrnlBase) & _
      " writer_rva=0x" & Hex(baseline.WriterFunctionRva) & _
      " base_reg=" & Str(baseline.CandidateBaseReg) & _
      " tracked=" & Str(baseline.DriverObjectTracked) & _
      " uniform_default=" & Str(baseline.HasUniformDefault) & _
      " default_rva=0x" & Hex(baseline.DefaultRva) & _
      " default_slots=" & Str(baseline.DefaultSlotCount)

Dim validCount As ULong = 0
For i As Integer = 0 To IRP_MJ_MAXIMUM_FUNCTION
    If baseline.MajorFunction(i).Valid Then
        validCount += 1
        Print "SLOT " & Str(i) & " VALID rva=0x" & _
              Hex(baseline.MajorFunction(i).FunctionRva) & _
              " state=" & Str(baseline.MajorFunction(i).State) & _
              " owner=" & Str(baseline.MajorFunction(i).OwnerKind) & _
              " source=" & Str(baseline.MajorFunction(i).Source) & _
              " conf=" & Str(baseline.MajorFunction(i).Confidence)
    End If
Next
Print "BASELINE_VALID_SLOTS " & Str(validCount)
End 0
'''


def build(fbc):
    (OUT / 'DispatchTypes_probe.bi').write_text(
        read('ring3/headers/DispatchTypes.bi'), encoding='utf-8')
    bodies = procedures(read(WDDM))
    bodies += procedures(read('ring3/modules/KernelHook/DispatchPeUtils.inc'))
    bodies += procedures(read('ring3/modules/KernelHook/DispatchDisasm.inc'))
    print(f'procedures: {len(bodies)}; wddm={len(procedures(read(WDDM)))} -> '
          f'{", ".join(names(procedures(read(WDDM))))}')
    program = PROLOGUE + declarations(bodies) + '\n' + \
        '\n'.join(bodies) + '\n' + EPILOGUE
    exe, log = compile_program(fbc, OUT, 'wddm_baseline.bas', program)
    if exe is None:
        print('BUILD FAILED')
        print(log[-5000:])
        raise SystemExit(1)
    print(f'BUILD OK {exe}')
    return exe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=Path)
    parser.add_argument('--fbc', type=Path, default=DEFAULT_FBC)
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    exe = OUT / 'wddm_baseline.exe'
    if not args.no_build:
        exe = build(args.fbc)
    output = subprocess.run([str(exe), str(args.target)], capture_output=True,
                            text=True, encoding='utf-8', errors='replace')
    for line in output.stdout.splitlines():
        if line.startswith(('TARGET', 'DXGKRNL', '  image', 'DETECT', 'BASELINE',
                            'SLOT ', '  LOG')):
            print(line)
    if output.returncode:
        print('exit=' + str(output.returncode))
        print(output.stderr[-1200:])


if __name__ == '__main__':
    main()
