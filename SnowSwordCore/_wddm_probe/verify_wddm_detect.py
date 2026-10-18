"""Static (kernel-free) oracle for the production WDDM *detection* backend.

Answers one question per image: does `DetectWddmDriver` classify it as WDDM?

It runs the repository's real detection code (DispatchWddm.inc) plus the
production PE helpers (DispatchPeUtils.inc), disassembler helpers
(DispatchDisasm.inc) and the shared types.  No kernel driver is loaded and no
image is modified.  The whole PE/disasm modules are included (unused procedures
are dead code) so the dependency closure does not have to be tracked by hand.

Usage:
    python _wddm_probe/verify_wddm_detect.py <image> [<image> ...]
    python _wddm_probe/verify_wddm_detect.py --no-build <image> ...

Scratch tooling for Phase 2; lives in _wddm_probe/ because the DSH file sandbox
only allows writes inside the SnowSwordCore workspace.
"""
from pathlib import Path
import argparse
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_common import (DEFAULT_FBC, compile_program, declarations,
                          names, procedures, read)

OUT = Path(__file__).resolve().parent
WDDM = 'ring3/modules/KernelHook/DispatchWddm.inc'

# Detection-side closure inside DispatchWddm.inc (verified by line map):
#   lines 1-421     the baseline helpers + IsKnownKmdodVersion
#   lines 453-1179  DetectWddmDriver / ScanWddmReachableFunction /
#                   ScanCallbackTableReferences / ScanForDxgkrnlImport
#   lines 1897-2034 ScoreWddmBaselineCandidate -- pulled in by a diagnostic
#                   line inside ScanForDxgkrnlImport; harmless to include.
WDDM_DETECT_REGIONS = ((1, 421), (453, 1179), (1897, 2034))

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
    If InStr(c, "[WDDM-EVIDENCE]") Then Print "  LOG " & c
End Sub
Sub TestLogger.PrintLog(ByVal lvl As Integer, ByVal a As String, ByVal b As String, ByVal c As String)
End Sub
Sub TestLogger.PrintWin32Error(ByVal a As String, ByVal b As String, ByVal c As String)
End Sub
Dim Shared MyLog As TestLogger
Function IRP_MJ_ToString(ByVal i As Integer) As String
    Return Str(i)
End Function
Declare Function GetKernelModuleBase(ByVal ModuleName As WString Ptr, ByRef ModuleSize As ULong) As PVOID
Function GetKernelModuleBase(ByVal ModuleName As WString Ptr, ByRef ModuleSize As ULong) As PVOID
    ' Host facility replaced: detection only reads the caller-supplied image
    ' buffer and never resolves a kernel module, so the lookup may be inert.
    ModuleSize = 0
    Return NULL
End Function
'''

EPILOGUE = r'''
Dim imagePath As String = Command(1)
If Dir(imagePath) = "" Then Print "missing image: " & imagePath: End 2
Dim handle As Integer = FreeFile
Open imagePath For Binary As #handle
Dim length As LongInt = LOF(handle)
If length < &H100 OrElse length > &H7000000 Then Print "bad image size": End 2
Dim image(0 To length - 1) As UByte
Get #handle, , image()
Close #handle

Dim dos As IMAGE_DOS_HEADER Ptr = Cast(IMAGE_DOS_HEADER Ptr, @image(0))
Dim nt As IMAGE_NT_HEADERS64 Ptr = Cast(IMAGE_NT_HEADERS64 Ptr, @image(0) + dos->e_lfanew)

Dim ctx As DRIVER_DISPATCH_RECOVERY_CONTEXT
memset(@ctx, 0, SizeOf(ctx))
ctx.pDump = @image(0)
ctx.FileSize = CULng(length)
ctx.ImageBase = Cast(ULONG_PTR, nt->OptionalHeader.ImageBase)
ctx.ImageSize = nt->OptionalHeader.SizeOfImage
ctx.ModuleName = imagePath

Dim info As DRIVER_MODEL_INFO
info.IsWddm = False
info.Confidence = 0
info.Reason = ""
info.FrameworkOwner = ""

Print "IMAGE " & imagePath
Print "  entry=0x" & Hex(GetImageEntryPointRVA(ctx.pDump)) & _
      " image_base=0x" & Hex(ctx.ImageBase) & " size=0x" & Hex(length)
Print "DETECT is_wddm=" & Str(DetectWddmDriver(ctx, info)) & _
      " confidence=" & Str(info.Confidence) & _
      " reason=[" & info.Reason & "] owner=[" & info.FrameworkOwner & "]"
End 0
'''


def slice_region(text, start, end):
    return '\n'.join(text.split('\n')[start - 1:end])


def build(fbc):
    wddm = read(WDDM)
    bodies = []
    for start, end in WDDM_DETECT_REGIONS:
        bodies += procedures(slice_region(wddm, start, end))
    bodies += procedures(read('ring3/modules/KernelHook/DispatchPeUtils.inc'))
    bodies += procedures(read('ring3/modules/KernelHook/DispatchDisasm.inc'))
    (OUT / 'DispatchTypes_probe.bi').write_text(
        read('ring3/headers/DispatchTypes.bi'), encoding='utf-8')
    print(f'procedures: {len(bodies)} -> {", ".join(names(bodies))}')
    program = PROLOGUE + declarations(bodies) + '\n' + \
        '\n'.join(bodies) + '\n' + EPILOGUE
    exe, log = compile_program(fbc, OUT, 'wddm_detect.bas', program)
    if exe is None:
        print('BUILD FAILED')
        print(log[-5000:])
        raise SystemExit(1)
    print(f'BUILD OK {exe}')
    return exe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('images', nargs='+', type=Path)
    parser.add_argument('--fbc', type=Path, default=DEFAULT_FBC)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    exe = OUT / 'wddm_detect.exe'
    if not args.no_build:
        exe = build(args.fbc)
    for image in args.images:
        output = subprocess.run([str(exe), str(image)], capture_output=True,
                                text=True, encoding='utf-8', errors='replace')
        print(f'--- {image.name} (exit {output.returncode})')
        for line in output.stdout.splitlines():
            if args.verbose or line.startswith(('IMAGE', 'DETECT', '  entry')):
                print('  ' + line)
        if output.returncode:
            print('  stderr: ' + output.stderr[-800:])


if __name__ == '__main__':
    main()
