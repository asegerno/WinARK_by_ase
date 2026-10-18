"""Generate and run a VB dumper that exercises the REAL FreeBASIC KMDF functions.

Phase 3B ground-truth cross-check. The compiled program links the actual
BuildKmdfDispatchBaseline / IsKmdfBaselineExecutable bodies extracted from the
SnowSword ring3 sources (same extraction mechanism as verify_kmdf_dispatch.py),
and prints the B/P/O slot dump in the exact line format emitted by
SnowSwordCore/_kmdf_probe/kmdf_gt_verify.c. The two stdout dumps are then diffed.

The O-section orchestration is a line-for-line port of the pure construction in
ApplyKmdfDispatchBaseline (DispatchKmdf.Inc:141-175) minus the IOCTL, file IO and
ApplyDispatchRecoveryResult address mapping (which stay host-owned under plan A).

Read-only with respect to the SnowSword repo: nothing is written there; the
generated .bas/.exe land in this Core _kmdf_probe/build directory.
"""
from pathlib import Path
import argparse
import re
import subprocess

CORE = Path(__file__).resolve().parents[1]
SNOWSWORD = Path(r"D:\GitHub Project\SnowSword")


def block(source, kind, name):
    return re.search(rf"^{kind} {name}\b.*?^End {kind}\s*$", source,
                     re.M | re.S).group(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fbc', default='D:/Programs/VisualFreeBasic6.0/Compile/'
                        'FreeBASIC-1.10.0-winlibs-gcc-9.3.0/fbc64.exe')
    parser.add_argument('--out', default=None)
    args = parser.parse_args()

    kernel = (SNOWSWORD / 'ring3/modules/ModKernel.Inc').read_text(encoding='utf-8-sig')
    module = (SNOWSWORD / 'ring3/modules/KernelHook/DispatchKmdf.Inc').read_text(encoding='utf-8-sig')

    build_dir = CORE / '_kmdf_probe' / 'build'
    build_dir.mkdir(parents=True, exist_ok=True)

    harness = '#include once "windows.bi"\n#include once "crt/string.bi"\n'
    harness += '#include once "DispatchTypes.bi"\n'
    harness += block(kernel, 'Enum', 'KMDF_DISPATCH_POLICY') + '\n'
    harness += block(kernel, 'Type', 'KMDF_DRIVER_INFO') + '\n'
    for name in ('BuildKmdfDispatchBaseline', 'IsKmdfBaselineExecutable'):
        harness += block(module, 'Function', name) + '\n'

    harness += r'''
Dim Shared mockBase As ULONG_PTR = &HFFFFF80000000000ULL
Dim Shared mockSize As ULong = &H5000
Dim Shared peBytes(0 To &H7FF) As UByte

Function MakeInfo() As KMDF_DRIVER_INFO
    Dim x As KMDF_DRIVER_INFO
    x.IsKmdf = 1: x.OwnsDispatch = 1: x.DispatchPolicyKnown = 1
    x.Dispatch = mockBase + &H1000
    x.DispatchWithLock = mockBase + &H2000
    x.DispatchPolicy = KmdfDispatchPolicyAllDispatchWithLock
    Return x
End Function

Sub DumpBuild(ByVal id As Integer, ByVal ok As Boolean, _
              ByRef b As DRIVER_DISPATCH_RECOVERY_OUTPUT)
    Print "B|" & id & "|" & IIf(ok, 1, 0) & "|" & b.ModelKind & "|" & _
          b.ModelConfidence & "|" & b.HitCount & "|" & b.Confidence
    For i As Integer = 0 To 27
        With b.MajorFunction(i)
            Print "S|" & id & "|" & i & "|" & IIf(.Valid, 1, 0) & "|" & _
                  Hex(.ModuleBase) & "|" & Hex(.FunctionRva) & "|" & _
                  .State & "|" & .OwnerKind & "|" & .Source & "|" & .Confidence
        End With
    Next
End Sub

Sub DumpOverlay(ByVal id As Integer, ByVal disposition As Integer, _
                ByRef b As DRIVER_DISPATCH_RECOVERY_OUTPUT, ByVal targetRva As ULong)
    Print "O|" & id & "|" & disposition & "|" & b.ModelKind & "|" & _
          b.ModelConfidence & "|" & b.HitCount & "|" & b.Confidence & "|" & Hex(targetRva)
    For i As Integer = 0 To 27
        With b.MajorFunction(i)
            Print "S|" & id & "|" & i & "|" & IIf(.Valid, 1, 0) & "|" & _
                  Hex(.ModuleBase) & "|" & Hex(.FunctionRva) & "|" & _
                  .State & "|" & .OwnerKind & "|" & .Source & "|" & .Confidence
        End With
    Next
End Sub

' Pure construction ported from ApplyKmdfDispatchBaseline (DispatchKmdf.Inc:141-175),
' without QueryKmdfDriverInfo / file IO / ApplyDispatchRecoveryResult.
Sub RunOverlay(ByVal id As Integer, ByRef info As KMDF_DRIVER_INFO, _
               ByVal haveImage As Boolean)
    Dim baseline As DRIVER_DISPATCH_RECOVERY_OUTPUT
    Dim disposition As Integer
    Dim targetRva As ULong

    If info.OwnsDispatch <> 1 OrElse (info.DriverInitFlags And &H2) <> 0 Then
        memset(@baseline, 0, SizeOf(baseline))
        baseline.ModelKind = DispatchModelKmdf
        DumpOverlay id, 0, baseline, 0
        Exit Sub
    End If

    Dim available As Boolean = BuildKmdfDispatchBaseline(info, mockBase, mockSize, baseline)
    targetRva = IIf(available, baseline.MajorFunction(0).FunctionRva, 0)
    If available Then
        If haveImage Then
            available = IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), _
                                                 mockSize, targetRva)
        Else
            available = False
        End If
    End If

    If Not available Then
        memset(@baseline, 0, SizeOf(baseline))
        baseline.ModelKind = DispatchModelKmdf
        For i As Integer = 0 To IRP_MJ_MAXIMUM_FUNCTION
            baseline.MajorFunction(i).State = DispatchSlotFrameworkOwned
            baseline.MajorFunction(i).OwnerKind = DispatchOwnerFramework
            baseline.MajorFunction(i).Source = DispatchSourceFrameworkClassification
        Next
        DumpOverlay id, 2, baseline, targetRva
    Else
        DumpOverlay id, 1, baseline, targetRva
    End If
End Sub

Sub MakeSyntheticPe()
    Dim dos As IMAGE_DOS_HEADER Ptr = Cast(IMAGE_DOS_HEADER Ptr, @peBytes(0))
    dos->e_magic = &H5A4D: dos->e_lfanew = &H80
    Dim nt As IMAGE_NT_HEADERS64 Ptr = Cast(IMAGE_NT_HEADERS64 Ptr, @peBytes(&H80))
    nt->Signature = &H4550: nt->FileHeader.Machine = &H8664
    nt->OptionalHeader.Magic = &H20B: nt->OptionalHeader.SizeOfImage = mockSize
    nt->FileHeader.SizeOfOptionalHeader = SizeOf(IMAGE_OPTIONAL_HEADER64)
    nt->FileHeader.NumberOfSections = 1
    Dim section As IMAGE_SECTION_HEADER Ptr = _
        Cast(IMAGE_SECTION_HEADER Ptr, @peBytes(&H80 + SizeOf(IMAGE_NT_HEADERS64)))
    section->VirtualAddress = &H1000: section->Misc.VirtualSize = &H1000
    section->SizeOfRawData = &H400: section->PointerToRawData = &H400
    section->Characteristics = IMAGE_SCN_MEM_EXECUTE
End Sub

Dim recovered As DRIVER_DISPATCH_RECOVERY_OUTPUT

' ---- B section ----
For policy As Integer = KmdfDispatchPolicyAllDispatch To KmdfDispatchPolicyAllDispatchWithLock
    Dim info As KMDF_DRIVER_INFO = MakeInfo()
    info.DispatchPolicy = policy
    Dim ok As Boolean = BuildKmdfDispatchBaseline(info, mockBase, mockSize, recovered)
    DumpBuild policy - 1, ok, recovered
Next

Dim baseInfo As KMDF_DRIVER_INFO = MakeInfo()
For scenario As Integer = 0 To 9
    Dim invalid As KMDF_DRIVER_INFO = baseInfo
    Dim testBase As ULONG_PTR = mockBase
    Select Case scenario
        Case 0: invalid.IsKmdf = 0
        Case 1: invalid.OwnsDispatch = 0
        Case 2: invalid.DriverInitFlags = 2
        Case 3: invalid.DispatchPolicyKnown = 0
        Case 4: invalid.DispatchPolicy = KmdfDispatchPolicyMixed
        Case 5: invalid.DispatchPolicy = 99
        Case 6: invalid.DispatchWithLock = 0
        Case 7: invalid.DispatchWithLock = mockBase + mockSize
        Case 8: testBase = &H1000
        Case 9: testBase = &HFFFFFFFFFFFFF000ULL
    End Select
    Dim rok As Boolean = BuildKmdfDispatchBaseline(invalid, testBase, mockSize, recovered)
    DumpBuild 2 + scenario, rok, recovered
Next

' ---- P section ----
MakeSyntheticPe()
Dim dosP As IMAGE_DOS_HEADER Ptr = Cast(IMAGE_DOS_HEADER Ptr, @peBytes(0))
Dim secP As IMAGE_SECTION_HEADER Ptr = _
    Cast(IMAGE_SECTION_HEADER Ptr, @peBytes(&H80 + SizeOf(IMAGE_NT_HEADERS64)))
Print "P|0|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), mockSize, &H1100), 1, 0)
Print "P|1|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), 16, mockSize, &H1100), 1, 0)
Print "P|2|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), &H90, mockSize, &H1100), 1, 0)
Print "P|3|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), mockSize + 1, &H1100), 1, 0)
Print "P|4|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), mockSize, &H1500), 1, 0)
secP->Characteristics = 0
Print "P|5|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), mockSize, &H1100), 1, 0)
secP->Characteristics = IMAGE_SCN_MEM_EXECUTE: secP->PointerToRawData = &HFFFFFF00
Print "P|6|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), mockSize, &H1100), 1, 0)
dosP->e_lfanew = &H7FFFFFFF
Print "P|7|" & IIf(IsKmdfBaselineExecutable(@peBytes(0), CUInt(UBound(peBytes) + 1), mockSize, &H1100), 1, 0)

' ---- O section ----
MakeSyntheticPe()
Dim o0 As KMDF_DRIVER_INFO = MakeInfo(): o0.DispatchPolicy = KmdfDispatchPolicyAllDispatch
RunOverlay 20, o0, True
Dim o1 As KMDF_DRIVER_INFO = MakeInfo(): o1.DispatchPolicyKnown = 0
RunOverlay 21, o1, True
Dim o2 As KMDF_DRIVER_INFO = MakeInfo(): o2.DriverInitFlags = 2
RunOverlay 22, o2, True
Dim o3 As KMDF_DRIVER_INFO = MakeInfo(): o3.OwnsDispatch = 0
RunOverlay 23, o3, True
Dim o4 As KMDF_DRIVER_INFO = MakeInfo(): o4.DispatchPolicy = KmdfDispatchPolicyAllDispatch
RunOverlay 24, o4, False
'''

    src = build_dir / 'kmdf_dump.bas'
    src.write_text(harness, encoding='utf-8')
    exe = build_dir / 'kmdf_dump.exe'
    subprocess.run([args.fbc, '-i', str(SNOWSWORD / 'ring3/headers'),
                    '-x', str(exe), str(src)], check=True)
    proc = subprocess.run([str(exe)], check=True, capture_output=True, text=True)

    if args.out:
        Path(args.out).write_text(proc.stdout, encoding='utf-8', newline='\n')
    else:
        print(proc.stdout, end='')


if __name__ == '__main__':
    main()
