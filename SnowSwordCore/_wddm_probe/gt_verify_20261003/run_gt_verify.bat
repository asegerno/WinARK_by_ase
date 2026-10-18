@echo off
REM Phase 2 helper: run wddm_gt_verify for the 5 dxgkrnl samples.
REM
REM Ground truth (inv/gt.json) was captured with dxgkrnl at runtime base
REM 0xFFFFF8043C220000; the candidate comparison subtracts that base, so the
REM same value must be replayed here.  Device paths come from inv/manifest.json.
setlocal

set "PROBE=%~dp0"
set "DXG=C:\Windows\System32\drivers\dxgkrnl.sys"
set "DXGBASE=0xFFFFF8043C220000"

set "IGDKM=C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_715821f1c885b416\igdkmdn64.sys"
set "BASICRENDER=C:\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_505dbfb03b1f39fa\BasicRender.sys"
set "INDIRECT=C:\Windows\System32\drivers\IndirectKmd.sys"
set "NPUKMD=C:\Windows\System32\DriverStore\FileRepository\npu.inf_amd64_c174cd41587112dd\npu_kmd.sys"
set "BASICDISPLAY=C:\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_2753efdbb0d9a226\BasicDisplay.sys"

cd /d "%PROBE%"

for %%S in (igdkmdn64 BasicRender IndirectKmd npu_kmd BasicDisplay) do (
    call :run %%S
)
exit /b 0

:run
set "STAMP=%~1"
if /I "%~1"=="igdkmdn64"     set "IMG=%IGDKM%"
if /I "%~1"=="BasicRender"   set "IMG=%BASICRENDER%"
if /I "%~1"=="IndirectKmd"   set "IMG=%INDIRECT%"
if /I "%~1"=="npu_kmd"       set "IMG=%NPUKMD%"
if /I "%~1"=="BasicDisplay"  set "IMG=%BASICDISPLAY%"

echo === %STAMP% ===
wddm_gt_verify.exe "%IMG%" "%DXG%" "inv\%STAMP%.cli.txt" %DXGBASE% dump > "out_%STAMP%.txt" 2>&1
if errorlevel 1 (
    echo   !! verify exit=%errorlevel%
) else (
    findstr /C:"MODEL " /C:"SUMMARY" "out_%STAMP%.txt"
)
exit /b 0
