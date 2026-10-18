@echo off
REM Phase 3B: build the Core-side KMDF ground-truth dumper (standalone, no DLL).
setlocal
set "NO_PROXY="& set "no_proxy="& set "HTTP_PROXY="& set "http_proxy="
set "HTTPS_PROXY="& set "https_proxy="& set "ALL_PROXY="& set "all_proxy="

if not exist "%~dp0build" mkdir "%~dp0build"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0.."
cl /nologo /wd4819 /I. /D SNOWSWORDCORE_EXPORTS /D NDEBUG ^
   /Fe"%~dp0build\kmdf_gt_verify.exe" /Fo"%~dp0build\\" ^
   "%~dp0kmdf_gt_verify.c" dispatch_kmdf.c
exit /b %errorlevel%
