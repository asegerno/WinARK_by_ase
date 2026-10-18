@echo off
REM Phase 2 helper: build SnowSwordCore Release|x64 with a clean environment.
REM
REM Why: the process environment block carries BOTH `NO_PROXY` and `no_proxy`.
REM MSBuild's ToolTask builds a case-insensitive dictionary of the child
REM environment and dies with MSB6001 ("an item with the same key has already
REM been added").  PowerShell's Env: provider is a case-insensitive hashtable,
REM so it cannot see or remove the duplicate -- the deletion must happen on the
REM cmd side.  Same workaround as validation/build_ring0.ps1.
set "NO_PROXY="
set "no_proxy="
set "HTTP_PROXY="
set "http_proxy="
set "HTTPS_PROXY="
set "https_proxy="
set "ALL_PROXY="
set "all_proxy="

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
msbuild "%~dp0..\SnowSwordCore.sln" /p:Configuration=Release /p:Platform=x64 %* /nologo
