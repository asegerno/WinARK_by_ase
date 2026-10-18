#pragma once

#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "ntdll.lib")   // 用于 RtlInitUnicodeString

#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010E)
#endif

extern HANDLE hDrv;
extern BOOL   IsDriverLoaded;

// ---------------------------------------------------------------------------
// 从完整路径中提取驱动名（不含扩展名）
// ---------------------------------------------------------------------------
static void GetDriverNameFromPath(LPCWSTR szDrvPath, LPWSTR szDrvName, size_t nameSize);

// ---------------------------------------------------------------------------
// 驱动操作封装
// ---------------------------------------------------------------------------
HANDLE OpenDrv(LPCWSTR szDrvLinkName, BOOL IsAsycn);

BOOL IoControl(HANDLE hDrvHandle, DWORD dwIoControlCode,
    LPVOID lpInBuffer, DWORD nInBufferSize,
    LPVOID lpOutBuffer, DWORD nOutBufferSize,
    LPDWORD lpBytesReturned);

void CloseDrv(HANDLE hDrvHandle);

DWORD CTL_CODE_GEN(DWORD lngFunction);

// ---------------------------------------------------------------------------
// 加载驱动
// ---------------------------------------------------------------------------
BOOL LoadDriver(LPCWSTR szDrvPath, BOOL IsMiniFilter);

// ---------------------------------------------------------------------------
// 卸载驱动
// ---------------------------------------------------------------------------
BOOL UnloadDriver(LPCWSTR szDrvPath, BOOL IsMiniFilter);

// ---------------------------------------------------------------------------
// 初始化 / 反初始化驱动
// ---------------------------------------------------------------------------
BOOL InitDriver();
void UninitDriver();