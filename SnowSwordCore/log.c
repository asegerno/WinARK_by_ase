#include "pch.h"
#include "log.h"

// ---------------------------------------------------------------------------
// 日志辅助函数（替代 FreeBASIC 中的 MyLog 对象）
// ---------------------------------------------------------------------------
static void MyLog_PrintLog(int level, const wchar_t* func, const wchar_t* api, const wchar_t* msg)
{
    printf("[%ws] %ws: %ws\n", func, api, msg);
}

static void MyLog_PrintWin32Error(const wchar_t* func, const wchar_t* api, const wchar_t* extra)
{
    DWORD err = GetLastError();
    printf("[%ws] %ws failed with error %lu", func, api, err);
    if (extra) printf(" (%ws)", extra);
    printf("\n");
}

static void MyLog_PrintNtError(const wchar_t* func, const wchar_t* api, NTSTATUS status, const wchar_t* extra)
{
    printf("[%ws] %ws failed with status 0x%08X", func, api, (unsigned int)status);
    if (extra) printf(" (%ws)", extra);
    printf("\n");
}