#pragma once

#define LOG_ERROR 0

// ---------------------------------------------------------------------------
// 日志辅助函数（替代 FreeBASIC 中的 MyLog 对象）
// ---------------------------------------------------------------------------
void MyLog_PrintLog(int level, const wchar_t* func, const wchar_t* api, const wchar_t* msg);

void MyLog_PrintWin32Error(const wchar_t* func, const wchar_t* api, const wchar_t* extra);

void MyLog_PrintNtError(const wchar_t* func, const wchar_t* api, NTSTATUS status, const wchar_t* extra);