#include "pch.h"
#include "module.h"
#include "log.h"

BOOL GetKernelModulePath(PCWSTR ModuleName, PWSTR OutPath)
{
    NTSTATUS st;
    ULONG    bufferSize = 0x1000;
    PVOID    buffer = malloc(bufferSize);
    BOOL     found = FALSE;

    if (!buffer) {
        MyLog_PrintLog(LOG_ERROR, L"GetKernelModulePath", L"malloc", L"bufferSize=4096");
        return FALSE;
    }

    /* 动态获取 ZwQuerySystemInformation */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        MyLog_PrintLog(LOG_ERROR, L"GetKernelModulePath", L"GetModuleHandleW", L"ntdll.dll");
        free(buffer);
        return FALSE;
    }
    pfnZwQuerySystemInformation ZwQuerySystemInformation =
        (pfnZwQuerySystemInformation)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
    if (!ZwQuerySystemInformation) {
        MyLog_PrintLog(LOG_ERROR, L"GetKernelModulePath", L"GetProcAddress", L"ZwQuerySystemInformation");
        free(buffer);
        return FALSE;
    }

    /* 第一次调用获取所需缓冲区大小 */
    st = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (st == STATUS_INFO_LENGTH_MISMATCH) {
        PVOID newBuf = realloc(buffer, bufferSize);
        if (!newBuf) {
            MyLog_PrintLog(LOG_ERROR, L"GetKernelModulePath", L"realloc", L"bufferSize");
            free(buffer);
            return FALSE;
        }
        buffer = newBuf;
    }

    /* 第二次调用获取实际数据 */
    st = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(st)) {
        MyLog_PrintNtError(L"GetKernelModulePath",
            L"ZwQuerySystemInformation(SystemModuleInformation)",
            st, NULL);
        free(buffer);
        return FALSE;
    }

    /* 解析模块信息 */
    PRTL_PROCESS_MODULES smi = (PRTL_PROCESS_MODULES)buffer;

    /* 构建目标字符串："\" + ModuleName（宽字符） */
    WCHAR targetW[512];
    _snwprintf_s(targetW, _countof(targetW), _TRUNCATE, L"\\%s", ModuleName);

    /* 转换为 ANSI 以便与 FullPathName 比较 */
    char targetA[512] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, targetW, -1, targetA, sizeof(targetA), NULL, NULL);
    _strupr_s(targetA, sizeof(targetA));

    /* 遍历所有模块，大小写不敏感的子串匹配 */
    for (ULONG i = 0; i < smi->NumberOfModules; i++) {
        char imageNameA[256] = { 0 };
        strncpy_s(imageNameA, sizeof(imageNameA),
            (const char*)smi->Modules[i].FullPathName, _TRUNCATE);
        _strupr_s(imageNameA, sizeof(imageNameA));

        if (strstr(imageNameA, targetA) != NULL) {
            /* 找到模块，将 ANSI 的 FullPathName 转换为 Unicode 写入 OutPath */
            MultiByteToWideChar(CP_ACP, 0,
                (const char*)smi->Modules[i].FullPathName,
                -1, OutPath, 260);
            found = TRUE;
            break;
        }
    }

    free(buffer);
    return found;
}