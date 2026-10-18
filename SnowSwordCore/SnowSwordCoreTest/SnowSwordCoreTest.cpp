#include <stdio.h>
#include "../SnowSwordCore.h"

/* SnowSwordCoreDispatchTest.cpp：派遣恢复离线测试入口 */
int RunDispatchTestMain(int argc, char** argv);

static BOOL EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(token);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(token);
        return FALSE;
    }

    DWORD error = GetLastError();
    CloseHandle(token);
    return error == ERROR_SUCCESS;
}

int main(int argc, char** argv)
{
    /*
     * 带参数 => 派遣恢复离线测试（不需要内核驱动、不需要管理员权限）。
     * 无参数 => 保持原有驱动通信自检行为。
     */
    if (argc >= 2) {
        return RunDispatchTestMain(argc, argv);
    }

    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        printf("Failed to enable SE_DEBUG_NAME privilege.\n");
        return -1;
    }
    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        printf("Failed to enable SE_LOAD_DRIVER_NAME privilege.\n");
        return -1;
	}
    SS_STATUS initStatus = SS_Initialize();
    if (initStatus != SS_STATUS_SUCCESS) {
        printf("Failed to initialize SnowSwordCore: %d\n", initStatus);
        return -1;
    }
	printf("SnowSwordCore initialized successfully.\n");

    ULONG64 eprocess = 0;
    BOOL exited = FALSE;

    SS_STATUS status = SS_GetEProcessEx(4, &eprocess, &exited);

    printf("status   = %d\n", status);
    printf("EPROCESS = 0x%llX\n", eprocess);
    printf("Exited   = %s\n", exited ? "TRUE" : "FALSE");

    SS_Shutdown();
    return 0;
}