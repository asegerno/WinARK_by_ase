#include "pch.h"
#include "driverload.h"
#include "ioctl.h"
#include "symbol.h"
#include "SnowSwordCore.h"

SS_API SS_STATUS SS_Initialize(void) {
    if (IsDriverLoaded) {
        return SS_STATUS_SUCCESS;
	}
    if (!InitDriver())
		return SS_STATUS_DRIVER_ERROR;
    if (CreateFileW(L"\\\\.\\SnowSword", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) == INVALID_HANDLE_VALUE) {
        return SS_STATUS_DRIVER_ERROR;
	}
    if (!OpenSymbolDevice())
		return SS_STATUS_DRIVER_ERROR;
    SymbolService_StartWorkers();
    IsDriverLoaded = TRUE;
	return SS_STATUS_SUCCESS;
}

SS_API VOID SS_Shutdown(void) {
    if (IsDriverLoaded) {
        SymbolService_StopWorkers();
		CloseDrv(hDrv);
        UninitDriver();
    }
    IsDriverLoaded = FALSE;
}

SS_API DWORD SS_GetVersion(void) {
	return 0x00010000; // 版本号
}

SS_STATUS SS_GetEProcessEx(ULONG ProcessId, ULONG64* EProcess, BOOL* Exited)
{
    if (!IsDriverLoaded || hDrv == INVALID_HANDLE_VALUE)
        return SS_STATUS_NOT_INITIALIZED;

    if (EProcess == NULL)
        return SS_STATUS_INVALID_PARAMETER;

    HANDLE processId = (HANDLE)(ULONG_PTR)ProcessId;
    EPROCESS_INFO info = { 0 };
    DWORD bytesReturned = 0;

    if (!IoControl(hDrv,
        IOCTL_GetEProcess,
        &processId,
        sizeof(processId),
        &info,
        sizeof(info),
        &bytesReturned))
    {
        return SS_STATUS_DRIVER_ERROR;
    }

    if (bytesReturned != sizeof(info))
        return SS_STATUS_DRIVER_ERROR;

    *EProcess = info.EProcess;

    if (Exited != NULL)
        *Exited = info.bExited;

    return SS_STATUS_SUCCESS;
}

SS_STATUS SS_GetEProcess(ULONG ProcessId, ULONG64* EProcess)
{
    return SS_GetEProcessEx(ProcessId, EProcess, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}