#pragma once
#include <Windows.h>

#ifdef SNOWSWORDCORE_EXPORTS
#define SS_API __declspec(dllexport)
#elif defined(SNOWSWORDCORE_STATIC)
#define SS_API
#else
#define SS_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum _SS_STATUS {
        SS_STATUS_SUCCESS = 0,
        SS_STATUS_NOT_INITIALIZED,
        SS_STATUS_DRIVER_ERROR,
        SS_STATUS_INVALID_PARAMETER
    } SS_STATUS;

    SS_API SS_STATUS SS_Initialize(void);
    SS_API void SS_Shutdown(void);
    SS_API DWORD SS_GetVersion(void);
    SS_API SS_STATUS SS_GetEProcess(ULONG ProcessId, ULONG64* EProcess);
    SS_API SS_STATUS SS_GetEProcessEx(ULONG ProcessId, ULONG64* EProcess, BOOL* Exited);

#ifdef __cplusplus
}
#endif