#include "pch.h"
#include "driverload.h"
#include "log.h"

// ---------------------------------------------------------------------------
// 全局变量
// ---------------------------------------------------------------------------
HANDLE hDrv = INVALID_HANDLE_VALUE;
BOOL   IsDriverLoaded = FALSE;

// ---------------------------------------------------------------------------
// 从完整路径中提取驱动名（不含扩展名）
// ---------------------------------------------------------------------------
static void GetDriverNameFromPath(LPCWSTR szDrvPath, LPWSTR szDrvName, size_t nameSize)
{
    LPCWSTR p = wcsrchr(szDrvPath, L'\\');
    if (!p) p = wcsrchr(szDrvPath, L'/');
    if (!p) p = szDrvPath; else p++;

    LPCWSTR dot = wcsrchr(p, L'.');
    size_t len = dot ? (size_t)(dot - p) : wcslen(p);
    if (len >= nameSize) len = nameSize - 1;
    wcsncpy(szDrvName, p, len);
    szDrvName[len] = L'\0';
}

// ---------------------------------------------------------------------------
// 驱动操作封装
// ---------------------------------------------------------------------------
HANDLE OpenDrv(LPCWSTR szDrvLinkName, BOOL IsAsycn)
{
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL;
    if (IsAsycn) dwFlags |= FILE_FLAG_OVERLAPPED;

    HANDLE hDrvHandle = CreateFileW(szDrvLinkName,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        dwFlags, NULL);
    if (hDrvHandle == INVALID_HANDLE_VALUE)
        MyLog_PrintWin32Error(L"OpenDrv", L"CreateFileW", NULL);
    return hDrvHandle;
}

BOOL IoControl(HANDLE hDrvHandle, DWORD dwIoControlCode,
    LPVOID lpInBuffer, DWORD nInBufferSize,
    LPVOID lpOutBuffer, DWORD nOutBufferSize,
    LPDWORD lpBytesReturned)
{
    DWORD lDrvRetSize = 0;
    SetLastError(0);
    BOOL ret = DeviceIoControl(hDrvHandle, dwIoControlCode,
        lpInBuffer, nInBufferSize,
        lpOutBuffer, nOutBufferSize,
        &lDrvRetSize, NULL);
    if (lpBytesReturned) *lpBytesReturned = lDrvRetSize;
    return ret;
}

void CloseDrv(HANDLE hDrvHandle)
{
    CloseHandle(hDrvHandle);   // 原代码使用 ZwClose，此处用 CloseHandle 更通用
}

DWORD CTL_CODE_GEN(DWORD lngFunction)
{
    return (FILE_DEVICE_UNKNOWN << 16) |
        (FILE_ANY_ACCESS << 14) |
        (lngFunction << 2) |
        METHOD_BUFFERED;
}

// ---------------------------------------------------------------------------
// 加载驱动
// ---------------------------------------------------------------------------
BOOL LoadDriver(LPCWSTR szDrvPath, BOOL IsMiniFilter)
{
    BOOL result = TRUE;

    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (!hNtdll) {
        MyLog_PrintLog(LOG_ERROR, L"LoadDriver", L"LoadLibraryW", L"加载NTDLL失败");
        return FALSE;
    }
    HMODULE hFltdll = LoadLibraryW(L"FltLib.dll");
    if (!hFltdll) {
        MyLog_PrintLog(LOG_ERROR, L"LoadDriver", L"LoadLibraryW", L"加载FltLib失败");
        FreeLibrary(hNtdll);
        return FALSE;
    }

    typedef NTSTATUS(NTAPI* pfnZwLoadDriver)(PUNICODE_STRING);
    typedef HRESULT(WINAPI* pfnFilterLoad)(LPCWSTR);

    pfnZwLoadDriver ZwLoadDriver = (pfnZwLoadDriver)GetProcAddress(hNtdll, "ZwLoadDriver");
    pfnFilterLoad   FilterLoad = (pfnFilterLoad)GetProcAddress(hFltdll, "FilterLoad");

    if (!ZwLoadDriver || !FilterLoad) {
        MyLog_PrintLog(LOG_ERROR, L"LoadDriver", L"GetProcAddress", L"获取函数地址失败");
        FreeLibrary(hNtdll);
        FreeLibrary(hFltdll);
        return FALSE;
    }

    WCHAR szDrvPathCopy[260] = { 0 };
    wcscpy_s(szDrvPathCopy, 260, szDrvPath);

    // 网络路径处理：复制到系统 drivers 目录
    if ((wcsncmp(szDrvPathCopy, L"\\\\", 2) == 0) ||
        (wcsncmp(szDrvPathCopy, L"//", 2) == 0)) {
        LPCWSTR fileName = wcsrchr(szDrvPathCopy, L'\\');
        if (!fileName) fileName = wcsrchr(szDrvPathCopy, L'/');
        if (fileName) fileName++; else fileName = szDrvPathCopy;

        WCHAR driverPath[260] = { 0 };
        swprintf_s(driverPath, 260, L"C:\\Windows\\System32\\drivers\\%s", fileName);
        CopyFileW(szDrvPathCopy, driverPath, FALSE);
        wcscpy_s(szDrvPathCopy, 260, driverPath);
    }

    WCHAR szDrvName[128] = { 0 };
    GetDriverNameFromPath(szDrvPathCopy, szDrvName, 128);

    WCHAR szSubKey[260];
    WCHAR szSubPath[260];
    swprintf_s(szSubKey, 260, L"SYSTEM\\CurrentControlSet\\Services\\%s", szDrvName);
    swprintf_s(szSubPath, 260, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", szDrvName);

    HKEY  KeyHandle = NULL;
    DWORD dwDisposition = 0;
    LONG  ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szSubKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &KeyHandle, &dwDisposition);
    if (ret != ERROR_SUCCESS) {
        MyLog_PrintWin32Error(L"LoadDriver", L"RegCreateKeyExW", szSubKey);
        FreeLibrary(hNtdll);
        FreeLibrary(hFltdll);
        return FALSE;
    }

    DWORD dwType = 1;    // SERVICE_KERNEL_DRIVER
    DWORD dwStart = 3;    // SERVICE_DEMAND_START
    DWORD dwErrorControl = 1;   // SERVICE_ERROR_NORMAL
    WCHAR strGroup[] = L"FSFilter Activity Monitor";
    WCHAR DependOnService[] = L"FltMgr";

    RegSetValueExW(KeyHandle, L"Type", 0, REG_DWORD,
        (const BYTE*)&dwType, sizeof(dwType));
    RegSetValueExW(KeyHandle, L"Start", 0, REG_DWORD,
        (const BYTE*)&dwStart, sizeof(dwStart));
    RegSetValueExW(KeyHandle, L"ErrorControl", 0, REG_DWORD,
        (const BYTE*)&dwErrorControl, sizeof(dwErrorControl));
    RegSetValueExW(KeyHandle, L"Group", 0, REG_SZ,
        (const BYTE*)strGroup,
        (DWORD)((wcslen(strGroup) + 1) * sizeof(WCHAR)));
    RegSetValueExW(KeyHandle, L"DependOnService", 0, REG_SZ,
        (const BYTE*)DependOnService,
        (DWORD)((wcslen(DependOnService) + 1) * sizeof(WCHAR)));

    WCHAR szImagePath[512];
    swprintf_s(szImagePath, 512, L"\\??\\%s", szDrvPathCopy);
    RegSetValueExW(KeyHandle, L"ImagePath", 0, REG_SZ,
        (const BYTE*)szImagePath,
        (DWORD)((wcslen(szImagePath) + 1) * sizeof(WCHAR)));
    RegCloseKey(KeyHandle);

    // ----- MiniFilter 实例注册 -----
    WCHAR szSubKey1[260];
    swprintf_s(szSubKey1, 260, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances", szDrvName);
    WCHAR InstanceName[128];
    swprintf_s(InstanceName, 128, L"%s Instance", szDrvName);

    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szSubKey1, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &KeyHandle, &dwDisposition);
    if (ret != ERROR_SUCCESS) {
        MyLog_PrintWin32Error(L"LoadDriver", L"RegCreateKeyExW", szSubKey1);
        FreeLibrary(hNtdll);
        FreeLibrary(hFltdll);
        return FALSE;
    }
    RegSetValueExW(KeyHandle, L"DefaultInstance", 0, REG_SZ,
        (const BYTE*)InstanceName,
        (DWORD)((wcslen(InstanceName) + 1) * sizeof(WCHAR)));
    RegCloseKey(KeyHandle);

    WCHAR szSubKey2[260];
    swprintf_s(szSubKey2, 260, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\%s",
        szDrvName, InstanceName);
    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szSubKey2, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &KeyHandle, &dwDisposition);
    if (ret != ERROR_SUCCESS) {
        MyLog_PrintWin32Error(L"LoadDriver", L"RegCreateKeyExW", szSubKey2);
        FreeLibrary(hNtdll);
        FreeLibrary(hFltdll);
        return FALSE;
    }

    WCHAR Altitude[] = L"370020";
    RegSetValueExW(KeyHandle, L"Altitude", 0, REG_SZ,
        (const BYTE*)Altitude,
        (DWORD)((wcslen(Altitude) + 1) * sizeof(WCHAR)));
    DWORD dwFlags = 0;
    RegSetValueExW(KeyHandle, L"Flags", 0, REG_DWORD,
        (const BYTE*)&dwFlags, sizeof(dwFlags));
    RegCloseKey(KeyHandle);

    // ----- 加载驱动 -----
    UNICODE_STRING uDriverServiceName;
    RtlInitUnicodeString(&uDriverServiceName, szSubPath);

    if (IsMiniFilter) {
        WCHAR FilterName[128];
        wcscpy_s(FilterName, 128, szDrvName);
        HRESULT hr = FilterLoad(FilterName);
        if (hr != S_OK) {
            MyLog_PrintNtError(L"LoadDriver", L"FilterLoad", hr, szDrvName);
            FreeLibrary(hNtdll);
            FreeLibrary(hFltdll);
            return FALSE;
        }
    }
    else {
        NTSTATUS st = ZwLoadDriver(&uDriverServiceName);
        if (!NT_SUCCESS(st) && st != STATUS_IMAGE_ALREADY_LOADED) {
            MyLog_PrintNtError(L"LoadDriver", L"ZwLoadDriver", st, szSubPath);
            result = FALSE;
        }
    }

    FreeLibrary(hNtdll);
    FreeLibrary(hFltdll);
    return result;
}

// ---------------------------------------------------------------------------
// 卸载驱动
// ---------------------------------------------------------------------------
BOOL UnloadDriver(LPCWSTR szDrvPath, BOOL IsMiniFilter)
{
    WCHAR szDrvName[128] = { 0 };
    GetDriverNameFromPath(szDrvPath, szDrvName, 128);

    WCHAR szSubKey1[260];
    swprintf_s(szSubKey1, 260, L"SYSTEM\\CurrentControlSet\\Services\\%s", szDrvName);
    WCHAR szSubKey2[260] = L"SYSTEM\\CurrentControlSet\\Services";   // 原代码如此，危险操作
    WCHAR szSubPath[260];
    swprintf_s(szSubPath, 260, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", szDrvName);

    UNICODE_STRING uDriverServiceName;

    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    HMODULE hFltdll = LoadLibraryW(L"FltLib.dll");
    if (!hNtdll) {
        MyLog_PrintLog(LOG_ERROR, L"UnloadDriver", L"LoadLibraryW", L"加载NTDLL失败");
        return FALSE;
    }
    if (!hFltdll) {
        MyLog_PrintLog(LOG_ERROR, L"UnloadDriver", L"LoadLibraryW", L"加载FltLib失败");
        FreeLibrary(hNtdll);
        return FALSE;
    }

    typedef NTSTATUS(NTAPI* pfnZwUnloadDriver)(PUNICODE_STRING);
    typedef HRESULT(WINAPI* pfnFilterUnload)(LPCWSTR);

    pfnZwUnloadDriver ZwUnloadDriver = (pfnZwUnloadDriver)GetProcAddress(hNtdll, "ZwUnloadDriver");
    pfnFilterUnload   FilterUnload = (pfnFilterUnload)GetProcAddress(hFltdll, "FilterUnload");

    if (!ZwUnloadDriver || !FilterUnload) {
        MyLog_PrintLog(LOG_ERROR, L"UnloadDriver", L"GetProcAddress", L"获取函数地址失败");
        FreeLibrary(hNtdll);
        FreeLibrary(hFltdll);
        return FALSE;
    }

    RtlInitUnicodeString(&uDriverServiceName, szSubPath);

    if (IsMiniFilter) {
        WCHAR FilterName[128];
        wcscpy_s(FilterName, 128, szDrvName);
        HRESULT hr = FilterUnload(FilterName);
        if (hr != S_OK) {
            MyLog_PrintNtError(L"UnloadDriver", L"FilterUnload", hr, szDrvName);
            FreeLibrary(hNtdll);
            FreeLibrary(hFltdll);
            return FALSE;
        }
    }
    else {
        NTSTATUS st = ZwUnloadDriver(&uDriverServiceName);
        if (st != 0) {
            MyLog_PrintNtError(L"UnloadDriver", L"ZwUnloadDriver", st, szSubPath);
            FreeLibrary(hNtdll);
            FreeLibrary(hFltdll);
            return FALSE;
        }
    }

    // 删除注册表信息（注意：原代码会尝试删除整个 Services 键，实际使用需修改）
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, szSubKey1);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, szSubKey2);

    FreeLibrary(hNtdll);
    FreeLibrary(hFltdll);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 初始化 / 反初始化驱动
// ---------------------------------------------------------------------------
BOOL InitDriver()
{
    WCHAR drvPath[260];
    GetModuleFileNameW(NULL, drvPath, 260);
    WCHAR* p = wcsrchr(drvPath, L'\\');
    if (p) *(p + 1) = L'\0';
    wcscat_s(drvPath, 260, L"SnowSword.sys");

    if (!LoadDriver(drvPath, FALSE)) return FALSE;

    hDrv = OpenDrv(L"\\\\.\\SnowSword", TRUE);
    if (hDrv == INVALID_HANDLE_VALUE) return FALSE;

    // 原代码中还有符号设备与服务初始化，此处省略
    // if (!OpenSymbolDevice() || hSymbolDrv == INVALID_HANDLE_VALUE) return FALSE;
    // SymbolService_StartWorkers();

    IsDriverLoaded = TRUE;
    // FrmMain.Check6.Value = 1;
    return TRUE;
}

void UninitDriver()
{
    CloseDrv(hDrv);
    // SymbolService_StopWorkers();

    WCHAR drvPath[260];
    GetModuleFileNameW(NULL, drvPath, 260);
    WCHAR* p = wcsrchr(drvPath, L'\\');
    if (p) *(p + 1) = L'\0';
    wcscat_s(drvPath, 260, L"SnowSword.sys");

    UnloadDriver(drvPath, FALSE);
    IsDriverLoaded = FALSE;
}