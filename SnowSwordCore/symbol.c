#include "pch.h"
#include "symbol.h"
#include "module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include "ioctl.h" 

/* ================================================================
 * 全局变量
 * ================================================================ */
HANDLE hSymbolDrv = INVALID_HANDLE_VALUE;
HANDLE g_hProgressEvent = NULL;
DWORD  g_SymbolPercent = 0;

/* 模块缓存（仅本文件使用） */
static LOADED_MODULE g_LoadedModules[MAX_LOADED_MODULES];

/* 符号引擎句柄 */
static HANDLE g_hSymProcess = NULL;

/* Actor 队列 */
static CRITICAL_SECTION g_csQueue;
static SYMBOL_REQUEST* g_pQueueHead = NULL;
static SYMBOL_REQUEST* g_pQueueTail = NULL;
static HANDLE           g_hQueueNotEmpty = NULL;
static HANDLE           g_hSymbolThread = NULL;

/* 工作线程 */
static volatile BOOL g_StopWorkerThreads = FALSE;
static HANDLE m_hThreads[WORKER_THREAD_COUNT];

/* P0-2: 符号引擎初始化状态（由 Actor 线程维护）。引擎失败时线程保持运行，
 * 对 SHUTDOWN 以外的请求快速失败，避免队列无消费者导致超时/卡死。 */
static BOOL g_SymEngineReady = FALSE;
static BOOL g_SymEngineFailed = FALSE;

/* ================================================================
 * 日志简单实现（用户可自行替换为其他实现）
 * ================================================================ */
void MyLog_PrintWin32Error(const char* func, const char* api, const char* extra)
{
    DWORD err = GetLastError();
    fprintf(stderr, "[%s] %s failed with error %lu", func, api, (unsigned long)err);
    if (extra) fprintf(stderr, " (%s)", extra);
    fprintf(stderr, "\n");
}

void MyLog_PrintInfo(const char* func, const char* api, const char* msg)
{
    fprintf(stderr, "[INFO][%s] %s: %s\n", func, api ? api : "", msg ? msg : "");
}

void MyLog_PrintLog(int level, const char* func, const char* api, const char* msg)
{
    const char* tag = (level == LOG_ERROR) ? "ERROR" :
        (level == LOG_WARN) ? "WARN" : "INFO";
    fprintf(stderr, "[%s][%s] %s: %s\n", tag, func, api ? api : "", msg ? msg : "");
}

void MyLog_PrintNtError(const char* func, const char* api, LONG status, const char* extra)
{
    fprintf(stderr, "[%s] %s failed with status 0x%08lX", func, api,
        (unsigned long)status);
    if (extra) fprintf(stderr, " (%s)", extra);
    fprintf(stderr, "\n");
}

static const char* WinErrorMsg(DWORD err)
{
    static char buf[256];
    buf[0] = '\0';
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, buf, sizeof(buf), NULL);
    return buf;
}

/* ================================================================
 * 3. 符号引擎核心
 * ================================================================ */

 /* --- 符号加载回调 --- */
static BOOL CALLBACK SymbolCallback(HANDLE hProcess, ULONG ActionCode,
    ULONG64 CallbackData, ULONG64 UserContext)
{
    (void)hProcess;
    (void)UserContext;

    switch (ActionCode) {
    case CBA_EVENT: {
        PIMAGEHLP_CBA_EVENTW pEvent = (PIMAGEHLP_CBA_EVENTW)(ULONG_PTR)CallbackData;
        if (pEvent && pEvent->desc) {
            int pct = ExtractPercent(pEvent->desc);
            if (pct != -1) g_SymbolPercent = (DWORD)pct;
            if (g_hProgressEvent) SetEvent(g_hProgressEvent);
        }
        return TRUE;
    }
    case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE:
        return TRUE;
    case CBA_DEFERRED_SYMBOL_LOAD_CANCEL:
        return FALSE;
    default:
        return FALSE;
    }
}

BOOL SymEngine_InitInternal(void)
{
    HANDLE hProcess = GetCurrentProcess();
    const WCHAR* symPath =
        L"srv*C:\\Windows\\Symbols*https://msdl.microsoft.com/download/symbols";

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEBUG |
        SYMOPT_LOAD_ANYTHING);

    if (!SymInitializeW(hProcess, symPath, FALSE)) {
        MyLog_PrintWin32Error("SymEngine_InitInternal", "SymInitializeW", NULL);
        return FALSE;
    }

    g_hSymProcess = hProcess;
    g_hProgressEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

    SymRegisterCallbackW64(hProcess, SymbolCallback, 0);

    MyLog_PrintInfo("SymEngine_InitInternal", "SymInitialize",
        "符号引擎初始化成功!");
    return TRUE;
}

void SymEngine_CleanupInternal(void)
{
    if (g_hSymProcess) {
        SymCleanup(g_hSymProcess);
        g_hSymProcess = NULL;

        for (int i = 0; i < MAX_LOADED_MODULES; ++i)
            g_LoadedModules[i].isLoaded = FALSE;

        MyLog_PrintInfo("SymEngine_CleanupInternal", NULL, "符号引擎已清理!");
    }
}

ULONG64 SymbolActor_LoadModuleInternal(PCWSTR modulePath)
{
    if (!modulePath) {
        MyLog_PrintLog(LOG_ERROR, "SymbolActor_LoadModuleInternal", NULL,
            "传入模块路径为空指针");
        return 0;
    }

    MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL,
        "==========================================================");
    {
        char buf[1024];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Module : %ls", modulePath);
        MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
    }

    /* 1. 缓存检查 */
    for (int i = 0; i < MAX_LOADED_MODULES; ++i) {
        if (g_LoadedModules[i].isLoaded &&
            wcscmp(g_LoadedModules[i].modulePath, modulePath) == 0) {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "Cache Hit, SymBase = 0x%llX",
                (unsigned long long)g_LoadedModules[i].SymBase);
            MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
            return g_LoadedModules[i].SymBase;
        }
    }
    MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, "Cache Miss");

    /* 2. 加载模块 */
    SetLastError(0);
    ULONG64 symBaseTmp = SymLoadModuleExW(g_hSymProcess, NULL, modulePath,
        NULL, 0, 0, NULL, 0);
    DWORD err1 = GetLastError();

    if (symBaseTmp == 0 && err1 != 0) {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "SymLoadModuleExW 返回0, LastError=%lu (%s)，尝试通过模块信息获取基址",
            (unsigned long)err1, WinErrorMsg(err1));
        MyLog_PrintLog(LOG_WARN, "SymbolActor_LoadModuleInternal", NULL, buf);
    }

    /* 3. 查询模块信息 */
    IMAGEHLP_MODULEW64 modInfo;
    memset(&modInfo, 0, sizeof(modInfo));
    modInfo.SizeOfStruct = sizeof(modInfo);

    ULONG64 queryBase = (symBaseTmp != 0) ? symBaseTmp : 0;
    BOOL bRet = SymGetModuleInfoW64(g_hSymProcess, queryBase, &modInfo);

    if (bRet) {
        char buf[512];
        MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL,
            "SymGetModuleInfo 成功");
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "BaseOfImage      : 0x%llX",
            (unsigned long long)modInfo.BaseOfImage);
        MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "ImageName        : %ls", modInfo.ImageName);
        MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "LoadedImageName  : %ls", modInfo.LoadedImageName);
        MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "LoadedPdbName    : %ls", modInfo.LoadedPdbName);
        MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);

        if (symBaseTmp == 0) {
            symBaseTmp = modInfo.BaseOfImage;
            MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL,
                "使用 BaseOfImage 作为 SymBase");
        }
    }
    else {
        DWORD err2 = GetLastError();
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "SymGetModuleInfoW64 失败, LastError=%lu (%s)",
            (unsigned long)err2, WinErrorMsg(err2));
        MyLog_PrintLog(LOG_ERROR, "SymbolActor_LoadModuleInternal", NULL, buf);
    }

    /* 4. 写入缓存 */
    if (symBaseTmp != 0) {
        for (int i = 0; i < MAX_LOADED_MODULES; ++i) {
            if (!g_LoadedModules[i].isLoaded) {
                wcsncpy_s(g_LoadedModules[i].modulePath,
                    _countof(g_LoadedModules[i].modulePath),
                    modulePath, _TRUNCATE);
                g_LoadedModules[i].baseAddr = 0;
                g_LoadedModules[i].SymBase = symBaseTmp;
                g_LoadedModules[i].isLoaded = TRUE;

                char buf[128];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Cache Saved -> Slot %d", i);
                MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
                break;
            }
        }
        {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "SUCCESS, SymBase = 0x%llX",
                (unsigned long long)symBaseTmp);
            MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL, buf);
        }
    }
    else {
        MyLog_PrintLog(LOG_ERROR, "SymbolActor_LoadModuleInternal", NULL,
            "FAILED: 无法获取有效模块基址");
    }

    MyLog_PrintLog(LOG_INFO, "SymbolActor_LoadModuleInternal", NULL,
        "==========================================================");
    return symBaseTmp;
}

/* --- 1. 符号 -> 地址（返回相对偏移） --- */
ULONG64 SymbolActor_SymbolToAddrInternal(PCWSTR modulePath, PCWSTR symbolName)
{
    if (!modulePath || !symbolName) return 0;

    ULONG64 symBase = SymbolActor_LoadModuleInternal(modulePath);
    if (symBase == 0) {
        MyLog_PrintLog(LOG_ERROR, "SymEngine_SymbolToAddr",
            "SymbolActor_LoadModuleInternal", "symBase=0");
        return 0;
    }

    ULONG64 symbolOffset = 0;
    ULONG symInfoSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR);
    PSYMBOL_INFOW pSym = (PSYMBOL_INFOW)calloc(1, symInfoSize);

    if (pSym) {
        pSym->SizeOfStruct = sizeof(SYMBOL_INFOW);
        pSym->MaxNameLen = MAX_SYM_NAME;

        if (SymFromNameW(g_hSymProcess, symbolName, pSym)) {
            symbolOffset = pSym->Address - symBase;
        }
        else {
            char buf[512];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "modulePath=%ls,symbolName=%ls", modulePath, symbolName);
            MyLog_PrintWin32Error("SymEngine_SymbolToAddr", "SymFromNameW", buf);
        }
        free(pSym);
    }
    return symbolOffset;
}

/* --- 2. 地址(偏移) -> 符号 --- */
BOOL SymbolActor_AddrToSymbolInternal(PCWSTR modulePath, ULONG64 offset,
    PWSTR outSymbolName, ULONG nameLen)
{
    if (!outSymbolName || nameLen == 0) return FALSE;

    ULONG64 baseAddr = SymbolActor_LoadModuleInternal(modulePath);
    if (baseAddr == 0) return FALSE;

    BOOL result = FALSE;
    ULONG symInfoSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR);
    PSYMBOL_INFOW pSym = (PSYMBOL_INFOW)calloc(1, symInfoSize);
    DWORD64 displacement = 0;

    if (pSym) {
        pSym->SizeOfStruct = sizeof(SYMBOL_INFOW);
        pSym->MaxNameLen = MAX_SYM_NAME;

        ULONG64 r3SimAddress = baseAddr + offset;
        if (SymFromAddrW(g_hSymProcess, r3SimAddress, &displacement, pSym)) {
            wcsncpy_s(outSymbolName, nameLen, pSym->Name, nameLen - 1);
            outSymbolName[nameLen - 1] = L'\0';
            result = TRUE;
        }
        else {
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "modulePath=%ls,offset=0x%llX",
                modulePath, (unsigned long long)offset);
            MyLog_PrintWin32Error("SymbolActor_AddrToSymbolInternal",
                "SymFromAddrW", buf);
        }
        free(pSym);
    }
    return result;
}

/* --- 3. 结构体成员偏移 --- */
LONG SymbolActor_GetStructOffsetInternal(PCWSTR modulePath,
    PCWSTR structName,
    PCWSTR memberName)
{
    if (!modulePath || !structName || !memberName) return -1;

    ULONG64 baseAddr = SymbolActor_LoadModuleInternal(modulePath);
    if (baseAddr == 0) return -1;

    LONG offset = -1;
    ULONG symInfoSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR);
    PSYMBOL_INFOW pSym = NULL;
    BYTE* buffer = NULL;
    PWSTR pName = NULL;

    pSym = (PSYMBOL_INFOW)calloc(1, symInfoSize);
    if (!pSym) goto Cleanup;

    pSym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSym->MaxNameLen = MAX_SYM_NAME;

    if (!SymGetTypeFromNameW(g_hSymProcess, baseAddr, structName, pSym))
        SymGetTypeFromNameW(g_hSymProcess, 0, structName, pSym);

    if (SymGetTypeFromNameW(g_hSymProcess, baseAddr, structName, pSym)) {
        ULONG numChildren = 0;
        if (SymGetTypeInfo(g_hSymProcess, baseAddr, pSym->TypeIndex,
            TI_GET_CHILDRENCOUNT, &numChildren)) {
            ULONG bufferSize = sizeof(TI_FINDCHILDREN_PARAMS) +
                numChildren * sizeof(ULONG);
            buffer = (BYTE*)calloc(1, bufferSize);
            if (buffer) {
                TI_FINDCHILDREN_PARAMS* params =
                    (TI_FINDCHILDREN_PARAMS*)buffer;
                params->Start = 0;
                params->Count = numChildren;

                if (SymGetTypeInfo(g_hSymProcess, baseAddr, pSym->TypeIndex,
                    TI_FINDCHILDREN, buffer)) {
                    ULONG* typeIdArray = (ULONG*)(buffer +
                        sizeof(TI_FINDCHILDREN_PARAMS));
                    for (ULONG i = 0; i < numChildren; ++i) {
                        pName = NULL;
                        if (SymGetTypeInfo(g_hSymProcess, baseAddr,
                            typeIdArray[i], TI_GET_SYMNAME,
                            &pName)) {
                            if (pName) {
                                if (wcscmp(pName, memberName) == 0) {
                                    SymGetTypeInfo(g_hSymProcess, baseAddr,
                                        typeIdArray[i],
                                        TI_GET_OFFSET, &offset);
                                }
                                LocalFree(pName);
                                pName = NULL;
                            }
                        }
                    }
                }
            }
        }
    }

Cleanup:
    if (buffer) free(buffer);
    if (pSym)   free(pSym);
    return offset;
}

/* ================================================================
 * 设备打开
 * ================================================================ */
BOOL OpenSymbolDevice(void)
{
    hSymbolDrv = CreateFileW(L"\\\\.\\SnowSymbol",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hSymbolDrv == INVALID_HANDLE_VALUE) {
        MyLog_PrintWin32Error("OpenSymbolDevice", "CreateFileW",
            "lpFileName=\\\\.\\SnowSymbol");
        return FALSE;
    }

    MyLog_PrintInfo("OpenSymbolDevice", "CreateFileW", "Symbol设备打开成功");
    return TRUE;
}

/* ================================================================
 * 5. 处理内核请求
 * ================================================================ */
/* P0-1: 符号服务等待 Actor 结果的超时（ms）。ring0 侧等待本侧响应的超时
 * 为 5 秒（SYMBOL_QUERY_TIMEOUT_SECONDS），此值须不超过 5 秒，避免 ring0
 * 已超时后本侧仍无限等待，导致 worker 线程永久卡死、进程退出被阻塞。 */
#define SYMBOL_SERVICE_WAIT_TIMEOUT_MS 5000

void SymbolService_ProcessRequest(SYMBOL_QUERY_REQUEST* req,
    SYMBOL_QUERY_RESPONSE* resp)
{
    resp->Status = STATUS_INVALID_PARAMETER;
    if (req->ModulePath[0] == L'\0') return;

    WCHAR fullPath[MAX_PATH] = { 0 };
    if (!GetKernelModulePath(req->ModulePath, fullPath) || fullPath[0] == L'\0') {
        resp->Status = STATUS_NOT_FOUND;
        return;
    }

    if (_wcsnicmp(fullPath, L"\\SystemRoot", 11) == 0) {
        WCHAR sysRoot[MAX_PATH] = { 0 };
        WCHAR convertedPath[MAX_PATH] = { 0 };

        DWORD len = GetEnvironmentVariableW(L"SystemRoot", sysRoot, _countof(sysRoot));
        if (len == 0 || len >= _countof(sysRoot)) {
            resp->Status = STATUS_NOT_FOUND;
            return;
        }

        if (swprintf(convertedPath, _countof(convertedPath),
            L"%s%s", sysRoot, fullPath + 11) < 0) {
            resp->Status = STATUS_INVALID_PARAMETER;
            return;
        }

        wcscpy_s(fullPath, _countof(fullPath), convertedPath);
    }

    SYMBOL_REQUEST* pReq = NULL;

    switch (req->qtype) {
    case QuerySymbolToAddress:
        pReq = SymbolActor_SubmitRequest(REQ_SYMBOL_TO_ADDR, fullPath,
            req->SymbolName, 0,
            NULL, NULL, NULL, 0);
        if (pReq) {
            if (WaitForSingleObject(pReq->hComplete,
                    SYMBOL_SERVICE_WAIT_TIMEOUT_MS) == WAIT_OBJECT_0) {
                if (pReq->ResultStatus == STATUS_SUCCESS) {
                    char buf[512];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "符号 %ls 解析成功!", req->SymbolName);
                    MyLog_PrintInfo("QuerySymbolToAddress",
                        "QuerySymbolToAddress", buf);
                    resp->Address = pReq->ResultAddress;
                    resp->Status = STATUS_SUCCESS;
                }
                else {
                    char buf[512];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "符号 %ls 解析失败", req->SymbolName);
                    MyLog_PrintLog(LOG_ERROR, "QuerySymbolToAddress",
                        "QuerySymbolToAddress", buf);
                    resp->Status = STATUS_NOT_FOUND;
                }
            }
            else {
                /* P0-1: 等待超时（Actor 不可用），回失败避免 worker 永久卡死 */
                MyLog_PrintLog(LOG_WARN, "QuerySymbolToAddress",
                    "SymbolActor", "符号请求超时");
                resp->Status = STATUS_UNSUCCESSFUL;
            }
            SymbolActor_ReleaseRequest(pReq);
        }
        break;

    case QueryAddressToSymbol:
        pReq = SymbolActor_SubmitRequest(REQ_ADDR_TO_SYMBOL, fullPath,
            NULL, req->Address,
            NULL, NULL,
            resp->SymbolName, 256);
        if (pReq) {
            if (WaitForSingleObject(pReq->hComplete,
                    SYMBOL_SERVICE_WAIT_TIMEOUT_MS) == WAIT_OBJECT_0) {
                resp->Status = pReq->ResultStatus;
            }
            else {
                /* P0-1: 等待超时，回失败避免 worker 永久卡死 */
                MyLog_PrintLog(LOG_WARN, "QueryAddressToSymbol",
                    "SymbolActor", "符号请求超时");
                resp->Status = STATUS_UNSUCCESSFUL;
            }
            SymbolActor_ReleaseRequest(pReq);
        }
        break;

    case QueryStructOffset:
        pReq = SymbolActor_SubmitRequest(REQ_STRUCT_OFFSET, fullPath,
            NULL, 0,
            req->StructOffset.StructName,
            req->StructOffset.MemberName,
            NULL, 0);
        if (pReq) {
            if (WaitForSingleObject(pReq->hComplete,
                    SYMBOL_SERVICE_WAIT_TIMEOUT_MS) == WAIT_OBJECT_0) {
                if (pReq->ResultStatus == STATUS_SUCCESS) {
                    resp->Offset = pReq->ResultOffset;
                    resp->Status = STATUS_SUCCESS;
                }
                else {
                    resp->Status = STATUS_NOT_FOUND;
                }
            }
            else {
                /* P0-1: 等待超时，回失败避免 worker 永久卡死 */
                MyLog_PrintLog(LOG_WARN, "QueryStructOffset",
                    "SymbolActor", "符号请求超时");
                resp->Status = STATUS_UNSUCCESSFUL;
            }
            SymbolActor_ReleaseRequest(pReq);
        }
        break;

    default:
        resp->Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
}

/* ================================================================
 * 工作线程
 * ================================================================ */
DWORD WINAPI SymbolService_WorkerThread(LPVOID p)
{
    (void)p;
    SYMBOL_QUERY_PACKET    pkt;
    SYMBOL_RESPONSE_PACKET respPkt;
    DWORD bytesRet = 0;

    MyLog_PrintInfo("SymbolService_WorkerThread", NULL, "Symbol Worker启动");

    while (!g_StopWorkerThreads) {
        if (hSymbolDrv == INVALID_HANDLE_VALUE) {
            Sleep(50);
            continue;
        }

        ZeroMemory(&pkt, sizeof(pkt));
        ZeroMemory(&respPkt, sizeof(respPkt));

        MyLog_PrintInfo("SymbolService_WorkerThread", NULL, "调用WaitRequest...");

        if (!IoControl(hSymbolDrv, IOCTL_WaitRequest,
            NULL, 0,
            &pkt, sizeof(pkt), &bytesRet)) {
            MyLog_PrintWin32Error("SymbolService_WorkerThread",
                "IOCTL_WaitRequest", NULL);
            if (g_StopWorkerThreads) break;
            Sleep(10);
            continue;
        }

        {
            char buf[64];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "收到请求,ID=%llu",
                (unsigned long long)pkt.RequestId);
            MyLog_PrintInfo("SymbolService_WorkerThread", NULL, buf);
        }

        SymbolService_ProcessRequest(&pkt.req, &respPkt.resp);
        respPkt.RequestId = pkt.RequestId;

        if (!IoControl(hSymbolDrv, IOCTL_SubmitResponse,
            &respPkt, sizeof(respPkt),
            NULL, 0, &bytesRet)) {
            MyLog_PrintWin32Error("SymbolService_WorkerThread",
                "IOCTL_SubmitResponse", "请求回复失败");
        }
        else {
            MyLog_PrintInfo("SymbolService_WorkerThread",
                "IOCTL_SubmitResponse", "请求回复成功!");
        }
    }

    MyLog_PrintInfo("SymbolService_WorkerThread", NULL, "Symbol Worker退出");
    return 0;
}

BOOL SymbolService_StartWorkers(void)
{
    g_StopWorkerThreads = FALSE;

    /* 初始化 Actor（原代码未显式调用，此处补上以便正常使用） */
    if (!SymbolActor_Init()) {
        MyLog_PrintLog(LOG_ERROR, "SymbolService_StartWorkers",
            "SymbolActor_Init", "Actor 初始化失败");
        return FALSE;
    }

    m_hThreads[0] = CreateThread(NULL, 0, SymbolService_WorkerThread,
        NULL, 0, NULL);
    return TRUE;
}

void SymbolService_StopWorkers(void)
{
    g_StopWorkerThreads = TRUE;

    if (hSymbolDrv != INVALID_HANDLE_VALUE)
        CancelIoEx(hSymbolDrv, NULL);

    if (m_hThreads[0]) {
        WaitForSingleObject(m_hThreads[0], INFINITE);
        CloseHandle(m_hThreads[0]);
        m_hThreads[0] = NULL;
    }

    if (hSymbolDrv != INVALID_HANDLE_VALUE) {
        CloseHandle(hSymbolDrv);
        hSymbolDrv = INVALID_HANDLE_VALUE;
    }

    SymbolActor_Shutdown();
}

/* ================================================================
 * Actor 模型
 * ================================================================ */
static void Queue_Push(SYMBOL_REQUEST* pReq)
{
    EnterCriticalSection(&g_csQueue);
    pReq->pNext = NULL;
    if (g_pQueueTail)
        g_pQueueTail->pNext = pReq;
    else
        g_pQueueHead = pReq;
    g_pQueueTail = pReq;
    SetEvent(g_hQueueNotEmpty);
    LeaveCriticalSection(&g_csQueue);
}

static SYMBOL_REQUEST* Queue_Pop(void)
{
    EnterCriticalSection(&g_csQueue);
    SYMBOL_REQUEST* pReq = g_pQueueHead;
    if (pReq) {
        g_pQueueHead = pReq->pNext;
        if (!g_pQueueHead) g_pQueueTail = NULL;
        if (g_pQueueHead) SetEvent(g_hQueueNotEmpty);
    }
    LeaveCriticalSection(&g_csQueue);
    return pReq;
}

SYMBOL_REQUEST* SymbolActor_SubmitRequest(SymbolRequestType reqType,
    PCWSTR pModulePath,
    PCWSTR pSymbolName,
    ULONG64 address,
    PCWSTR pStructName,
    PCWSTR pMemberName,
    PWSTR pOutName,
    ULONG nameLen)
{
    SYMBOL_REQUEST* pReq =
        (SYMBOL_REQUEST*)calloc(1, sizeof(SYMBOL_REQUEST));
    if (!pReq) return NULL;

    pReq->reqType = reqType;

    if (pModulePath) {
        wcsncpy_s(pReq->ModulePath, _countof(pReq->ModulePath),
            pModulePath, _TRUNCATE);
    }
    if (pSymbolName) {
        wcsncpy_s(pReq->SymbolName, _countof(pReq->SymbolName),
            pSymbolName, _TRUNCATE);
    }
    if (pStructName) {
        wcsncpy_s(pReq->StructName, _countof(pReq->StructName),
            pStructName, _TRUNCATE);
    }
    if (pMemberName) {
        wcsncpy_s(pReq->MemberName, _countof(pReq->MemberName),
            pMemberName, _TRUNCATE);
    }

    pReq->Address = address;
    pReq->pOutputName = pOutName;
    pReq->NameLen = nameLen;

    pReq->hComplete = CreateEventW(NULL, FALSE, FALSE, NULL);

    /* P0-1: 引用计数，调用方与 Actor 线程各持 1 份，超时释放安全 */
    pReq->RefCount = 2;

    Queue_Push(pReq);
    return pReq;
}

void SymbolActor_ReleaseRequest(SYMBOL_REQUEST* pReq)
{
    if (!pReq) return;
    if (InterlockedDecrement(&pReq->RefCount) == 0) {
        if (pReq->hComplete) CloseHandle(pReq->hComplete);
        free(pReq);
    }
}

/* Actor 线程 */
static DWORD WINAPI SymbolActor_Thread(LPVOID p)
{
    (void)p;

    MyLog_PrintInfo("SymbolActor_Thread", NULL, "线程启动,等待请求...");

    if (!SymEngine_InitInternal()) {
        /* P0-2: 引擎初始化失败不再退出线程。退出会让队列失去唯一消费者：
         * 内部调用方全部空等超时、符号服务 INFINITE 卡死，且 g_hSymbolThread
         * 句柄残留导致重建检查永远失效。改为置失败标志并保持运行，
         * 对 SHUTDOWN 以外的请求快速失败。 */
        g_SymEngineFailed = TRUE;
        MyLog_PrintLog(LOG_ERROR, "SymbolActor_Thread",
            "SymEngine_InitInternal", "符号引擎初始化失败，后续符号请求将快速失败");
    } else {
        g_SymEngineReady = TRUE;
    }

    for (;;) {
        WaitForSingleObject(g_hQueueNotEmpty, INFINITE);

        SYMBOL_REQUEST* pReq = Queue_Pop();
        if (!pReq) continue;

        /* P0-2: 引擎失败时除 SHUTDOWN 外一律快速失败，提交方立即拿到结果；
         * SHUTDOWN 走正常退出路径，保证进程可正常关闭。 */
        if (g_SymEngineFailed && pReq->reqType != REQ_SHUTDOWN) {
            pReq->ResultStatus = STATUS_UNSUCCESSFUL;
            if (pReq->hComplete) SetEvent(pReq->hComplete);
            SymbolActor_ReleaseRequest(pReq);
            continue;
        }

        switch (pReq->reqType) {
        case REQ_PRELOAD_WIN32KFULL: {
            WCHAR fullPath[260];
            WCHAR sysRoot[260] = { 0 };
            GetEnvironmentVariableW(L"SystemRoot", sysRoot, 260);
            _snwprintf_s(fullPath, _countof(fullPath), _TRUNCATE,
                L"%ls\\System32\\win32kfull.sys", sysRoot);

            ULONG64 r = SymbolActor_LoadModuleInternal(fullPath);
            pReq->ResultStatus = (r != 0) ? STATUS_SUCCESS
                : STATUS_UNSUCCESSFUL;
            if (r == 0)
                MyLog_PrintLog(LOG_ERROR, "SymbolActor_Thread",
                    "SymbolActor_LoadModuleInternal",
                    "预加载 win32kfull.sys 失败");
            break;
        }
        case REQ_LOAD_MODULE:
            pReq->ResultAddress = SymbolActor_LoadModuleInternal(pReq->ModulePath);
            pReq->ResultStatus = STATUS_SUCCESS;
            break;

        case REQ_SYMBOL_TO_ADDR:
            pReq->ResultAddress = SymbolActor_SymbolToAddrInternal(
                pReq->ModulePath, pReq->SymbolName);
            pReq->ResultStatus = (pReq->ResultAddress != 0)
                ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            break;

        case REQ_ADDR_TO_SYMBOL:
            if (SymbolActor_AddrToSymbolInternal(pReq->ModulePath,
                pReq->Address,
                pReq->pOutputName,
                pReq->NameLen))
                pReq->ResultStatus = STATUS_SUCCESS;
            else
                pReq->ResultStatus = STATUS_NOT_FOUND;
            break;

        case REQ_STRUCT_OFFSET:
            pReq->ResultOffset = SymbolActor_GetStructOffsetInternal(
                pReq->ModulePath, pReq->StructName, pReq->MemberName);
            pReq->ResultStatus = (pReq->ResultOffset != -1)
                ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            break;

        case REQ_SHUTDOWN:
            if (pReq->hComplete) SetEvent(pReq->hComplete);
            SymbolActor_ReleaseRequest(pReq);
            goto thread_exit;

        default:
            pReq->ResultStatus = STATUS_INVALID_PARAMETER;
            break;
        }

        if (pReq->hComplete) SetEvent(pReq->hComplete);
        SymbolActor_ReleaseRequest(pReq);
    }

thread_exit:
    SymEngine_CleanupInternal();
    MyLog_PrintInfo("SymbolActor_Thread", NULL, "线程退出");
    return 0;
}

BOOL SymbolActor_Init(void)
{
    g_hQueueNotEmpty = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_hQueueNotEmpty) return FALSE;

    InitializeCriticalSection(&g_csQueue);

    g_hSymbolThread = CreateThread(NULL, 0, SymbolActor_Thread, NULL, 0, NULL);
    if (!g_hSymbolThread) {
        DeleteCriticalSection(&g_csQueue);
        CloseHandle(g_hQueueNotEmpty);
        g_hQueueNotEmpty = NULL;
        return FALSE;
    }
    return TRUE;
}

void SymbolActor_Shutdown(void)
{
    SYMBOL_REQUEST* pReq = SymbolActor_SubmitRequest(REQ_SHUTDOWN,
        NULL, NULL, 0,
        NULL, NULL, NULL, 0);
    if (pReq) {
        WaitForSingleObject(pReq->hComplete, INFINITE);
        CloseHandle(pReq->hComplete);
        free(pReq);
    }

    if (g_hSymbolThread) {
        WaitForSingleObject(g_hSymbolThread, INFINITE);
        CloseHandle(g_hSymbolThread);
        g_hSymbolThread = NULL;
    }

    DeleteCriticalSection(&g_csQueue);

    if (g_hQueueNotEmpty) {
        CloseHandle(g_hQueueNotEmpty);
        g_hQueueNotEmpty = NULL;
    }
}

/* ================================================================
 * 从字符串中提取百分比
 * ================================================================ */
int ExtractPercent(const WCHAR* msg)
{
    if (!msg) return -1;

    size_t len = wcslen(msg);
    for (size_t i = 0; i < len; ++i) {
        WCHAR ch = msg[i];
        if (ch >= L'0' && ch <= L'9') {
            int num = 0;
            while (i < len) {
                ch = msg[i];
                if (ch < L'0' || ch > L'9') break;
                num = num * 10 + (ch - L'0');
                ++i;
            }
            if (num < 0)   num = 0;
            if (num > 100) num = 100;
            return num;
        }
    }
    return -1;
}