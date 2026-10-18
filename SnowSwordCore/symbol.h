#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include <wchar.h>

#pragma comment(lib, "dbghelp.lib")

/* ================================================================
* 常量
* ================================================================ */
#define WORKER_THREAD_COUNT 1

#define MAX_LOADED_MODULES 32

#define MAX_SYM_NAME 2000

#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2

    /* ================================================================
    * 驱动通信结构体（与内核完全对齐）
    * ================================================================ */
typedef enum _QUERY_TYPE {
    QuerySymbolToAddress = 0,
    QueryAddressToSymbol = 1,
    QueryStructOffset = 2
} QUERY_TYPE;

typedef struct _STRUCT_OFFSET {
    WCHAR StructName[64];
    WCHAR MemberName[64];
} STRUCT_OFFSET;

/*
    * 布局说明（自然对齐）：
    *   ModulePath[256]  : offset 0   size 512
    *   qtype            : offset 512 size 4
    *   (编译器自动填充 4 字节对齐联合体)
    *   union            : offset 520 size 512
    *   总计: 1032 字节
    */
typedef struct _SYMBOL_QUERY_REQUEST {
    WCHAR ModulePath[256];
    QUERY_TYPE qtype;
    union {
        WCHAR         SymbolName[256];
        ULONG64       Address;
        STRUCT_OFFSET StructOffset;
    };
} SYMBOL_QUERY_REQUEST;

typedef struct _SYMBOL_QUERY_RESPONSE {
    LONG Status;
    union {
        ULONG64 Address;
        LONG    Offset;
        WCHAR   SymbolName[256];
    };
} SYMBOL_QUERY_RESPONSE;

typedef struct _SYMBOL_QUERY_PACKET {
    ULONG64 RequestId;
    SYMBOL_QUERY_REQUEST req;
} SYMBOL_QUERY_PACKET;

typedef struct _SYMBOL_RESPONSE_PACKET {
    ULONG64 RequestId;
    SYMBOL_QUERY_RESPONSE resp;
} SYMBOL_RESPONSE_PACKET;

/* ================================================================
    * Actor 请求类型
    * ================================================================ */
typedef enum _SymbolRequestType {
    REQ_PRELOAD_WIN32KFULL = 0,
    REQ_LOAD_MODULE = 1,
    REQ_SYMBOL_TO_ADDR = 2,
    REQ_ADDR_TO_SYMBOL = 3,
    REQ_STRUCT_OFFSET = 4,
    REQ_SHUTDOWN = 99
} SymbolRequestType;

typedef struct _SYMBOL_REQUEST SYMBOL_REQUEST;
struct _SYMBOL_REQUEST {
    SymbolRequestType reqType;

    /* 输入 */
    WCHAR    ModulePath[260];
    WCHAR    SymbolName[256];
    WCHAR    StructName[64];
    WCHAR    MemberName[64];
    ULONG64  Address;
    ULONG    NameLen;
    PWSTR    pOutputName;

    /* 输出 */
    LONG     ResultStatus;
    ULONG64  ResultAddress;
    LONG     ResultOffset;

    /* 同步 */
    HANDLE   hComplete;
    /* P0-1: 引用计数（SubmitRequest 置 2：调用方 1 + Actor 1），
     * 保证超时释放安全，避免 Actor 处理期间 use-after-free */
    LONG     RefCount;
    SYMBOL_REQUEST* pNext;
};

/* ================================================================
    * 模块缓存
    * ================================================================ */
typedef struct _LOADED_MODULE {
    WCHAR   modulePath[1024];
    ULONG64 baseAddr;
    ULONG64 SymBase;
    BOOL    isLoaded;
} LOADED_MODULE;

typedef struct _LOAD_MODULE_PARAMS {
    PWSTR   modulePath;
    ULONG64 imageBase;
    ULONG64 resultBase;
    BOOL    completed;
    HANDLE  hEvent;
} LOAD_MODULE_PARAMS;

/* ================================================================
    * 全局变量
    * ================================================================ */
extern HANDLE hSymbolDrv;
extern HANDLE g_hProgressEvent;
extern DWORD  g_SymbolPercent;

/* ================================================================
    * 驱动 I/O（外部提供）
    * ================================================================ */
BOOL  IoControl(HANDLE hDrv, DWORD code,
    LPVOID inBuf, DWORD inSize,
    LPVOID outBuf, DWORD outSize,
    LPDWORD bytesRet);
DWORD CTL_CODE_GEN(DWORD lngFunction);

/* ================================================================
    * 符号引擎
    * ================================================================ */
BOOL    SymEngine_InitInternal(void);
void    SymEngine_CleanupInternal(void);

ULONG64 SymbolActor_LoadModuleInternal(PCWSTR modulePath);
ULONG64 SymbolActor_SymbolToAddrInternal(PCWSTR modulePath, PCWSTR symbolName);
BOOL    SymbolActor_AddrToSymbolInternal(PCWSTR modulePath, ULONG64 offset,
    PWSTR outSymbolName, ULONG nameLen);
LONG    SymbolActor_GetStructOffsetInternal(PCWSTR modulePath,
    PCWSTR structName,
    PCWSTR memberName);

/* ================================================================
    * 设备 + 工作线程
    * ================================================================ */
BOOL  OpenSymbolDevice(void);
void  SymbolService_ProcessRequest(SYMBOL_QUERY_REQUEST* req,
    SYMBOL_QUERY_RESPONSE* resp);
DWORD WINAPI SymbolService_WorkerThread(LPVOID p);
BOOL  SymbolService_StartWorkers(void);
void  SymbolService_StopWorkers(void);

/* ================================================================
    * Actor 模型
    * ================================================================ */
BOOL  SymbolActor_Init(void);
void  SymbolActor_Shutdown(void);

void SymbolActor_ReleaseRequest(SYMBOL_REQUEST* pReq);

SYMBOL_REQUEST* SymbolActor_SubmitRequest(SymbolRequestType reqType,
    PCWSTR pModulePath,
    PCWSTR pSymbolName,
    ULONG64 address,
    PCWSTR pStructName,
    PCWSTR pMemberName,
    PWSTR pOutName,
    ULONG nameLen);

int   ExtractPercent(const WCHAR* msg);

#ifdef __cplusplus
}
#endif