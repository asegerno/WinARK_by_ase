/*
 * dispatch.h -- SnowSwordCore 结构化派遣函数（MajorFunction）原始地址恢复 API
 *
 * 设计约束：
 *   1. 本 API 不含任何 GUI / ListView / CLI 文本概念，只输出结构化数据。
 *   2. 内存所有权显式声明，见文件末尾「内存所有权契约」。
 *   3. 恢复算法与判定逻辑逐行等价于 ring3/modules/KernelHook/Dispatch*.inc，
 *      常量（DISPATCH_BASE / DISPATCH_STEP 等）刻意保持原值。
 */
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

/* ------------------------------------------------------------------
 * 槽位规模
 *
 * IRP_MJ_MAXIMUM_FUNCTION = 0x1B，槽位数组为 0..0x1B 共 28 项，
 * 与 DispatchTypes.bi 的 MajorFunction(0 To IRP_MJ_MAXIMUM_FUNCTION) 一致。
 * ------------------------------------------------------------------ */
#define SS_IRP_MJ_MAXIMUM_FUNCTION   0x1B
#define SS_DISPATCH_SLOT_COUNT       (SS_IRP_MJ_MAXIMUM_FUNCTION + 1)   /* 28 */
#define SS_FASTIO_FUNCTION_COUNT     27

/* ------------------------------------------------------------------
 * 状态与枚举：数值与 DispatchTypes.bi 完全一致
 * ------------------------------------------------------------------ */

typedef enum _SS_DISPATCH_STATUS {
    SS_DISPATCH_STATUS_PARSE_FAILED      = 0,
    SS_DISPATCH_STATUS_RECOVERED         = 1,
    SS_DISPATCH_STATUS_NO_MATCH          = 2,
    /* 以下为 Core 侧扩展，不参与算法判定 */
    SS_DISPATCH_STATUS_INVALID_PARAMETER = 3,
    SS_DISPATCH_STATUS_OUT_OF_MEMORY     = 4
} SS_DISPATCH_STATUS;

typedef enum _SS_DISPATCH_MODEL_KIND {
    SS_MODEL_UNKNOWN        = 0,
    SS_MODEL_GENERIC_WDM    = 1,
    SS_MODEL_FRAMEWORK_WDM  = 2,
    SS_MODEL_WDDM           = 3,
    SS_MODEL_KMDF           = 4
} SS_DISPATCH_MODEL_KIND;

typedef enum _SS_WDM_FRAMEWORK_KIND {
    SS_FRAMEWORK_NONE      = 0,
    SS_FRAMEWORK_HID       = 1,
    SS_FRAMEWORK_STORPORT  = 2,
    SS_FRAMEWORK_SCSIPORT  = 3,
    SS_FRAMEWORK_NDIS      = 4,
    SS_FRAMEWORK_KS        = 5,
    SS_FRAMEWORK_OTHER     = 6
} SS_WDM_FRAMEWORK_KIND;

typedef enum _SS_DISPATCH_OWNER_KIND {
    SS_OWNER_UNKNOWN        = 0,
    SS_OWNER_DRIVER         = 1,
    SS_OWNER_FRAMEWORK      = 2,
    SS_OWNER_KERNEL_DEFAULT = 3
} SS_DISPATCH_OWNER_KIND;

typedef enum _SS_DISPATCH_SLOT_STATE {
    SS_SLOT_UNRESOLVED      = 0,
    SS_SLOT_RECOVERED       = 1,
    SS_SLOT_FRAMEWORK_OWNED = 2,
    SS_SLOT_DEFAULT         = 3
} SS_DISPATCH_SLOT_STATE;

typedef enum _SS_DISPATCH_SOURCE {
    SS_SOURCE_UNKNOWN                = 0,
    SS_SOURCE_DIRECT_STORE           = 1,
    SS_SOURCE_REP_STOSQ              = 2,
    SS_SOURCE_IMPORTED_FRAMEWORK     = 3,
    SS_SOURCE_FRAMEWORK_CLASSIFY     = 4,
    SS_SOURCE_FRAMEWORK_BASELINE     = 5,
    SS_SOURCE_DEFAULT                = 6,
    SS_SOURCE_FRAMEWORK_DEFAULT      = 7
} SS_DISPATCH_SOURCE;

/* ------------------------------------------------------------------
 * KMDF（Wdf01000）派遣基线
 *
 * SS_KMDF_POLICY_* 数值与 ring3 ModKernel.Inc 的 KMDF_DISPATCH_POLICY、
 * ring0 KmdfCallbacks.h 的 _KMDF_DISPATCH_POLICY 完全一致。
 * ------------------------------------------------------------------ */
typedef enum _SS_KMDF_DISPATCH_POLICY {
    SS_KMDF_POLICY_UNKNOWN             = 0,
    SS_KMDF_POLICY_ALL_DISPATCH        = 1,
    SS_KMDF_POLICY_ALL_DISPATCH_WITH_LOCK = 2,
    SS_KMDF_POLICY_MIXED               = 3
} SS_KMDF_DISPATCH_POLICY;

/*
 * SS_KMDF_DRIVER_INFO 与 VB KMDF_DRIVER_INFO（ModKernel.Inc）、
 * ring0 KMDF_DRIVER_INFO（KmdfCallbacks.h）**逐字节一致（40 字节，4 字节对齐）**，
 * 因为该结构经 IOCTL 在 ring3 / ring0 间传递。字段顺序不得调整。
 */
typedef struct _SS_KMDF_DRIVER_INFO {
    UINT8   isKmdf;                 /* +0  KMDF 框架驱动 */
    UINT8   ownsDispatch;           /* +1  框架当前持有派遣表 */
    UINT8   dispatchPolicyKnown;    /* +2  PDB 绑定策略已解析 */
    UINT8   reserved;               /* +3  对齐填充 */
    ULONG   driverInitFlags;        /* +4  bit1(&H2)=NoDispatchOverride */
    ULONG   dispatchPolicy;         /* +8  SS_KMDF_DISPATCH_POLICY */
    ULONG   reserved2;              /* +12 */
    ULONG64 fxDriver;               /* +16 FxDriver 对象地址 */
    ULONG64 dispatch;               /* +24 FxDriver::Dispatch   统一派遣 */
    ULONG64 dispatchWithLock;       /* +32 FxDriver::DispatchWithLock */
} SS_KMDF_DRIVER_INFO;              /* 总长 40 */

/*
 * KMDF overlay 的三种处置，严格对应 ApplyKmdfDispatchBaseline（DispatchKmdf.Inc）：
 *   SKIP                —— query 失败 / OwnsDispatch!=1 / NoDispatchOverride：
 *                          原实现 Exit Sub，完全不动既有 generic 结果。
 *   FRAMEWORK_BASELINE  —— BuildKmdfDispatchBaseline 与 Wdf01000 PE 校验均通过：
 *                          28 槽发布框架统一派遣地址（Recovered/Framework/Baseline）。
 *   FRAMEWORK_OWNED     —— 框架拥有派遣但策略/可执行地址未通过验证：
 *                          不发布地址，28 槽标记 FrameworkOwned 并清空 pre-framework 存储。
 */
typedef enum _SS_KMDF_DISPOSITION {
    SS_KMDF_SKIP                    = 0,
    SS_KMDF_FRAMEWORK_BASELINE      = 1,
    SS_KMDF_FRAMEWORK_OWNED_FALLBACK = 2
} SS_KMDF_DISPOSITION;

/* SS_KMDF_BASELINE_OUTPUT 依赖 SS_DISPATCH_SLOT，定义在该结构之后。 */

/* ------------------------------------------------------------------
 * 结构化输出
 * ------------------------------------------------------------------ */

typedef struct _SS_DISPATCH_SLOT {
    ULONG   irpIndex;       /* 0..SS_IRP_MJ_MAXIMUM_FUNCTION */
    BOOL    valid;          /* MajorFunction[irpIndex].Valid */
    ULONG64 moduleBase;     /* 恢复出的归属模块基址 */
    ULONG   functionRva;    /* 恢复出的模块内 RVA */
    INT     state;          /* SS_DISPATCH_SLOT_STATE */
    INT     ownerKind;      /* SS_DISPATCH_OWNER_KIND */
    INT     source;         /* SS_DISPATCH_SOURCE */
    ULONG   confidence;
} SS_DISPATCH_SLOT;

typedef struct _SS_DISPATCH_RESULT {
    INT     modelKind;          /* SS_DISPATCH_MODEL_KIND */
    INT     frameworkKind;      /* SS_WDM_FRAMEWORK_KIND */
    ULONG   modelConfidence;
    ULONG   hitCount;
    ULONG   confidence;
    ULONG   fastIoDispatchRva;  /* FastIoDispatch 指针的模块内 RVA，0 表示未恢复 */
    ULONG   slotCount;          /* 恒为 SS_DISPATCH_SLOT_COUNT */
    SS_DISPATCH_SLOT* slots;    /* 长度 slotCount，随本结构一并释放 */
} SS_DISPATCH_RESULT;

/*
 * KMDF 基线构造结果（固定 28 槽，调用方拥有，无堆分配）。
 * 语义等价于 ApplyKmdfDispatchBaseline 中喂给 ApplyDispatchRecoveryResult
 * 的那个 DRIVER_DISPATCH_RECOVERY_OUTPUT（映射前的中间结构）。
 */
typedef struct _SS_KMDF_BASELINE_OUTPUT {
    INT     disposition;        /* SS_KMDF_DISPOSITION */
    INT     modelKind;          /* SS_MODEL_KMDF */
    ULONG   modelConfidence;    /* baseline=100；fallback/skip=0 */
    ULONG   hitCount;           /* baseline=28；fallback/skip=0 */
    ULONG   confidence;         /* baseline=100；fallback/skip=0 */
    ULONG   targetRva;          /* 诊断：build 接受时的框架派遣 RVA，否则 0 */
    SS_DISPATCH_SLOT slots[SS_DISPATCH_SLOT_COUNT];
} SS_KMDF_BASELINE_OUTPUT;

/* ------------------------------------------------------------------
 * 宿主回调
 *
 * 跨模块扫描需要按模块名取「已加载基址 + 磁盘镜像字节」。
 * Core 不自行枚举内核模块、也不自行读文件，全部经由此回调由宿主提供。
 * ------------------------------------------------------------------ */

typedef struct _SS_MODULE_IMAGE {
    const BYTE* buffer;     /* 镜像文件字节，调用方拥有 */
    ULONG64     size;
    ULONG64     imageBase;  /* 运行时基址；0 表示未知，跨模块扫描将放弃该模块 */
} SS_MODULE_IMAGE;

typedef BOOL (WINAPI *SS_MODULE_LOAD_CALLBACK)(
    _In_  const WCHAR* moduleName,
    _In_  void*        userContext,
    _Out_ SS_MODULE_IMAGE* image);

/* 诊断日志回调；message 为 UTF-8，生命周期仅限本次调用。可为 NULL。 */
typedef void (WINAPI *SS_DISPATCH_LOG_CALLBACK)(
    _In_ void*       userContext,
    _In_ const char* functionName,
    _In_ const char* message);

/* ------------------------------------------------------------------
 * 输入请求
 * ------------------------------------------------------------------ */

typedef struct _SS_DISPATCH_REQUEST {
    /* [in] 驱动镜像文件字节。调用方拥有；Core 只读，不释放。
     *      必须在 SS_RecoverDispatchFromImage 返回前保持有效。 */
    const BYTE* imageBuffer;
    ULONG64     imageSize;

    /* [in] 运行时加载基址（用于 ModuleBase 字段与指针归一化） */
    ULONG64     imageBase;

    /* [in] 模块名（如 "Ntfs.sys"）。可为 NULL；NULL 时跳过跨模块扫描。
     *      调用方拥有，Core 不释放。 */
    const WCHAR* moduleName;

    /* [in] 运行时 MajorFunction 快照，用于 DispatchSlotDefault 判定。
     *      hasCurrentMajorFunction 为 FALSE 时忽略本字段。 */
    BOOL        hasCurrentMajorFunction;
    ULONG64     currentMajorFunction[SS_DISPATCH_SLOT_COUNT];

    /* [in] nt!IopInvalidDeviceRequest 地址；0 表示未知。 */
    ULONG64     iopInvalidDeviceRequest;

    /* [in] 跨模块扫描回调。可为 NULL；NULL 时跨模块扫描整体跳过。 */
    SS_MODULE_LOAD_CALLBACK loadModule;
    void*                   loadModuleContext;

    /* [in] 诊断日志回调。可为 NULL（静默）。 */
    SS_DISPATCH_LOG_CALLBACK logSink;
    void*                    logContext;
} SS_DISPATCH_REQUEST;

/* ------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------ */

/*
 * 从驱动镜像恢复 MajorFunction 原始地址。
 *
 * 成功（返回 SS_DISPATCH_STATUS_RECOVERED 或 _NO_MATCH）时 *result 非空，
 * 调用方必须调用 SS_DispatchFreeResult 释放。
 * 失败（_PARSE_FAILED / _INVALID_PARAMETER / _OUT_OF_MEMORY）时 *result 置 NULL。
 */
SS_API SS_DISPATCH_STATUS SS_RecoverDispatchFromImage(
    _In_  const SS_DISPATCH_REQUEST* request,
    _Out_ SS_DISPATCH_RESULT**       result);

/*
 * 释放 SS_RecoverDispatchFromImage 返回的结果。
 * 递归释放 slots；传入 NULL 是合法的空操作。
 * 不得对同一指针调用两次；不得单独释放 result->slots。
 */
SS_API void SS_DispatchFreeResult(
    _In_opt_ SS_DISPATCH_RESULT* result);

/*
 * 把槽位名（"IRP_MJ_CREATE" 等）写入调用方缓冲。
 * 纯字符串映射，不持有任何状态；用于宿主自行格式化输出。
 * 返回写入的字符数（不含结尾 NUL），缓冲不足时返回所需字符数。
 */
SS_API ULONG SS_DispatchSlotName(
    _In_  ULONG  irpIndex,
    _Out_writes_opt_z_(nameCount) WCHAR* name,
    _In_  ULONG  nameCount);

/*
 * 构造 KMDF（Wdf01000）派遣基线 —— Phase 3 迁入，严格等价于
 * BuildKmdfDispatchBaseline + IsKmdfBaselineExecutable + ApplyKmdfDispatchBaseline
 * 中「build → PE 校验 → fallback」这段纯算法（不含 IOCTL、文件 IO、地址映射）。
 *
 * 入参：
 *   info          宿主通过 IOCTL_QueryKmdfDriverInfo 取回的 40 字节结构。
 *   wdfBase       Wdf01000.sys 运行时基址（GetKernelModuleBase）。
 *   wdfSize       Wdf01000.sys 运行时映像大小（SizeOfImage）。
 *   wdfImage      Wdf01000.sys 的磁盘镜像字节，由宿主读取后提供；Core 只读。
 *                 传 NULL 等价于原实现 ValidateKmdfBaselineImage 读文件失败。
 *   wdfFileSize   磁盘镜像字节数；wdfImage 为 NULL 时忽略。
 *   wdfImageSize  Wdf01000 的 SizeOfImage（须等于 wdfSize 的语义来源）。
 *   out           调用方拥有的输出结构（28 槽固定数组）。
 *
 * 返回：
 *   SS_DISPATCH_STATUS_RECOVERED         正常完成（含 SKIP / BASELINE / FALLBACK 三态，
 *                                        具体处置见 out->disposition）。
 *   SS_DISPATCH_STATUS_INVALID_PARAMETER info/out 为空。
 *
 * 处置语义见 SS_KMDF_DISPOSITION 注释。query 失败由宿主决定是否调用本 API。
 */
SS_API SS_DISPATCH_STATUS SS_BuildKmdfDispatchBaseline(
    _In_  const SS_KMDF_DRIVER_INFO* info,
    _In_  ULONG64 wdfBase,
    _In_  ULONG   wdfSize,
    _In_opt_ const BYTE* wdfImage,
    _In_  ULONG   wdfFileSize,
    _In_  ULONG   wdfImageSize,
    _Out_ SS_KMDF_BASELINE_OUTPUT* out);

/* ------------------------------------------------------------------
 * 内存所有权契约
 *
 * 调用方拥有（Core 只读、绝不释放）：
 *   request->imageBuffer
 *   request->moduleName
 *   request->loadModuleContext
 *   request->logContext
 *   loadModule 回调写入的 image->buffer
 *
 * Core 拥有（调用方必须用 SS_DispatchFreeResult 释放）：
 *   *result 及其 result->slots
 *
 * 生命周期要求：
 *   - imageBuffer 必须在 SS_RecoverDispatchFromImage 返回前保持有效。
 *   - loadModule 回调写入的 image->buffer 必须在该回调返回后、直到本次
 *     SS_RecoverDispatchFromImage 返回之前保持有效（Core 可能多次读取同一
 *     模块镜像）。Core 不会把该缓冲区的指针存留到 API 返回之后。
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * 跨语言（FreeBASIC / 其它 FFI）友好入口
 *
 * 动机：宿主编译器对 struct 的对齐/填充规则可能与 MSVC 不一致。
 * 下面这个请求结构体全部由 8 字节字段组成，不存在填充歧义；结果侧
 * 用不透明句柄 + 逐槽 getter 读取，完全避免结构体布局耦合。
 * 语义与 SS_RecoverDispatchFromImage 完全一致。
 * ------------------------------------------------------------------ */

typedef struct _SS_DISPATCH_REQUEST_FLAT {
    const BYTE*    imageBuffer;             /* [in] 调用方拥有 */
    ULONG64        imageSize;
    ULONG64        imageBase;
    const WCHAR*   moduleName;              /* [in] 可空 */
    const ULONG64* currentMajorFunction;    /* [in] 可空；非空表示长度 28 的 live 快照 */
    ULONG64        iopInvalidDeviceRequest;
    void*          loadModule;              /* [in] SS_MODULE_LOAD_CALLBACK；可空 */
    void*          loadModuleContext;       /* [in] 回调上下文；可空 */
    /* 说明：本结构全部字段为 8 字节，宿主编译器的填充规则不影响布局。
     * 回调写入的 image->buffer 必须存活到本次 API 返回（Core 可能递归加载多个模块）。 */
} SS_DISPATCH_REQUEST_FLAT;

/*
 * 恢复并返回不透明句柄。句柄即 SS_DISPATCH_RESULT*，但调用方不应解引用它。
 * 成功时 *resultHandle 非空，必须用 SS_DispatchFreeHandle 释放。
 */
SS_API SS_DISPATCH_STATUS SS_DispatchRecoverFlat(
    _In_  const SS_DISPATCH_REQUEST_FLAT* request,
    _Out_ void**                          resultHandle);

/* 释放句柄；NULL 合法。不得重复释放。 */
SS_API void SS_DispatchFreeHandle(
    _In_opt_ void* resultHandle);

/* 读取汇总信息；任何 out 参数可为 NULL。 */
SS_API BOOL SS_DispatchHandleInfo(
    _In_  void*  resultHandle,
    _Out_opt_ INT*   modelKind,
    _Out_opt_ INT*   frameworkKind,
    _Out_opt_ ULONG* modelConfidence,
    _Out_opt_ ULONG* hitCount,
    _Out_opt_ ULONG* confidence,
    _Out_opt_ ULONG* fastIoDispatchRva,
    _Out_opt_ ULONG* slotCount);

/* 读取单个槽；index 超出 slotCount 时返回 INVALID_PARAMETER。 */
SS_API BOOL SS_DispatchHandleSlot(
    _In_  void*  resultHandle,
    _In_  ULONG  index,
    _Out_opt_ BOOL*    valid,
    _Out_opt_ ULONG64* moduleBase,
    _Out_opt_ ULONG*   functionRva,
    _Out_opt_ INT*     state,
    _Out_opt_ INT*     ownerKind,
    _Out_opt_ INT*     source,
    _Out_opt_ ULONG*   confidence);

#ifdef __cplusplus
}
#endif