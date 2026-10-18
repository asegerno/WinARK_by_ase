/*
 * dispatch_internal.h -- 派遣恢复内部类型与常量
 *
 * 与 ring3/headers/DispatchTypes.bi 一一对应。命名前缀加 SS_ 以免与宿主冲突。
 * 注意：这些结构只在 Core 内部使用，不跨越 API 边界，因此不要求与 FreeBASIC
 * 版本字节级布局相同；要求的是**语义逐行等价**。
 *
 * 例外：third_party/udis86/udis86.h 的 struct ud / ud_operand 必须与
 * libudis86.lib 字节级一致，因为那是跨编译器边界的真实 ABI。
 */
#pragma once

#include "dispatch.h"
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <strsafe.h>

/* ==================================================================
 * 常量：刻意保持 DispatchTypes.bi 的原值，不得"顺手修正"
 * ================================================================== */
#define SS_DISPATCH_BASE                    0x70
#define SS_DISPATCH_STEP                    8
#define SS_DRIVER_OBJECT_FAST_IO_DISPATCH   0x50

#define SS_DISPATCH_MAX_CALL_DEPTH          5
#define SS_DISPATCH_FUNCTION_SCAN_RANGE     0x3000
#define SS_DISPATCH_MAX_VISITED             128
#define SS_DISPATCH_ENTRY_THUNK_SCAN_RANGE  0x80

#define SS_DISPATCH_CFG_MAX_BLOCKS          256
#define SS_DISPATCH_CFG_MAX_INSTRUCTIONS    4096
#define SS_DISPATCH_CFG_MAX_ITERATIONS      1024

#define SS_MODULE_NAME_MAX                  64

/* ==================================================================
 * 抽象寄存器值类型
 * ================================================================== */
typedef enum _SS_REG_VALUE_TYPE {
    SS_REG_UNKNOWN = 0,
    SS_REG_DRIVER_OBJECT,
    SS_REG_FUNCTION_RVA,
    SS_REG_IMAGE_RVA,
    SS_REG_IMMEDIATE,
    SS_REG_DRIVER_OBJECT_ADDRESS,
    /* Generic scanner: definite image address, pointer read from image, or
     * pointer produced by a runtime object. Executability is checked at use. */
    SS_REG_IMAGE_ADDRESS,
    SS_REG_STATIC_POINTER,
    SS_REG_OBJECT_POINTER,
    /* 框架注册扫描（HIDCLASS!HidRegisterMinidriver）专用 provenance。
     * 只有「框架注册 API 的入口状态」被显式注入时才会产生这两个值，
     * 其它扫描路径永远不会写出它们，因此不改变既有判定。 */
    SS_REG_FRAMEWORK_REGISTRATION,        /* 注册块指针（rcx = PHID_MINIDRIVER_REGISTRATION） */
    SS_REG_FRAMEWORK_REGISTRATION_FIELD   /* 注册块内字段地址；value = 字段字节偏移 */
} SS_REG_VALUE_TYPE;

/* 注册块中 DriverObject 指针的字段偏移。
 * 由 HIDCLASS.SYS!HidRegisterMinidriver 的真实指令序列确认：
 *     lea r14,[rcx+8] ; mov r14,[r14]      =>  registration + 8 == 宿主 DriverObject
 * 这不是「寄存器编号」常量，而是 API 结构的字段偏移。 */
#define SS_FRAMEWORK_REGISTRATION_DRIVER_OBJECT_OFFSET 8

/* 效果来源名（SetRecoveredDispatch 的 Source 参数，与原 VB 实现同义）。
 * 定义在头文件里是因为框架语义恢复扫描要经 SS_SCAN_CONTEXT 覆盖来源。 */
typedef enum _SS_SOURCE_NAME {
    SS_SOURCE_NAME_MOV = 0,
    SS_SOURCE_NAME_REP_STOSQ,
    SS_SOURCE_NAME_HID
} SS_SOURCE_NAME;

typedef struct _SS_REG_STATE {
    INT     valueType;   /* SS_REG_VALUE_TYPE */
    ULONG64 value;
} SS_REG_STATE;

/* 入口寄存器标签（FindForwardedDriverEntryRVA 用） */
#define SS_ENTRY_REG_UNKNOWN        0
#define SS_ENTRY_REG_DRIVER_OBJECT  1
#define SS_ENTRY_REG_REGISTRY_PATH  2

/* ==================================================================
 * 扫描上下文
 * ================================================================== */
typedef struct _SS_SCAN_CONTEXT {
    const BYTE* pDump;
    ULONG64     fileSize;
    ULONG64     imageBase;
    /* 运行时映像大小（SizeOfImage）。IsAddressInModule 等价判定需要它；
     * fileSize 是磁盘字节数，两者不可混用。0 表示未知。 */
    ULONG64     imageSize;
    WCHAR       moduleName[SS_MODULE_NAME_MAX];

    /* 宿主回调（跨模块扫描用） */
    SS_MODULE_LOAD_CALLBACK  loadModule;
    void*                    loadModuleContext;
    SS_DISPATCH_LOG_CALLBACK logSink;
    void*                    logContext;

    /* 效果来源覆盖（SS_SOURCE_NAME）。
     * 框架语义恢复扫描（HID 注册）产生的槽必须记为 ImportedFramework，
     * 而不是驱动自身的直接写入；0 = 不覆盖，保持逐指令形态归类。 */
    INT                      recoveredSourceName;
} SS_SCAN_CONTEXT;

/* ==================================================================
 * 输出
 * ================================================================== */
typedef struct _SS_FUNCTION_REF {
    BOOL    valid;
    ULONG64 moduleBase;
    ULONG   functionRva;
    INT     state;       /* SS_DISPATCH_SLOT_STATE */
    INT     ownerKind;   /* SS_DISPATCH_OWNER_KIND */
    INT     source;      /* SS_DISPATCH_SOURCE */
    ULONG   confidence;
} SS_FUNCTION_REF;

typedef struct _SS_RECOVERY_OUTPUT {
    SS_FUNCTION_REF majorFunction[SS_DISPATCH_SLOT_COUNT];
    ULONG           fastIoDispatchRva;
    ULONG           hitCount;
    ULONG           confidence;
} SS_RECOVERY_OUTPUT;

typedef struct _SS_RECOVERY_INPUT {
    const BYTE* pDump;
    ULONG64     fileSize;
    ULONG64     imageBase;
} SS_RECOVERY_INPUT;

/* ==================================================================
 * 被访问函数集合
 * ================================================================== */
typedef struct _SS_VISITED_FUNCTION {
    ULONG64      moduleBase;
    ULONG        functionRva;
    INT          driverObjectArgReg;
    SS_REG_STATE entryArg[4];
} SS_VISITED_FUNCTION;

typedef struct _SS_REACHABLE_VISITED {
    ULONG64 moduleBase;
    ULONG   functionRva;
} SS_REACHABLE_VISITED;

typedef struct _SS_SCAN_STATE {
    INT visitedCount;
    SS_VISITED_FUNCTION visited[SS_DISPATCH_MAX_VISITED];

    INT reachableVisitedCount;
    SS_REACHABLE_VISITED reachableVisited[SS_DISPATCH_MAX_VISITED];
} SS_SCAN_STATE;

/* ==================================================================
 * 抽象执行状态与 CFG
 * ================================================================== */
typedef struct _SS_ABSTRACT_STATE {
    SS_REG_STATE regState[16];
    INT64        stackOffset[32];
    SS_REG_STATE stackValue[32];
    INT64        rspDelta;
    BOOL         rspKnown;
} SS_ABSTRACT_STATE;

typedef struct _SS_CFG_INSTRUCTION {
    ULONG startRva;
    ULONG endRva;
    INT   terminator;      /* 0=ordinary, 1=Jcc, 2=Jmp, 3=Ret, 4=indirect, 5=invalid */
    INT   successorCount;
    ULONG successorRva[2];
} SS_CFG_INSTRUCTION;

typedef struct _SS_CFG_BLOCK {
    ULONG startRva;
    ULONG endRva;
    INT   terminator;
    INT   instructionCount;
    INT   successorCount;
    ULONG successorRva[2];
    BOOL  hasIn;
    BOOL  hasOut;
    BOOL  dirty;
    SS_ABSTRACT_STATE inState;
    SS_ABSTRACT_STATE outState;
} SS_CFG_BLOCK;

typedef struct _SS_CFG_FUNCTION {
    ULONG         entryRva;
    ULONG         beginRva;
    ULONG         endRva;
    INT           blockCount;
    SS_CFG_BLOCK* blocks;
} SS_CFG_FUNCTION;

/* ==================================================================
 * PE 导入/导出
 * ================================================================== */
typedef struct _SS_IMPORT_TARGET {
    BOOL   valid;
    WCHAR  moduleName[260];
    char   functionName[1025];  /* 导入名按 ASCII 处理，与原实现一致 */
    ULONG  ordinal;
    BOOL   byOrdinal;
} SS_IMPORT_TARGET;

/* ==================================================================
 * WDDM 检测证据（DispatchWddm.inc / WDDM_DETECTION_EVIDENCE）
 *
 * 只在 Core 内部使用，不跨越 API 边界；要求的是语义逐行等价。
 * ================================================================== */
typedef struct _SS_WDDM_DETECTION_EVIDENCE {
    BOOL    has23003F;
    BOOL    has230043;

    BOOL    hasLargeSelfCallbackTable;
    ULONG   callbackRun;
    ULONG   callbackTableRva;

    BOOL    hasIndirectRegistrationPath;

    ULONG   registrationHelperRva;
    ULONG   confidence;

    BOOL    hasKmdodInitialization;
    ULONG   kmdodVersion;
    ULONG   kmdodHelperRva;
    ULONG   kmdodCallbackCount;
} SS_WDDM_DETECTION_EVIDENCE;

/* 驱动模型信息（DRIVER_MODEL_INFO）。reason 用固定缓冲，避免 Core 内部
 * 依赖宿主分配；长度按原实现 reasonParts 的最坏情况取足。 */
#define SS_MODEL_REASON_MAX    192
#define SS_FRAMEWORK_OWNER_MAX 64
typedef struct _SS_DRIVER_MODEL_INFO {
    BOOL  isWddm;
    INT   confidence;
    char  reason[SS_MODEL_REASON_MAX];
    char  frameworkOwner[SS_FRAMEWORK_OWNER_MAX];
} SS_DRIVER_MODEL_INFO;

/* ==================================================================
 * 诊断日志
 * ================================================================== */
void ss_log_ctx(const SS_SCAN_CONTEXT* ctx, const char* functionName, const char* format, ...);

/* ==================================================================
 * PE 层（dispatch_pe.c）
 * ================================================================== */
ULONG64 ss_rva_to_foa(const BYTE* pFile, ULONG64 rva);
ULONG64 ss_foa_to_rva(const BYTE* pFile, ULONG64 foa);
BOOL    ss_is_rva_executable(const BYTE* pDump, ULONG64 rva);
BOOL    ss_get_image_entry_point_rva(const BYTE* pDump, ULONG64 fileSize, ULONG* outEntryRva);
BOOL    ss_read_raw_rva_dword(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, ULONG* value);
BOOL    ss_read_raw_rva_qword(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, ULONG64* value);
BOOL    ss_read_raw_rva_word(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, USHORT* value);
BOOL    ss_read_ascii_string_by_rva(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, char* out, size_t outCount);
BOOL    ss_get_runtime_function_bounds(const BYTE* pDump, ULONG64 fileSize, ULONG functionRva,
                                       ULONG* beginRva, ULONG* endRva);
BOOL    ss_read_image_pointer_rva(const SS_SCAN_CONTEXT* ctx, ULONG slotRva, ULONG* outRva);
BOOL    ss_get_image_layout(const BYTE* pDump, ULONG64 fileSize, ULONG64* preferredImageBase, ULONG* sizeOfImage);
BOOL    ss_get_pe_image_info(const BYTE* pDump, ULONG64* preferredImageBase, ULONG* sizeOfImage);
BOOL    ss_resolve_import_by_iat_rva(const BYTE* pDump, ULONG64 fileSize, ULONG64 iatRva,
                                     SS_IMPORT_TARGET* target);
BOOL    ss_resolve_export_rva(const BYTE* pDump, ULONG64 fileSize,
                              const char* functionName, ULONG ordinal, BOOL byOrdinal,
                              ULONG* functionRva);

/* ==================================================================
 * 反汇编辅助层（dispatch_disasm.c）
 * ================================================================== */
struct ud;
struct ud_operand;
union ud_lval;

INT     ss_ud_reg_to_gpr_index(int udRegType);
BOOL    ss_ud_is_64bit_gpr(const struct ud_operand* opr);
INT64   ss_ud_signed_value(const union ud_lval* value, INT bits);
INT64   ss_ud_memory_displacement(const struct ud_operand* opr);
ULONG   ss_ud_relative_target_rva(struct ud* u, const struct ud_operand* opr);
BOOL    ss_ud_mnemonic_writes_op0(int mnemonic);
ULONG   ss_get_rip_relative_operand_rva(struct ud* u, const struct ud_operand* opr);

void    ss_clear_reg(SS_REG_STATE* regState);
void    ss_copy_reg(SS_REG_STATE* dst, const SS_REG_STATE* src);
void    ss_invalidate_volatile_regs(SS_REG_STATE* regState);
void    ss_invalidate_unknown_instruction_destination(struct ud* u, SS_REG_STATE* regState);

INT     ss_find_driver_object_argument_register(const SS_REG_STATE* regState);

const char* ss_dispatch_reg_name(INT regIndex);
const char* ss_dispatch_state_name(INT valueType);

BOOL    ss_dispatch_function_visited(const SS_SCAN_STATE* state, ULONG64 moduleBase, ULONG functionRva);
BOOL    ss_add_visited_dispatch_function(SS_SCAN_STATE* state, ULONG64 moduleBase, ULONG functionRva,
                                         const SS_ABSTRACT_STATE* entryState);
/* AddVisitedReachableFunction（DispatchDisasm.inc）：reachable 访问集合。
 * 由 WDDM 检测的 ScanWddmReachableFunction 使用，故非 static。 */
BOOL    ss_add_visited_reachable_function(SS_SCAN_STATE* state, ULONG64 moduleBase,
                                          ULONG functionRva);
BOOL    ss_load_dispatch_module_context(const SS_SCAN_CONTEXT* callerCtx, const WCHAR* moduleName,
                                        SS_SCAN_CONTEXT* outContext);

/* 入口解析（DispatchDisasm.inc） */
ULONG   ss_resolve_real_driver_entry_rva(const SS_SCAN_CONTEXT* ctx, ULONG imageEntryRva);

/* ==================================================================
 * Generic WDM 恢复（dispatch_generic.c）
 * ================================================================== */
SS_DISPATCH_STATUS ss_recover_dispatch_from_dump(const SS_SCAN_CONTEXT* ctx, SS_RECOVERY_OUTPUT* output);
BOOL ss_recover_hid_register_minidriver_dispatch(const SS_SCAN_CONTEXT* extCtx, ULONG targetRva,
                                                 SS_RECOVERY_OUTPUT* output);
const WCHAR* ss_irp_mj_name(ULONG irpIndex);

/* 单函数抽象执行（CFG 定点 + 稳定态重放）。
 * 框架后端（dispatch_hid.c）需要以自定义入口状态复用同一扫描器，
 * 因此不再是 generic 内部 static。 */
void ss_scan_dispatch_function_with_args(const SS_SCAN_CONTEXT* ctx, SS_SCAN_STATE* state,
                                         ULONG currentFunctionRva,
                                         const SS_ABSTRACT_STATE* entryState,
                                         INT depth, SS_RECOVERY_OUTPUT* output);

/* ==================================================================
 * 编排（dispatch_orchestrator.c）
 * ================================================================== */
typedef struct _SS_RECOVERY_CONTEXT {
    const BYTE* pDump;
    ULONG64     fileSize;
    ULONG64     imageBase;
    ULONG64     imageSize;
    WCHAR       moduleName[SS_MODULE_NAME_MAX];

    ULONG64     currentMajorFunction[SS_DISPATCH_SLOT_COUNT];
    BOOL        hasCurrentMajorFunction;
    ULONG64     iopInvalidDeviceRequest;

    INT         modelKind;
    INT         frameworkKind;
    ULONG       modelConfidence;

    /* DRIVER_MODEL_INFO：WDDM 分类结果（DetectWddmDriver 写入） */
    SS_DRIVER_MODEL_INFO modelInfo;

    SS_MODULE_LOAD_CALLBACK  loadModule;
    void*                    loadModuleContext;
    SS_DISPATCH_LOG_CALLBACK logSink;
    void*                    logContext;
} SS_RECOVERY_CONTEXT;

typedef struct _SS_DRIVER_RECOVERY_OUTPUT {
    INT             modelKind;
    INT             frameworkKind;
    ULONG           modelConfidence;
    SS_FUNCTION_REF majorFunction[SS_DISPATCH_SLOT_COUNT];
    ULONG           fastIoDispatchRva;
    ULONG           hitCount;
    ULONG           confidence;
} SS_DRIVER_RECOVERY_OUTPUT;

/*
 * context 非 const：编排阶段要把分类结果写回 Context.ModelKind /
 * Context.ModelInfo —— 与原实现一致（VB 的 ClassifyDriverDispatchModel 直接写
 * ByRef Context），且 RecoverDxgkrnlDispatchBaseline 会读这两个字段作为入口门。
 * 除这三个字段外，编排不得修改 context 的入参部分。
 */
SS_DISPATCH_STATUS ss_recover_driver_dispatch(SS_RECOVERY_CONTEXT* context,
                                              SS_DRIVER_RECOVERY_OUTPUT* output);

/* ==================================================================
 * WDDM 后端（dispatch_wddm.c，移植自 DispatchWddm.inc）
 * ================================================================== */

/*
 * ClassifyDriverDispatchModel（DispatchOrchestrator.inc:114 的等价物）：
 * 唯一 WDDM 分类出口。默认 GenericWdm / FrameworkNone / 30；
 * DetectWddmDriver 判 WDDM 时写 WDDM 并返回 TRUE。
 * 返回 TRUE 与原实现一致（原实现两条分支都 Return True）。
 */
BOOL ss_classify_driver_dispatch_model(const SS_SCAN_CONTEXT* ctx,
                                       INT* modelKind, INT* frameworkKind,
                                       ULONG* modelConfidence,
                                       SS_DRIVER_MODEL_INFO* info);

/* WDDM_DISPATCH_BASELINE_OUTPUT（DispatchWddm.inc）。
 * 跨 translation unit 使用（编排器持有它），故定义在头文件里。 */
typedef struct _SS_WDDM_DISPATCH_BASELINE_OUTPUT {
    SS_FUNCTION_REF majorFunction[SS_DISPATCH_SLOT_COUNT];

    ULONG hitCount;
    ULONG confidence;

    ULONG64 dxgkrnlBase;
    ULONG64 dxgkrnlImageSize;   /* SizeOfImage，供 IsAddressInModule 等价判定 */

    ULONG writerFunctionRva;
    INT   candidateBaseReg;

    BOOL  driverObjectTracked;   /* baseline 可信来源 */

    /* 原 VB 另有 SequentialMajorFunction，但 ScanDxgkrnlBaselineFunction 从不写入，
     * 恒为 0；此处不保留，理由见 dispatch_wddm.c 的 SS_WDDM_BASELINE_CANDIDATE。 */

    /* dump 实证强度 / 诊断用（原实现只在 Candidate 里，这里额外留存以便转储） */
    ULONG exactCount;
    ULONG conflictCount;
    ULONG runtimeFunctionCount;

    BOOL  hasUniformDefault;
    ULONG defaultRva;
    ULONG defaultSlotCount;
} SS_WDDM_DISPATCH_BASELINE_OUTPUT;

/* MergeWddmDispatchResult：把 current ∈ dxgkrnl 的槽标为 FrameworkOwned。 */
void ss_merge_wddm_dispatch_result(SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                   const SS_DRIVER_MODEL_INFO* modelInfo,
                                   const SS_RECOVERY_CONTEXT* context,
                                   ULONG64 dxgRuntimeBase,
                                   ULONG64 dxgImageSize);

/* MergeWddmDispatchBaseline：把已接受的 baseline 填回 recovery output。 */
void ss_merge_wddm_dispatch_baseline(SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                     const SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline,
                                     ULONG64 dxgImageSize);

/* RecoverDxgkrnlDispatchBaseline：结构扫描 dxgkrnl 求 dispatch 基线。 */
BOOL ss_recover_dxgkrnl_dispatch_baseline(const SS_RECOVERY_CONTEXT* context,
                                         const SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                         SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline);

/* 按模块名加载模块镜像（LoadDispatchModuleContext 的等价物）。 */
BOOL ss_load_dispatch_module_context_named(const SS_RECOVERY_CONTEXT* context,
                                           const WCHAR* moduleName,
                                           SS_SCAN_CONTEXT* outContext);

/*
 * Phase 2 调试转储（仅内部使用，**不导出**到 dispatch.h）。
 * 用于判断 baseline 是「扫描没找到 / 评分淘汰 / merge 丢失」。
 */
void ss_wddm_debug_dump_baseline(const SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline,
                                 SS_DISPATCH_LOG_CALLBACK sink, void* logContext);

/* ==================================================================
 * KMDF 后端（dispatch_kmdf.c，移植自 KernelHook/DispatchKmdf.Inc）
 *
 * 严格等价迁移，禁止顺手改判定/常量：
 *   - 内核地址下界 0xFFFF800000000000
 *   - Build 入口即 memset 清零
 *   - PE 校验刻意独立实现（节区命中式），不得改用 ss_is_rva_executable 等
 *     通用/无界 helper（见 DispatchKmdf.Inc:49 的注释）。
 * ================================================================== */

/* BuildKmdfDispatchBaseline：成功时填充 28 槽框架统一派遣基线。 */
BOOL ss_build_kmdf_dispatch_baseline(const SS_KMDF_DRIVER_INFO* info,
                                     ULONG64 wdfBase,
                                     ULONG   wdfSize,
                                     SS_DRIVER_RECOVERY_OUTPUT* baseline);

/* IsKmdfBaselineExecutable：有界 PE + 节区可执行性校验。 */
BOOL ss_is_kmdf_baseline_executable(const BYTE* dump,
                                    ULONG fileSize,
                                    ULONG imageSize,
                                    ULONG targetRva);
