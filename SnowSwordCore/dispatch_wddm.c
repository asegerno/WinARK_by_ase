/*
 * dispatch_wddm.c -- WDDM 后端（DispatchWddm.inc 的逐行等价移植）
 *
 * 范围（Phase 2）：只移植 ring3/modules/KernelHook/DispatchWddm.inc。
 * 明确不迁移：DispatchFastIo.inc / DispatchKmdf.Inc / DispatchFrameworkHid.inc。
 *
 * 移植约定：
 *   - 常量与判定阈值原样保留，不得"顺手修正"（见 DispatchTypes.bi §5）。
 *   - VB 的 ByRef 结构在 C 里全部传指针；VB 的 Select Case / For / While
 *     逐句保持形状，便于与原实现逐行对照。
 *   - MyLog.PrintInfo 一律经 ss_wddm_log 走 SS_DISPATCH_LOG_CALLBACK；
 *     回调为 NULL 时完全静默（与原实现日志关闭时等价）。
 *   - 字符串用固定缓冲 + StringCchCatA，避免 Core 内部依赖宿主分配器。
 *
 * 本文件当前进度：类型/常量/有界 helpers + 检测层（DetectWddmDriver 及其
 * 三个扫描器）。baseline 层（ScanDxgkrnl* / Merge*）与编排接线随后补齐。
 */
#include "pch.h"
#include "dispatch_internal.h"
#include "third_party/udis86/udis86.h"

/* ==================================================================
 * 结构（DispatchTypes.bi: WDDM_BASELINE_CANDIDATE / WDDM_DISPATCH_BASELINE_OUTPUT）
 * ================================================================== */
typedef struct _SS_WDDM_BASELINE_CANDIDATE {
    BOOL valid;

    ULONG writerFunctionRva;   /* 写入派遣表的函数 RVA */
    INT   baseReg;             /* 认为是 DRIVER_OBJECT 的基址寄存器 */

    BOOL  driverObjectTracked; /* DriverObject 追踪证据 */

    /*
     * 注意：原 VB 结构 DispatchTypes.bi 里另有
     *   SequentialMajorFunction As ULong
     *   FirstMajorFunctionOffset As LongInt
     * 两个字段，但 DispatchWddm.inc 的 ScanDxgkrnlBaselineFunction **从不写入**它们
     * （仅被 ClearWddmBaselineCandidate 置 0 / -1），因此 ScoreWddmBaselineTieBreaker
     * 中对应的第 2、3 项是同值常数，对候选取舍没有任何影响——是死代码。
     *
     * 本迁移目标是「行为等价」，不顺手修补算法，故这里**不设**这两个字段。
     * 如日后要真正激活连续性 tie-break，属于独立的算法改进任务，
     * 必须用 50 样本 A/B 重新验证（见 _state/state.md Phase 2 边界）。
     */

    ULONG hitCount;

    ULONG matchCount;
    ULONG extraCount;
    ULONG missingCount;

    INT64 score;

    SS_FUNCTION_REF majorFunction[SS_DISPATCH_SLOT_COUNT];

    ULONG exactCount;      /* 与 dump 精确一致 */
    ULONG conflictCount;   /* 与 dump 冲突 */
    ULONG hookedCount;     /* current 在 dxgkrnl 之外 */
} SS_WDDM_BASELINE_CANDIDATE;

/* SS_WDDM_DISPATCH_BASELINE_OUTPUT 定义在 dispatch_internal.h（编排器也要用）。 */

/* ==================================================================
 * 常量：原样保留
 * ================================================================== */
#define SS_WDDM_REACH_MAX_DEPTH            3
#define SS_WDDM_REACH_FALLBACK_SCAN_SIZE   0x800
#define SS_WDDM_UNIFORM_DEFAULT_MIN_SLOTS  5
#define SS_WDDM_BASELINE_MIN_HITS          6
#define SS_WDDM_BASELINE_MAX_FUNCTION_SIZE 0x4000
#define SS_WDDM_DETECT_THRESHOLD           70

/*
 * ScoreWddmBaselineCandidate 的硬门槛（原实现字面量）：
 *   expectedCount >= 6   TooFewFrameworkOwned
 *   exactCount    >= 4   NoExactMatch
 *   conflictCount <= 1   ConflictsDump
 */
#define SS_WDDM_MIN_FRAMEWORK_OWNED        6
#define SS_WDDM_MIN_EXACT                  4

/* RecoverDxgkrnlDispatchBaseline 的第二道保险：candidate.HitCount >= 4 */
#define SS_WDDM_MIN_CANDIDATE_SLOTS        4

/* IMAGE_DIRECTORY_ENTRY_EXCEPTION 的 RUNTIME_FUNCTION 项大小 */
#define SS_RUNTIME_FUNCTION_ENTRY_SIZE     12

#define SS_IMAGE_SCN_MEM_EXECUTE_           0x20000000
#define SS_IMAGE_SCN_CNT_INITIALIZED_DATA_  0x00000040

#define SS_DXGKRNL_MODULE_NAME "dxgkrnl.sys"

/* ==================================================================
 * 日志：DispatchWddm.inc 里的 MyLog.PrintInfo 等价物
 * ================================================================== */
static void ss_wddm_log(const SS_SCAN_CONTEXT* ctx, const char* functionName, const char* format, ...)
{
    char message[1024];
    va_list args;

    if (ctx == NULL || ctx->logSink == NULL) {
        return;
    }

    va_start(args, format);
    _vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    ctx->logSink(ctx->logContext, functionName, message);
}

/* ==================================================================
 * reason 追加（VB: reasonParts &= IIf(Len(reasonParts) > 0, "+", "") & X）
 * ================================================================== */
static void ss_reason_append(char* reason, size_t reasonCount, const char* text)
{
    if (reason[0] != '\0') {
        strcat_s(reason, reasonCount, "+");
    }
    strcat_s(reason, reasonCount, text);
}

/* ==================================================================
 * 日志：DRIVER_DISPATCH_RECOVERY_CONTEXT 版本
 *
 * SS_RECOVERY_CONTEXT 与 SS_SCAN_CONTEXT 是两套结构（前者没有 pDump），
 * 故不能直接复用 ss_log_ctx；这里按同样的回调契约包一层。
 * ================================================================== */
static void ss_log_ctx_wddm(const SS_RECOVERY_CONTEXT* ctx, const char* functionName,
                            const char* format, ...)
{
    char message[1024];
    va_list args;

    if (ctx == NULL || ctx->logSink == NULL) {
        return;
    }

    va_start(args, format);
    _vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    ctx->logSink(ctx->logContext, functionName, message);
}

/* ==================================================================
 * IsAddressInModule 的等价物
 *
 * 原实现（DispatchPeUtils.inc:249）按模块名向宿主查「已加载基址 + 大小」再
 * 做区间判定。Core 不自行枚举内核模块：dxgkrnl 的运行时基址与映像大小由
 * loadModule 回调给出（SS_SCAN_CONTEXT.imageBase / fileSize 是文件字节数，
 * 不是映像大小），因此调用点改为传入回调得到的基址与 SizeOfImage。
 * 语义等价：Address ∈ [模块基址, 模块基址 + 映像大小)。
 * ================================================================== */
static BOOL ss_wddm_address_in_module(ULONG64 address, ULONG64 moduleBase, ULONG64 imageSize)
{
    if (address == 0 || moduleBase == 0 || imageSize == 0) {
        return FALSE;
    }

    return (address >= moduleBase) && (address < moduleBase + imageSize);
}

/* ==================================================================
 * ClearWddmBaselineCandidate
 * ================================================================== */
static void ss_clear_wddm_baseline_candidate(SS_WDDM_BASELINE_CANDIDATE* candidate)
{
    candidate->valid = FALSE;

    candidate->writerFunctionRva = 0;
    candidate->baseReg = -1;

    candidate->driverObjectTracked = FALSE;

    candidate->hitCount = 0;

    candidate->matchCount = 0;
    candidate->extraCount = 0;
    candidate->missingCount = 0;

    candidate->score = 0;
    candidate->exactCount = 0;
    candidate->conflictCount = 0;
    candidate->hookedCount = 0;

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        candidate->majorFunction[i].valid = FALSE;
        candidate->majorFunction[i].moduleBase = 0;
        candidate->majorFunction[i].functionRva = 0;
        candidate->majorFunction[i].state = SS_SLOT_UNRESOLVED;
        candidate->majorFunction[i].ownerKind = SS_OWNER_UNKNOWN;
        candidate->majorFunction[i].source = SS_SOURCE_UNKNOWN;
        candidate->majorFunction[i].confidence = 0;
    }
}

/* ==================================================================
 * ClearWddmDispatchBaseline
 * ================================================================== */
static void ss_clear_wddm_dispatch_baseline(SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline)
{
    baseline->hitCount = 0;
    baseline->confidence = 0;
    baseline->dxgkrnlBase = 0;
    baseline->writerFunctionRva = 0;
    baseline->candidateBaseReg = -1;
    baseline->hasUniformDefault = FALSE;
    baseline->defaultRva = 0;
    baseline->defaultSlotCount = 0;

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        baseline->majorFunction[i].valid = FALSE;
        baseline->majorFunction[i].moduleBase = 0;
        baseline->majorFunction[i].functionRva = 0;
        baseline->majorFunction[i].state = SS_SLOT_UNRESOLVED;
        baseline->majorFunction[i].ownerKind = SS_OWNER_UNKNOWN;
        baseline->majorFunction[i].source = SS_SOURCE_UNKNOWN;
        baseline->majorFunction[i].confidence = 0;
    }
}

/* ==================================================================
 * WddmMajorOffsetToIndex
 *
 * VB 用 `delta Mod DISPATCH_STEP` 与 `delta \ DISPATCH_STEP`；Offset 为
 * LongInt（有符号），故此处保持 INT64 并在取模前确认 delta >= 0（Offset 已
 * 经 >= DISPATCH_BASE 检查，delta 必然非负）。
 * ================================================================== */
static BOOL ss_wddm_major_offset_to_index(INT64 offset, INT* irpIndex)
{
    INT64 maxOffset;
    INT64 delta;
    INT64 index64;

    *irpIndex = -1;

    if (offset < SS_DISPATCH_BASE) {
        return FALSE;
    }

    maxOffset = SS_DISPATCH_BASE +
                (INT64)SS_IRP_MJ_MAXIMUM_FUNCTION * (INT64)SS_DISPATCH_STEP;

    if (offset > maxOffset) {
        return FALSE;
    }

    delta = offset - SS_DISPATCH_BASE;

    if ((delta % (INT64)SS_DISPATCH_STEP) != 0) {
        return FALSE;
    }

    index64 = delta / (INT64)SS_DISPATCH_STEP;

    if (index64 < 0 || index64 > (INT64)SS_IRP_MJ_MAXIMUM_FUNCTION) {
        return FALSE;
    }

    *irpIndex = (INT)index64;

    return TRUE;
}

/* ==================================================================
 * IsKnownKmdodVersion
 * ================================================================== */
static BOOL ss_is_known_kmdod_version(ULONG value)
{
    switch (value) {
    case 0x1052: case 0x1053:
    case 0x2005:
    case 0x300E:
    case 0x4002: case 0x4003:
    case 0x5023:
    case 0x6003:
    case 0x6010: case 0x6011:
    case 0x700A:
    case 0x8001:
    case 0x9006:
    case 0xA00B:
    case 0xB004:
    case 0xC004:
    case 0xD001:
    case 0xE003:
    case 0xF003:
    case 0x10004:
        return TRUE;
    default:
        break;
    }

    if (value >= 0x11007 && value < 0x100000) {
        return TRUE;
    }

    return FALSE;
}

/* ==================================================================
 * ScanWddmReachableFunction
 *
 * 只追踪 DriverObject 是否仍存在于某个 GPR 中；不做完整通用数据流。
 * ================================================================== */
static void ss_scan_wddm_reachable_function(const SS_SCAN_CONTEXT* ctx,
                                            SS_SCAN_STATE* state,
                                            ULONG functionRva,
                                            INT depth,
                                            SS_WDDM_DETECTION_EVIDENCE* evidence)
{
    ULONG funcFoa;
    ULONG scanSize;
    ULONG funcBegin;
    ULONG funcEnd;
    struct ud u;
    SS_REG_STATE regState[16];
    INT funcLocalCallbackCount = 0;
    INT funcIndirectCalls = 0;
    BOOL funcHasConst = FALSE;
    ULONG funcConstValue = 0;
    BOOL funcHasKmdodVersion = FALSE;
    ULONG funcKmdodVersion = 0;

    if (ctx->pDump == NULL || ctx->fileSize == 0) {
        return;
    }
    if (functionRva == 0) {
        return;
    }
    if (depth > SS_WDDM_REACH_MAX_DEPTH) {
        return;
    }

    if (ss_add_visited_reachable_function(state, ctx->imageBase, functionRva) == FALSE) {
        return;
    }

    funcFoa = (ULONG)ss_rva_to_foa(ctx->pDump, functionRva);
    if (funcFoa == 0 || funcFoa >= ctx->fileSize) {
        return;
    }

    /*
     * 优先使用 PDATA 中的真实函数边界。不能像旧版本一样从每个函数起点
     * 无条件扫 0x2000，否则会跨进后续函数并产生大量伪 call edge。
     */
    scanSize = SS_WDDM_REACH_FALLBACK_SCAN_SIZE;
    funcBegin = 0;
    funcEnd = 0;

    if (ss_get_runtime_function_bounds(ctx->pDump, ctx->fileSize, functionRva,
                                       &funcBegin, &funcEnd)) {
        if (funcEnd > functionRva) {
            scanSize = funcEnd - functionRva;
        }
    }

    if (scanSize == 0) {
        return;
    }

    if ((ULONG64)funcFoa + scanSize > ctx->fileSize) {
        scanSize = (ULONG)(ctx->fileSize - funcFoa);
    }

    ss_wddm_log(ctx, "ScanWddmReachableFunction",
                "[WDDM-SCAN] Depth=%d FunctionRVA=0x%X ScanSize=0x%X",
                depth, functionRva, scanSize);

    ud_init(&u);
    ud_set_mode(&u, 64);
    ud_set_pc(&u, functionRva);
    ud_set_input_buffer(&u, ctx->pDump + funcFoa, scanSize);

    for (INT i = 0; i <= 15; i++) {
        ss_clear_reg(&regState[i]);
    }

    /*
     * 入口约定：只有当调用者确认 RCX == DriverObject 时才会递归进入本函数。
     * 根 DriverEntry 同样满足这一约定。
     */
    regState[1].valueType = SS_REG_DRIVER_OBJECT;

    while (ud_decode(&u) != 0) {
        enum ud_mnemonic_code mnemonic = ud_insn_mnemonic(&u);
        const struct ud_operand* op0 = ud_insn_opr(&u, 0);
        const struct ud_operand* op1 = ud_insn_opr(&u, 1);

        switch (mnemonic) {
        case UD_Imov:
            /* 先处理 DriverObject 寄存器传播。 */
            if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    if (ss_ud_is_64bit_gpr(op1)) {
                        INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);

                        if (srcReg >= 0) {
                            ss_copy_reg(&regState[dstReg], &regState[srcReg]);
                        } else {
                            ss_clear_reg(&regState[dstReg]);
                        }
                    } else {
                        ss_clear_reg(&regState[dstReg]);
                    }
                }
            }

            /* 再独立处理 WDDM registration constant。 */
            if (op0 != NULL && op1 != NULL) {
                if (op0->typ == UD_OP_REG && op1->typ == UD_OP_IMM) {
                    ULONG_PTR immValue = 0;
                    ULONG low32;
                    INT dstReg;

                    /* op1->SIZE 是位域，MSVC 不允许把位域当 case 标签，
                     * 故用 if 链（语义与 VB 的 Select Case op1->SIZE 等价）。 */
                    if (op1->SIZE == 8) {
                        immValue = op1->lval.UByte;
                    } else if (op1->SIZE == 16) {
                        immValue = op1->lval.UWORD;
                    } else if (op1->SIZE == 32) {
                        immValue = op1->lval.udword;
                    } else if (op1->SIZE == 64) {
                        immValue = op1->lval.uqword;
                    }

                    low32 = (ULONG)(immValue & 0xFFFFFFFFULL);
                    dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                    if (low32 == 0x23003F) {
                        evidence->has23003F = TRUE;
                        evidence->registrationHelperRva = functionRva;
                        funcHasConst = TRUE;
                        funcConstValue = 0x23003F;

                        ss_wddm_log(ctx, "ScanWddmReachableFunction",
                                    "[WDDM-EVIDENCE] HelperRVA=0x%X RegValue=0x23003F "
                                    "Reg=%s InsnRVA=0x%X",
                                    functionRva, ss_dispatch_reg_name(dstReg),
                                    (ULONG)ud_insn_off(&u));
                    } else if (low32 == 0x230043) {
                        evidence->has230043 = TRUE;
                        evidence->registrationHelperRva = functionRva;
                        funcHasConst = TRUE;
                        funcConstValue = 0x230043;

                        ss_wddm_log(ctx, "ScanWddmReachableFunction",
                                    "[WDDM-EVIDENCE] HelperRVA=0x%X RegValue=0x230043 "
                                    "Reg=%s InsnRVA=0x%X",
                                    functionRva, ss_dispatch_reg_name(dstReg),
                                    (ULONG)ud_insn_off(&u));
                    }
                }
            }

            /*
             * KMDOD_INITIALIZATION_DATA.Version 通常是：
             *   mov [rsp/rbp + local.Version], imm32
             */
            if (op0 != NULL && op1 != NULL) {
                if (op0->typ == UD_OP_MEM && op1->typ == UD_OP_IMM) {
                    if (op0->Base == UD_R_RSP || op0->Base == UD_R_RBP) {
                        ULONG_PTR immValue = 0;
                        ULONG low32;

                        if (op1->SIZE == 8) {
                            immValue = op1->lval.UByte;
                        } else if (op1->SIZE == 16) {
                            immValue = op1->lval.UWORD;
                        } else if (op1->SIZE == 32) {
                            immValue = op1->lval.udword;
                        } else if (op1->SIZE == 64) {
                            immValue = op1->lval.uqword;
                        }

                        low32 = (ULONG)(immValue & 0xFFFFFFFFULL);

                        if (ss_is_known_kmdod_version(low32)) {
                            funcHasKmdodVersion = TRUE;
                            funcKmdodVersion = low32;

                            ss_wddm_log(ctx, "ScanWddmReachableFunction",
                                        "[WDDM-EVIDENCE] KMDOD version candidate "
                                        "HelperRVA=0x%X Version=0x%X InsnRVA=0x%X",
                                        functionRva, low32, (ULONG)ud_insn_off(&u));
                        }
                    }
                }
            }
            break;

        case UD_Ilea:
            if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    /* LEA 一般产生地址，不再视为原 DriverObject。 */
                    ss_clear_reg(&regState[dstReg]);
                }
            }

            if (op0 != NULL && op1 != NULL) {
                if (op0->typ == UD_OP_REG && op1->typ == UD_OP_MEM &&
                    op1->Base == UD_R_RIP && op1->index == UD_NONE) {

                    ULONG tgtRva = ss_get_rip_relative_operand_rva(&u, op1);

                    if (tgtRva != 0 && ss_is_rva_executable(ctx->pDump, tgtRva)) {
                        INT dstReg;

                        funcLocalCallbackCount += 1;
                        dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                        ss_wddm_log(ctx, "ScanWddmReachableFunction",
                                    "[WDDM-EVIDENCE] ImageLocalFnPtr HelperRVA=0x%X "
                                    "Reg=%s TargetRVA=0x%X",
                                    functionRva, ss_dispatch_reg_name(dstReg), tgtRva);
                    }
                }
            }
            break;

        case UD_Icall: {
            /*
             * 关键修复：只有 RCX 当前仍然是 DriverObject，才沿 direct call 递归。
             */
            BOOL passDriverObject = (regState[1].valueType == SS_REG_DRIVER_OBJECT);

            if (op0 != NULL) {
                if (op0->typ == UD_OP_JIMM) {
                    ULONG callTarget = ss_ud_relative_target_rva(&u, op0);

                    if (passDriverObject &&
                        callTarget != 0 &&
                        callTarget != functionRva &&
                        depth < SS_WDDM_REACH_MAX_DEPTH &&
                        ss_rva_to_foa(ctx->pDump, callTarget) != 0 &&
                        ss_is_rva_executable(ctx->pDump, callTarget)) {

                        ss_wddm_log(ctx, "ScanWddmReachableFunction",
                                    "[WDDM-CALL] Caller=0x%X Target=0x%X DriverObject=true",
                                    functionRva, callTarget);

                        ss_scan_wddm_reachable_function(ctx, state, callTarget,
                                                        depth + 1, evidence);
                    }
                } else {
                    /* 对间接调用本身只收证据。 */
                    funcIndirectCalls += 1;
                }
            }

            /* Windows x64 volatile registers 在调用后失效。 */
            ss_invalidate_volatile_regs(regState);
            break;
        }

        case UD_Iret:
        case UD_Iretf:
            /* 已经限制到真实函数边界，遇到 RET 就可以结束。 */
            goto done;

        default:
            break;
        }
    }

done:
    if (funcHasConst) {
        if (funcLocalCallbackCount > 0 || funcIndirectCalls > 0) {
            evidence->hasIndirectRegistrationPath = TRUE;

            ss_wddm_log(ctx, "ScanWddmReachableFunction",
                        "[WDDM-EVIDENCE] IndirectRegistrationPath HelperRVA=0x%X "
                        "Const=0x%X LocalLeas=%d IndirectCalls=%d",
                        functionRva, funcConstValue, funcLocalCallbackCount,
                        funcIndirectCalls);
        }
    }

    if (funcHasKmdodVersion && funcLocalCallbackCount >= 2) {
        evidence->hasKmdodInitialization = TRUE;
        evidence->kmdodVersion = funcKmdodVersion;
        evidence->kmdodHelperRva = functionRva;
        evidence->kmdodCallbackCount = (ULONG)funcLocalCallbackCount;

        ss_wddm_log(ctx, "ScanWddmReachableFunction",
                    "[WDDM-EVIDENCE] KMDOD initialization HelperRVA=0x%X "
                    "Version=0x%X LocalCallbacks=%d",
                    functionRva, funcKmdodVersion, funcLocalCallbackCount);
    }
}

/* ==================================================================
 * ScanCallbackTableReferences
 *
 * 扫描已初始化数据段，寻找连续的可执行函数 RVA。
 * 判定条件：连续 >= 3 个 entry 属于当前映像可执行节。
 * 返回最长连续 run 的长度和起始 RVA。
 * ================================================================== */
static BOOL ss_scan_callback_table_references(const SS_SCAN_CONTEXT* ctx,
                                              ULONG* callbackHits, ULONG* tableStartRva)
{
    ULONG64 preferredBase = 0;
    ULONG sizeOfImage = 0;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt64;
    const IMAGE_SECTION_HEADER* secHdr;
    ULONG bestRun = 0;
    ULONG bestStart = 0;

    *callbackHits = 0;
    *tableStartRva = 0;

    if (ctx->pDump == NULL || ctx->fileSize == 0) {
        return FALSE;
    }

    if (ss_get_pe_image_info(ctx->pDump, &preferredBase, &sizeOfImage) == FALSE) {
        return FALSE;
    }

    dos = (const IMAGE_DOS_HEADER*)ctx->pDump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    nt64 = (const IMAGE_NT_HEADERS64*)(ctx->pDump + dos->e_lfanew);
    if (nt64->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    secHdr = (const IMAGE_SECTION_HEADER*)((ULONG_PTR)nt64 + sizeof(IMAGE_NT_HEADERS64));

    for (ULONG secIdx = 0; secIdx < nt64->FileHeader.NumberOfSections; secIdx++) {
        ULONG ch = secHdr->Characteristics;

        /* 只看已初始化数据段，排除 .text */
        if ((ch & SS_IMAGE_SCN_MEM_EXECUTE_) == 0 &&
            (ch & SS_IMAGE_SCN_CNT_INITIALIZED_DATA_) != 0) {

            ULONG rawStart = secHdr->PointerToRawData;
            ULONG rawSize = secHdr->SizeOfRawData;

            if (rawSize >= 8 && (ULONG64)rawStart + rawSize <= ctx->fileSize) {
                const BYTE* pSec = ctx->pDump + rawStart;
                ULONG numEntries = rawSize / 8;
                ULONG currentRun = 0;
                ULONG currentRunStart = 0;

                for (ULONG i = 0; i < numEntries; i++) {
                    ULONG_PTR nVal = 0;
                    BOOL isExec = FALSE;

                    memcpy(&nVal, pSec + (size_t)i * 8, 8);

                    /* 判定：VA 落在 preferred image 且 RVA 可执行 */
                    if (nVal >= preferredBase && nVal < preferredBase + sizeOfImage) {
                        ULONG candidateRva = (ULONG)(nVal - preferredBase);

                        if (ss_is_rva_executable(ctx->pDump, candidateRva)) {
                            isExec = TRUE;
                        }
                    }

                    if (isExec) {
                        if (currentRun == 0) {
                            currentRunStart = secHdr->VirtualAddress + i * 8;
                        }
                        currentRun += 1;
                    } else {
                        if (currentRun > bestRun) {
                            bestRun = currentRun;
                            bestStart = currentRunStart;
                        }
                        currentRun = 0;
                    }
                }

                if (currentRun > bestRun) {
                    bestRun = currentRun;
                    bestStart = currentRunStart;
                }
            }
        }

        secHdr += 1;
    }

    *callbackHits = bestRun;
    *tableStartRva = bestStart;

    return (bestRun >= 3);
}

/* ==================================================================
 * ScanForDxgkrnlImport
 *
 * 只读 Import Directory，不解析 IAT 槽位，不做 DxgkDdi 解析。
 * ================================================================== */
static BOOL ss_scan_for_dxgkrnl_import(const SS_SCAN_CONTEXT* ctx)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt64;
    ULONG importRva;
    ULONG importSize;
    INT64 importEnd64;
    ULONG descriptorRva;

    if (ctx->pDump == NULL || ctx->fileSize == 0) {
        return FALSE;
    }

    dos = (const IMAGE_DOS_HEADER*)ctx->pDump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((INT64)dos->e_lfanew + (INT64)sizeof(IMAGE_NT_HEADERS64) > (INT64)ctx->fileSize) {
        return FALSE;
    }

    nt64 = (const IMAGE_NT_HEADERS64*)(ctx->pDump + dos->e_lfanew);
    if (nt64->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    importRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    importSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (importRva == 0 || importSize < 20) {
        return FALSE;
    }

    importEnd64 = (INT64)importRva + (INT64)importSize;
    descriptorRva = importRva;

    while ((INT64)descriptorRva + 20 <= importEnd64) {
        ULONG nameRva = 0;
        char moduleName[SS_MODULE_NAME_MAX * 4];

        if (ss_read_raw_rva_dword(ctx->pDump, ctx->fileSize, descriptorRva + 12, &nameRva) == FALSE) {
            break;
        }

        if (nameRva == 0) {
            break;
        }

        moduleName[0] = '\0';
        if (ss_read_ascii_string_by_rva(ctx->pDump, ctx->fileSize, nameRva,
                                        moduleName, sizeof(moduleName))) {
            if (_stricmp(moduleName, SS_DXGKRNL_MODULE_NAME) == 0) {
                return TRUE;
            }
        }

        descriptorRva += 20;
    }

    return FALSE;
}

/* ==================================================================
 * DetectWddmDriver
 *
 * 证据来源（一次汇总，不再二次分类）：
 *   Evidence 1   ScanWddmReachableFunction -> 0x23003F / 0x230043
 *   Evidence 2   ScanWddmReachableFunction -> 间接注册路径
 *   Evidence 3   ScanCallbackTableReferences -> 辅助证据
 *   Evidence 4   ScanForDxgkrnlImport      -> 加分项（非否决项）
 *
 * 评分：+30 registration constant / +30 间接路径 / +70 KMDOD / +20 callback table / +20 dxgkrnl
 * 硬约束：必须 HasRegistrationConstant 或 ExplicitDxgkRegistration 或 KmdodInitialization
 * 判定阈值：Confidence >= 70
 * ================================================================== */
static BOOL ss_detect_wddm_driver(const SS_SCAN_CONTEXT* ctx, SS_DRIVER_MODEL_INFO* info)
{
    ULONG entryRva;
    SS_WDDM_DETECTION_EVIDENCE evidence;
    SS_SCAN_STATE reachState;
    BOOL hasRegistrationConstant;
    ULONG cbHits = 0;
    ULONG cbTableRva = 0;
    BOOL hasCallbackTable;
    BOOL hasDxgkrnl;
    BOOL hasExplicitDxgkReg;
    BOOL hasRegistrationEvidence;
    ULONG confidence = 0;
    char* reasonParts = info->reason;

    info->isWddm = FALSE;
    info->confidence = 0;
    info->reason[0] = '\0';
    info->frameworkOwner[0] = '\0';

    if (ctx->pDump == NULL || ctx->fileSize == 0) {
        return FALSE;
    }

    if (ss_get_image_entry_point_rva(ctx->pDump, ctx->fileSize, &entryRva) == FALSE) {
        return FALSE;
    }
    if (entryRva == 0) {
        return FALSE;
    }

    memset(&evidence, 0, sizeof(evidence));

    /* --- Evidence 1 + 2：reachable helper 扫描 --- */
    memset(&reachState, 0, sizeof(reachState));

    ss_scan_wddm_reachable_function(ctx, &reachState, entryRva, 0, &evidence);

    hasRegistrationConstant = evidence.has23003F || evidence.has230043;

    /* --- Evidence 3：callback table（辅助） --- */
    hasCallbackTable = ss_scan_callback_table_references(ctx, &cbHits, &cbTableRva);

    evidence.callbackRun = cbHits;
    evidence.callbackTableRva = cbTableRva;
    evidence.hasLargeSelfCallbackTable = hasCallbackTable;

    /* --- Evidence 4：dxgkrnl 导入（加分） --- */
    hasDxgkrnl = ss_scan_for_dxgkrnl_import(ctx);

    /* 硬约束：不能仅凭 callback table 判 WDDM */
    hasExplicitDxgkReg = hasDxgkrnl;
    hasRegistrationEvidence = hasRegistrationConstant ||
                              hasExplicitDxgkReg ||
                              evidence.hasKmdodInitialization;

    if (hasRegistrationEvidence == FALSE) {
        info->confidence = 0;
        strcpy_s(info->reason, SS_MODEL_REASON_MAX, "NoRegistrationEvidence");

        ss_wddm_log(ctx, "DetectWddmDriver",
                    "[WDDM] Rejected: no registration evidence CallbackTable=%u", cbHits);

        return FALSE;
    }

    /* 1) registration constant（必给，硬约束已确认至少一项） */
    if (hasRegistrationConstant) {
        confidence += 30;

        if (evidence.has23003F) {
            ss_reason_append(reasonParts, SS_MODEL_REASON_MAX, "RegValue 0x23003F");
        }
        if (evidence.has230043) {
            ss_reason_append(reasonParts, SS_MODEL_REASON_MAX, "RegValue 0x230043");
        }

        ss_wddm_log(ctx, "DetectWddmDriver",
                    "[WDDM-EVIDENCE] RegistrationConstant=true has23003F=%d has230043=%d "
                    "HelperRVA=0x%X",
                    evidence.has23003F, evidence.has230043, evidence.registrationHelperRva);
    }

    /* 2) 间接注册路径 */
    if (evidence.hasIndirectRegistrationPath) {
        confidence += 30;
        ss_reason_append(reasonParts, SS_MODEL_REASON_MAX, "IndirectRegistrationPath");

        ss_wddm_log(ctx, "DetectWddmDriver", "[WDDM-EVIDENCE] IndirectRegistrationPath=true");
    }

    if (evidence.hasKmdodInitialization) {
        char texture[96];

        confidence += 70;

        _snprintf(texture, sizeof(texture), "KMDOD(0x%X,%u callbacks)",
                         evidence.kmdodVersion, evidence.kmdodCallbackCount);
        ss_reason_append(reasonParts, SS_MODEL_REASON_MAX, texture);

        ss_wddm_log(ctx, "DetectWddmDriver",
                    "[WDDM-EVIDENCE] KMDOD initialization=true Version=0x%X HelperRVA=0x%X "
                    "Callbacks=%u",
                    evidence.kmdodVersion, evidence.kmdodHelperRva, evidence.kmdodCallbackCount);
    }

    /* 3) callback table（辅助，不单独判 WDDM） */
    if (hasCallbackTable) {
        char texture[48];

        confidence += 20;
        _snprintf(texture, sizeof(texture), "CallbackTable(%u)", cbHits);
        ss_reason_append(reasonParts, SS_MODEL_REASON_MAX, texture);

        ss_wddm_log(ctx, "DetectWddmDriver",
                    "[WDDM] CallbackTable run=%u TableStartRVA=0x%X", cbHits, cbTableRva);
    }

    /* 4) dxgkrnl import（加分） */
    if (hasDxgkrnl) {
        confidence += 20;
        ss_reason_append(reasonParts, SS_MODEL_REASON_MAX, "dxgkrnl");
    }

    if (confidence > 100) {
        confidence = 100;
    }

    info->confidence = (INT)confidence;

    /* 判定阈值 70 */
    if (confidence >= SS_WDDM_DETECT_THRESHOLD) {
        info->isWddm = TRUE;
        strcpy_s(info->frameworkOwner, SS_FRAMEWORK_OWNER_MAX, SS_DXGKRNL_MODULE_NAME);
    }

    ss_wddm_log(ctx, "DetectWddmDriver",
                "[WDDM] Detected=%d Confidence=%d RegistrationConstant=%d "
                "IndirectRegistrationPath=%d CallbackRun=%u DxgkrnlImport=%d Reason=%s",
                info->isWddm, info->confidence, hasRegistrationConstant,
                evidence.hasIndirectRegistrationPath, cbHits, hasDxgkrnl, info->reason);

    return info->isWddm;
}

/* ==================================================================
 * ClassifyDriverDispatchModel
 *
 * 单一 WDDM 分类出口：DetectWddmDriver 判 WDDM -> DispatchModelWddm，否则 GenericWdm。
 * 原实现（DispatchOrchestrator.inc:114）默认值：GenericWdm / FrameworkNone /
 * ModelConfidence = 30。
 * ================================================================== */
BOOL ss_classify_driver_dispatch_model(const SS_SCAN_CONTEXT* ctx,
                                       INT* modelKind, INT* frameworkKind,
                                       ULONG* modelConfidence, SS_DRIVER_MODEL_INFO* info)
{
    *modelKind = SS_MODEL_GENERIC_WDM;
    *frameworkKind = SS_FRAMEWORK_NONE;
    *modelConfidence = 30;

    /* 显式清零（不能 memset 宿主侧字符串语义，这里逐字段清） */
    info->isWddm = FALSE;
    info->confidence = 0;
    info->reason[0] = '\0';
    info->frameworkOwner[0] = '\0';

    if (ss_detect_wddm_driver(ctx, info)) {
        *modelKind = SS_MODEL_WDDM;
        *modelConfidence = (ULONG)info->confidence;

        ss_wddm_log(ctx, "ClassifyDriverDispatchModel",
                    "[CLASSIFY] Module=%s Model=WDDM Confidence=%d Reason=%s",
                    ctx->moduleName, info->confidence, info->reason);

        return TRUE;
    }

    ss_wddm_log(ctx, "ClassifyDriverDispatchModel",
                "[CLASSIFY] Module=%s Model=GenericWdm Confidence=%u WddmReason=%s",
                ctx->moduleName, *modelConfidence, info->reason);

    return TRUE;
}

/* ==================================================================
 * =================== baseline 层（本刀新增） =======================
 *
 * 依赖顺序：TrackDriverObjectRegister -> ScoreWddmBaselineCandidate ->
 *           ScanDxgkrnlBaselineFunction -> ScanDxgkrnlRuntimeFunctionsForBaseline
 *           -> ApplyWddmUniformDefault -> RecoverDxgkrnlDispatchBaseline
 *           -> MergeWddmDispatchBaseline -> MergeWddmDispatchResult
 *
 * 全部照原语义搬运；tie-break / 连续写入 / RCX 追踪 / 首 slot 特征一处不减。
 * ================================================================== */

/* ==================================================================
 * 按模块名加载模块镜像（LoadDispatchModuleContext 等价物）
 *
 * Core 不自行枚举内核模块：模块名交给宿主的 loadModule 回调，由它给出
 * 运行时基址与磁盘镜像字节。imageSize 取 PE 的 SizeOfImage，供
 * IsAddressInModule 等价判定使用。
 * ================================================================== */
BOOL ss_load_dispatch_module_context_named(const SS_RECOVERY_CONTEXT* context,
                                           const WCHAR* moduleName,
                                           SS_SCAN_CONTEXT* outContext)
{
    SS_MODULE_IMAGE image;

    memset(outContext, 0, sizeof(*outContext));

    if (moduleName == NULL || moduleName[0] == L'\0') {
        return FALSE;
    }

    if (context->loadModule == NULL) {
        return FALSE;
    }

    memset(&image, 0, sizeof(image));

    if (context->loadModule(moduleName, context->loadModuleContext, &image) == FALSE) {
        return FALSE;
    }

    if (image.buffer == NULL || image.size == 0) {
        return FALSE;
    }

    if (image.imageBase == 0) {
        /* 与原实现一致：基址未知则放弃跨模块扫描。 */
        return FALSE;
    }

    outContext->pDump = image.buffer;
    outContext->fileSize = image.size;
    outContext->imageBase = image.imageBase;
    outContext->loadModule = context->loadModule;
    outContext->loadModuleContext = context->loadModuleContext;
    outContext->logSink = context->logSink;
    outContext->logContext = context->logContext;
    wcscpy_s(outContext->moduleName, SS_MODULE_NAME_MAX, moduleName);

    {
        /* imageSize 优先取 PE 的 SizeOfImage；取不到时退化为文件大小，
         * 但此时 IsAddressInModule 判定会偏宽，故记录一条日志以便排查。 */
        ULONG sizeOfImage = 0;
        ULONG64 preferredBase = 0;

        if (ss_get_pe_image_info(image.buffer, &preferredBase, &sizeOfImage) &&
            sizeOfImage != 0) {
            outContext->imageSize = sizeOfImage;
        } else {
            outContext->imageSize = image.size;
            ss_wddm_log(outContext, "LoadDispatchModuleContextNamed",
                        "[WDDM-BASELINE] SizeOfImage unavailable for %ls, "
                        "falling back to file size",
                        moduleName);
        }

        ss_wddm_log(outContext, "LoadDispatchModuleContextNamed",
                    "[WDDM-BASELINE] Loaded %ls ImageBase=0x%llX ImageSize=0x%llX "
                    "FileSize=0x%llX",
                    moduleName,
                    (unsigned long long)outContext->imageBase,
                    (unsigned long long)outContext->imageSize,
                    (unsigned long long)outContext->fileSize);
    }

    return TRUE;
}

/* ==================================================================
 * TrackDriverObjectRegister
 * ================================================================== */
static void ss_track_driver_object_register(const SS_REG_STATE* regState,
                                            SS_WDDM_BASELINE_CANDIDATE* candidateByReg)
{
    for (INT i = 0; i <= 15; i++) {
        if (regState[i].valueType == SS_REG_DRIVER_OBJECT) {
            candidateByReg[i].driverObjectTracked = TRUE;
        }
    }
}

/* ==================================================================
 * SameWddmBaselineTargets
 * ================================================================== */
static BOOL ss_same_wddm_baseline_targets(const SS_WDDM_BASELINE_CANDIDATE* a,
                                          const SS_WDDM_BASELINE_CANDIDATE* b)
{
    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (a->majorFunction[i].valid != b->majorFunction[i].valid) {
            return FALSE;
        }

        if (a->majorFunction[i].valid) {
            if (a->majorFunction[i].functionRva != b->majorFunction[i].functionRva) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/* ==================================================================
 * ScoreWddmBaselineTieBreaker
 *
 * 看似可简化，但它决定同分候选的取舍，必须原样保留。
 *
 * 严格等价说明：原 VB 版本在此另有第 2 项「MajorFunction 连续写入」
 * （SequentialMajorFunction >= 28 -> +5000，否则 *100）与第 3 项
 * 「第一个 slot 是否为 MajorFunction[0]」（FirstMajorFunctionOffset = &H70 -> +2000）。
 * 但 ScanDxgkrnlBaselineFunction 从不写入这两个字段——SequentialMajorFunction
 * 恒为 0、FirstMajorFunctionOffset 恒为 -1，两项对所有候选恒为同一个常数
 * （0 与 0），不改变任何候选之间的相对大小。
 * 因此这里**故意不实现**这两项，以保持与原 VB 真实行为逐位一致。
 * 详见 SS_WDDM_BASELINE_CANDIDATE 处的说明。
 * ================================================================== */
static INT64 ss_score_wddm_baseline_tie_breaker(const SS_WDDM_BASELINE_CANDIDATE* candidate)
{
    INT64 score = 0;

    /* 1. DriverObject 寄存器匹配 */
    if (candidate->baseReg == UD_R_RCX || candidate->driverObjectTracked) {
        score += 10000;
    }

    /* 2. 写入数量 */
    score += (INT64)candidate->matchCount * 10;

    return score;
}

/* ==================================================================
 * ScoreWddmBaselineCandidate
 *
 * 主评分 = target 与 dump 当前值的一致性：
 *   exact    — candidate 写入的 RVA == dxgkrnl 运行时该槽位 RVA
 *   conflict — current ∈ dxgkrnl 但 ≠ candidate RVA
 *   hooked   — current 在 dxgkrnl 之外（不罚分）
 *
 * 硬门槛：expectedCount >= 6 / exactCount >= 4 / conflictCount <= 1
 * ================================================================== */
static BOOL ss_score_wddm_baseline_candidate(SS_WDDM_BASELINE_CANDIDATE* candidate,
                                             const SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                             const SS_RECOVERY_CONTEXT* context,
                                             ULONG64 dxgRuntimeBase,
                                             ULONG64 dxgImageSize)
{
    INT64 exactCount = 0;
    INT64 conflictCount = 0;
    INT64 hookedCount = 0;
    INT64 validCount = 0;
    INT64 expectedCount = 0;
    INT64 matchCount = 0;
    INT64 extraCount = 0;
    INT64 missingCount;

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        BOOL frameworkOwned = (recoverOutput->majorFunction[i].state == SS_SLOT_FRAMEWORK_OWNED);
        ULONG64 curAddr;

        if (frameworkOwned) {
            expectedCount += 1;
        }

        if (candidate->majorFunction[i].valid == FALSE) {
            continue;
        }

        validCount += 1;

        if (frameworkOwned) {
            matchCount += 1;
        } else {
            extraCount += 1;
        }

        curAddr = context->hasCurrentMajorFunction ? context->currentMajorFunction[i] : 0;

        if (curAddr == 0) {
            continue;
        }
        if (curAddr == context->iopInvalidDeviceRequest) {
            continue;
        }

        if (ss_wddm_address_in_module(curAddr, dxgRuntimeBase, dxgImageSize)) {
            if (curAddr - dxgRuntimeBase == (ULONG64)candidate->majorFunction[i].functionRva) {
                exactCount += 1;
            } else {
                conflictCount += 1;
            }
        } else {
            /*
             * current 在 dxgkrnl 之外：可能是被 hook 的槽位，candidate 的值
             * 恰是 hook 前的原始地址。不罚分，单独计数供日志使用。
             */
            hookedCount += 1;
        }
    }

    missingCount = expectedCount - matchCount;

    candidate->matchCount = (ULONG)matchCount;
    candidate->extraCount = (ULONG)extraCount;
    candidate->missingCount = (ULONG)missingCount;

    /* ---- 硬门槛（带日志，不再静默拒绝） ---- */
    if (expectedCount < SS_WDDM_MIN_FRAMEWORK_OWNED) {
        ss_log_ctx_wddm(context, "ScoreWddmBaselineCandidate",
                        "[WDDM-BASELINE-SCORE] REJECT(TooFewFrameworkOwned) Writer=0x%X "
                        "Base=%s Expected=%lld",
                        candidate->writerFunctionRva,
                        ss_dispatch_reg_name(candidate->baseReg),
                        (long long)expectedCount);
        return FALSE;
    }

    if (exactCount < SS_WDDM_MIN_EXACT) {
        ss_log_ctx_wddm(context, "ScoreWddmBaselineCandidate",
                        "[WDDM-BASELINE-SCORE] REJECT(NoExactMatch) Writer=0x%X Base=%s "
                        "Valid=%lld Exact=%lld Conflict=%lld Hooked=%lld",
                        candidate->writerFunctionRva,
                        ss_dispatch_reg_name(candidate->baseReg),
                        (long long)validCount, (long long)exactCount,
                        (long long)conflictCount, (long long)hookedCount);
        return FALSE;
    }

    if (conflictCount > 1) {
        ss_log_ctx_wddm(context, "ScoreWddmBaselineCandidate",
                        "[WDDM-BASELINE-SCORE] REJECT(ConflictsDump) Writer=0x%X Base=%s "
                        "Exact=%lld Conflict=%lld",
                        candidate->writerFunctionRva,
                        ss_dispatch_reg_name(candidate->baseReg),
                        (long long)exactCount, (long long)conflictCount);
        return FALSE;
    }

    /* ---- 评分：exact 为主，coverage 为辅 ---- */
    candidate->score = exactCount * 1000
                     - conflictCount * 5000
                     + validCount * 10
                     + matchCount * 10;

    /* 完全覆盖所有 framework-owned 槽位：强 bonus */
    if (missingCount == 0 && extraCount == 0) {
        candidate->score += 10000;
    }

    candidate->exactCount = (ULONG)exactCount;
    candidate->conflictCount = (ULONG)conflictCount;
    candidate->hookedCount = (ULONG)hookedCount;

    ss_log_ctx_wddm(context, "ScoreWddmBaselineCandidate",
                    "[WDDM-BASELINE-SCORE] Writer=0x%X Base=%s Hits=%u Exact=%u "
                    "Conflict=%u Hooked=%u Match=%u Missing=%u Extra=%u Score=%lld",
                    candidate->writerFunctionRva,
                    ss_dispatch_reg_name(candidate->baseReg),
                    candidate->hitCount,
                    candidate->exactCount, candidate->conflictCount, candidate->hookedCount,
                    candidate->matchCount, candidate->missingCount, candidate->extraCount,
                    (long long)candidate->score);

    return TRUE;
}

/* ==================================================================
 * ConsiderWddmBaselineCandidate
 *
 * 注意：Candidate.Score 已包含 tie-breaker，这里不再二次相加。
 * 同分时依次比较 extraCount / missingCount，仍同形但 target 集不同则标 Ambiguous。
 * ================================================================== */
static void ss_consider_wddm_baseline_candidate(SS_WDDM_BASELINE_CANDIDATE* candidate,
                                                const SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                                const SS_RECOVERY_CONTEXT* context,
                                                ULONG64 dxgRuntimeBase,
                                                ULONG64 dxgImageSize,
                                                SS_WDDM_BASELINE_CANDIDATE* bestCandidate,
                                                BOOL* ambiguous)
{
    INT64 candidateTotalScore;
    INT64 bestTotalScore;

    if (ss_score_wddm_baseline_candidate(candidate, recoverOutput, context,
                                         dxgRuntimeBase, dxgImageSize) == FALSE) {
        return;
    }

    candidate->valid = TRUE;

    if (bestCandidate->valid == FALSE) {
        *bestCandidate = *candidate;
        *ambiguous = FALSE;
        return;
    }

    candidateTotalScore = candidate->score;
    bestTotalScore = bestCandidate->score;

    if (candidateTotalScore > bestTotalScore) {
        *bestCandidate = *candidate;
        *ambiguous = FALSE;
        return;
    }

    if (candidateTotalScore < bestTotalScore) {
        return;
    }

    /* 同分时优先 extra 更少 */
    if (candidate->extraCount < bestCandidate->extraCount) {
        *bestCandidate = *candidate;
        *ambiguous = FALSE;
        return;
    }

    if (candidate->extraCount > bestCandidate->extraCount) {
        return;
    }

    /* 再优先 missing 更少 */
    if (candidate->missingCount < bestCandidate->missingCount) {
        *bestCandidate = *candidate;
        *ambiguous = FALSE;
        return;
    }

    if (candidate->missingCount > bestCandidate->missingCount) {
        return;
    }

    /* 同 score / same shape，但 target 集不同，则不能武断选择 */
    if (ss_same_wddm_baseline_targets(candidate, bestCandidate) == FALSE) {
        *ambiguous = TRUE;

        ss_log_ctx_wddm(context, "ConsiderWddmBaselineCandidate",
                        "[WDDM-BASELINE] Ambiguous equal-score candidates A=0x%X B=0x%X "
                        "Score=%lld",
                        bestCandidate->writerFunctionRva, candidate->writerFunctionRva,
                        (long long)candidate->score);
    }
}

/* ==================================================================
 * ScanDxgkrnlBaselineFunction
 *
 * 在一个 RuntimeFunction 内追踪「MOV [base + MajorFunctionOffset], FunctionReg」
 * 形式的派遣表写入，按 base register 分别累积候选。
 * ================================================================== */
static BOOL ss_scan_dxgkrnl_baseline_function(const SS_SCAN_CONTEXT* dxgContext,
                                              ULONG functionRva,
                                              ULONG functionEndRva,
                                              const SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                              const SS_RECOVERY_CONTEXT* context,
                                              SS_WDDM_BASELINE_CANDIDATE* bestCandidate,
                                              BOOL* ambiguous)
{
    ULONG functionSize;
    ULONG64 functionFoa;
    SS_REG_STATE regState[16];
    SS_WDDM_BASELINE_CANDIDATE candidateByReg[16];
    struct ud u;
    BOOL foundCandidate = FALSE;

    if (dxgContext->pDump == NULL || dxgContext->fileSize == 0) {
        return FALSE;
    }

    if (functionRva == 0 || functionEndRva <= functionRva) {
        return FALSE;
    }

    functionSize = functionEndRva - functionRva;

    if (functionSize == 0 || functionSize > SS_WDDM_BASELINE_MAX_FUNCTION_SIZE) {
        return FALSE;
    }

    functionFoa = ss_rva_to_foa(dxgContext->pDump, functionRva);

    if (functionFoa == 0 || functionFoa >= dxgContext->fileSize) {
        return FALSE;
    }

    if (functionFoa + functionSize > dxgContext->fileSize) {
        functionSize = (ULONG)(dxgContext->fileSize - functionFoa);
    }

    for (INT i = 0; i <= 15; i++) {
        ss_clear_reg(&regState[i]);
    }

    /* 每个可能的 base register 单独统计。 */
    for (INT i = 0; i <= 15; i++) {
        ss_clear_wddm_baseline_candidate(&candidateByReg[i]);

        candidateByReg[i].writerFunctionRva = functionRva;
        candidateByReg[i].baseReg = i;
        candidateByReg[i].driverObjectTracked = FALSE;
    }

    ud_init(&u);
    ud_set_mode(&u, 64);
    ud_set_pc(&u, functionRva);
    ud_set_input_buffer(&u, dxgContext->pDump + functionFoa, functionSize);

    while (ud_decode(&u) != 0) {
        enum ud_mnemonic_code mnemonic = ud_insn_mnemonic(&u);
        const struct ud_operand* op0 = ud_insn_opr(&u, 0);
        const struct ud_operand* op1 = ud_insn_opr(&u, 1);

        switch (mnemonic) {
        case UD_Ilea:
            /* LEA reg, [RIP + function] */
            if (op0 != NULL && op1 != NULL &&
                op0->typ == UD_OP_REG && op1->typ == UD_OP_MEM &&
                op1->Base == UD_R_RIP && op1->index == UD_NONE) {

                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    ULONG targetRva;

                    ss_clear_reg(&regState[dstReg]);
                    targetRva = ss_get_rip_relative_operand_rva(&u, op1);

                    if (targetRva != 0 && ss_is_rva_executable(dxgContext->pDump, targetRva)) {
                        regState[dstReg].valueType = SS_REG_FUNCTION_RVA;
                        regState[dstReg].value = targetRva;
                    }
                }
            } else if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    ss_clear_reg(&regState[dstReg]);
                }
            }
            break;

        case UD_Imov: {
            /* MOV reg, reg —— 原实现在此 Continue While。 */
            if (ss_ud_is_64bit_gpr(op0) && ss_ud_is_64bit_gpr(op1)) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);
                INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);

                if (dstReg >= 0 && srcReg >= 0) {
                    ss_copy_reg(&regState[dstReg], &regState[srcReg]);
                }

                if (srcReg == UD_R_RCX) {
                    ss_track_driver_object_register(regState, candidateByReg);
                }

                break;
            }

            /* MOV [base + MajorFunctionOffset], FunctionReg */
            if (op0 != NULL && op1 != NULL &&
                op0->typ == UD_OP_MEM && op1->typ == UD_OP_REG &&
                op0->index == UD_NONE) {

                INT baseReg = ss_ud_reg_to_gpr_index(op0->Base);
                INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);

                if (baseReg >= 0 && srcReg >= 0) {
                    INT64 disp = ss_ud_memory_displacement(op0);
                    INT irpIndex = -1;

                    if (ss_wddm_major_offset_to_index(disp, &irpIndex)) {
                        if (regState[srcReg].valueType == SS_REG_FUNCTION_RVA) {
                            ULONG targetRva = (ULONG)regState[srcReg].value;

                            if (targetRva != 0 &&
                                ss_is_rva_executable(dxgContext->pDump, targetRva)) {

                                SS_FUNCTION_REF* pRef =
                                    &candidateByReg[baseReg].majorFunction[irpIndex];

                                if (pRef->valid == FALSE) {
                                    candidateByReg[baseReg].hitCount += 1;
                                }

                                pRef->valid = TRUE;
                                pRef->moduleBase = dxgContext->imageBase;
                                pRef->functionRva = targetRva;
                                pRef->state = SS_SLOT_RECOVERED;
                                pRef->ownerKind = SS_OWNER_FRAMEWORK;
                                pRef->source = SS_SOURCE_FRAMEWORK_BASELINE;
                                pRef->confidence = 0;

                                ss_wddm_log(dxgContext, "ScanDxgkrnlBaselineFunction",
                                            "[WDDM-BASELINE-CANDIDATE] Writer=0x%X Base=%s "
                                            "Slot=%u TargetRVA=0x%X StoreRVA=0x%X",
                                            functionRva, ss_dispatch_reg_name(baseReg),
                                            (ULONG)irpIndex, targetRva,
                                            (ULONG)ud_insn_off(&u));
                            }
                        }
                    }
                }

                break;
            }

            /* MOV 写寄存器但不是 reg <- reg，则旧 FunctionRva 状态失效。 */
            if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    ss_clear_reg(&regState[dstReg]);
                }
            }
            break;
        }

        case UD_Icall:
            /* volatile GPR 在 call 后不可继续相信。 */
            ss_invalidate_volatile_regs(regState);
            break;

        default:
            ss_invalidate_unknown_instruction_destination(&u, regState);
            break;
        }
    }

    for (INT i = 0; i <= 15; i++) {
        if (candidateByReg[i].hitCount == 0) {
            continue;
        }

        candidateByReg[i].valid = TRUE;

        ss_consider_wddm_baseline_candidate(&candidateByReg[i], recoverOutput, context,
                                            dxgContext->imageBase,
                                            dxgContext->imageSize,
                                            bestCandidate, ambiguous);

        foundCandidate = TRUE;
    }

    return foundCandidate;
}

/* ==================================================================
 * ScanDxgkrnlRuntimeFunctionsForBaseline
 * ================================================================== */
static BOOL ss_scan_dxgkrnl_runtime_functions_for_baseline(
    const SS_SCAN_CONTEXT* dxgContext,
    const SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
    const SS_RECOVERY_CONTEXT* context,
    SS_WDDM_BASELINE_CANDIDATE* bestCandidate,
    ULONG* outEntryCount)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt64;
    ULONG exceptionRva;
    ULONG exceptionSize;
    ULONG entryCount;
    BOOL ambiguous = FALSE;

    *outEntryCount = 0;

    ss_clear_wddm_baseline_candidate(bestCandidate);

    if (dxgContext->pDump == NULL || dxgContext->fileSize == 0) {
        return FALSE;
    }

    dos = (const IMAGE_DOS_HEADER*)dxgContext->pDump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((INT64)dos->e_lfanew + (INT64)sizeof(IMAGE_NT_HEADERS64) > (INT64)dxgContext->fileSize) {
        return FALSE;
    }

    nt64 = (const IMAGE_NT_HEADERS64*)(dxgContext->pDump + dos->e_lfanew);
    if (nt64->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    exceptionRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    exceptionSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (exceptionRva == 0 || exceptionSize < (ULONG)SS_RUNTIME_FUNCTION_ENTRY_SIZE) {
        ss_wddm_log(dxgContext, "ScanDxgkrnlRuntimeFunctionsForBaseline",
                    "[WDDM-BASELINE] No exception directory");
        return FALSE;
    }

    entryCount = exceptionSize / (ULONG)SS_RUNTIME_FUNCTION_ENTRY_SIZE;
    *outEntryCount = entryCount;

    ss_wddm_log(dxgContext, "ScanDxgkrnlRuntimeFunctionsForBaseline",
                "[WDDM-BASELINE] RuntimeFunctionCount=%u", entryCount);

    for (ULONG i = 0; i < entryCount; i++) {
        ULONG entryRva = exceptionRva + i * (ULONG)SS_RUNTIME_FUNCTION_ENTRY_SIZE;
        ULONG beginRva = 0;
        ULONG endRva = 0;

        if (ss_read_raw_rva_dword(dxgContext->pDump, dxgContext->fileSize,
                                  entryRva, &beginRva) == FALSE) {
            continue;
        }

        if (ss_read_raw_rva_dword(dxgContext->pDump, dxgContext->fileSize,
                                  entryRva + 4, &endRva) == FALSE) {
            continue;
        }

        if (beginRva == 0 || endRva <= beginRva) {
            continue;
        }

        if (ss_is_rva_executable(dxgContext->pDump, beginRva) == FALSE) {
            continue;
        }

        ss_scan_dxgkrnl_baseline_function(dxgContext, beginRva, endRva,
                                          recoverOutput, context,
                                          bestCandidate, &ambiguous);
    }

    if (bestCandidate->valid == FALSE) {
        ss_wddm_log(dxgContext, "ScanDxgkrnlRuntimeFunctionsForBaseline",
                    "[WDDM-BASELINE] No structural candidate");
        return FALSE;
    }

    if (ambiguous) {
        ss_wddm_log(dxgContext, "ScanDxgkrnlRuntimeFunctionsForBaseline",
                    "[WDDM-BASELINE] Best candidate ambiguous, reject baseline");
        return FALSE;
    }

    ss_wddm_log(dxgContext, "ScanDxgkrnlRuntimeFunctionsForBaseline",
                "[WDDM-BASELINE] Best structural candidate Writer=0x%X Base=%s Hits=%u "
                "Match=%u Missing=%u Extra=%u Score=%lld",
                bestCandidate->writerFunctionRva,
                ss_dispatch_reg_name(bestCandidate->baseReg),
                bestCandidate->hitCount,
                bestCandidate->matchCount, bestCandidate->missingCount,
                bestCandidate->extraCount, (long long)bestCandidate->score);

    return TRUE;
}

/* ==================================================================
 * ApplyWddmUniformDefault
 * ================================================================== */
static void ss_apply_wddm_uniform_default(const SS_RECOVERY_CONTEXT* context,
                                          const SS_SCAN_CONTEXT* dxgContext,
                                          const SS_WDDM_BASELINE_CANDIDATE* candidate,
                                          SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline)
{
    ULONG histRva[SS_DISPATCH_SLOT_COUNT];
    ULONG histCnt[SS_DISPATCH_SLOT_COUNT];
    INT histN = 0;
    INT bestIdx = -1;
    ULONG bestCnt = 0;
    ULONG defaultRva;
    ULONG filledCount = 0;

    memset(histRva, 0, sizeof(histRva));
    memset(histCnt, 0, sizeof(histCnt));

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        ULONG64 curAddr;
        ULONG curRva;
        BOOL found = FALSE;

        if (candidate->majorFunction[i].valid) {
            continue;
        }

        curAddr = context->hasCurrentMajorFunction ? context->currentMajorFunction[i] : 0;

        if (curAddr == 0) {
            continue;
        }
        if (curAddr == context->iopInvalidDeviceRequest) {
            continue;
        }
        if (ss_wddm_address_in_module(curAddr, dxgContext->imageBase,
                                      dxgContext->imageSize) == FALSE) {
            continue;
        }

        curRva = (ULONG)(curAddr - dxgContext->imageBase);

        for (INT j = 0; j < histN; j++) {
            if (histRva[j] == curRva) {
                histCnt[j] += 1;
                found = TRUE;
                break;
            }
        }

        if (found == FALSE) {
            if (histN <= SS_IRP_MJ_MAXIMUM_FUNCTION) {
                histRva[histN] = curRva;
                histCnt[histN] = 1;
                histN += 1;
            }
        }
    }

    if (histN == 0) {
        return;
    }

    for (INT j = 0; j < histN; j++) {
        if (histCnt[j] > bestCnt) {
            bestCnt = histCnt[j];
            bestIdx = j;
        }
    }

    if (bestIdx < 0) {
        return;
    }
    if (bestCnt < SS_WDDM_UNIFORM_DEFAULT_MIN_SLOTS) {
        return;
    }

    defaultRva = histRva[bestIdx];

    if (ss_is_rva_executable(dxgContext->pDump, defaultRva) == FALSE) {
        ss_wddm_log(dxgContext, "ApplyWddmUniformDefault",
                    "[WDDM-BASELINE] Uniform default rejected RVA=0x%X Count=%u "
                    "Reason=NotExecutable",
                    defaultRva, bestCnt);
        return;
    }

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        ULONG64 curAddr;

        if (candidate->majorFunction[i].valid) {
            continue;
        }

        curAddr = context->hasCurrentMajorFunction ? context->currentMajorFunction[i] : 0;

        if (curAddr == 0) {
            continue;
        }
        if (curAddr == context->iopInvalidDeviceRequest) {
            continue;
        }
        if (ss_wddm_address_in_module(curAddr, dxgContext->imageBase,
                                      dxgContext->imageSize) == FALSE) {
            continue;
        }

        if ((ULONG)(curAddr - dxgContext->imageBase) != defaultRva) {
            /*
             * current 在 dxgkrnl 内但偏离众数：保留 FrameworkOwned，
             * 凸显为可疑槽位。
             */
            ss_wddm_log(dxgContext, "ApplyWddmUniformDefault",
                        "[WDDM-BASELINE] NonDefault slot retained Slot=%u RVA=0x%X",
                        (ULONG)i, (ULONG)(curAddr - dxgContext->imageBase));
            continue;
        }

        baseline->majorFunction[i].valid = TRUE;
        baseline->majorFunction[i].moduleBase = dxgContext->imageBase;
        baseline->majorFunction[i].functionRva = defaultRva;
        baseline->majorFunction[i].state = SS_SLOT_RECOVERED;
        baseline->majorFunction[i].ownerKind = SS_OWNER_FRAMEWORK;
        baseline->majorFunction[i].source = SS_SOURCE_FRAMEWORK_DEFAULT;
        baseline->majorFunction[i].confidence = 85;

        filledCount += 1;

        ss_wddm_log(dxgContext, "ApplyWddmUniformDefault",
                    "[WDDM-BASELINE] %u UniformDefault RVA=0x%X VA=0x%llX",
                    (ULONG)i, defaultRva,
                    (unsigned long long)(dxgContext->imageBase + defaultRva));
    }

    if (filledCount > 0) {
        baseline->hasUniformDefault = TRUE;
        baseline->defaultRva = defaultRva;
        baseline->defaultSlotCount = filledCount;

        ss_wddm_log(dxgContext, "ApplyWddmUniformDefault",
                    "[WDDM-BASELINE] Uniform default accepted RVA=0x%X Distinct=%d Filled=%u",
                    defaultRva, histN, filledCount);
    }
}

/* ==================================================================
 * RecoverDxgkrnlDispatchBaseline
 *
 * 前置条件（由 RecoverDriverDispatch 保证）：
 *   ModelKind = WDDM 且已执行 MergeWddmDispatchResult（FrameworkOwned 标记）。
 * ================================================================== */
BOOL ss_recover_dxgkrnl_dispatch_baseline(const SS_RECOVERY_CONTEXT* context,
                                         const SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                         SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline)
{
    SS_SCAN_CONTEXT dxgContext;
    SS_WDDM_BASELINE_CANDIDATE candidate;

    ss_clear_wddm_dispatch_baseline(baseline);

    if (context->modelKind != SS_MODEL_WDDM) {
        return FALSE;
    }

    if (context->modelInfo.isWddm == FALSE) {
        return FALSE;
    }

    memset(&dxgContext, 0, sizeof(dxgContext));

    if (ss_load_dispatch_module_context_named(context, L"dxgkrnl.sys",
                                              &dxgContext) == FALSE) {
        ss_log_ctx_wddm(context, "RecoverDxgkrnlDispatchBaseline",
                        "[WDDM-BASELINE] Failed to load dxgkrnl.sys");
        return FALSE;
    }

    ss_clear_wddm_baseline_candidate(&candidate);

    if (ss_scan_dxgkrnl_runtime_functions_for_baseline(&dxgContext, recoverOutput,
                                                       context, &candidate,
                                                       &baseline->runtimeFunctionCount) == FALSE) {
        ss_log_ctx_wddm(context, "RecoverDxgkrnlDispatchBaseline",
                        "[WDDM-BASELINE] Structural scan found no candidate");
        return FALSE;
    }

    /*
     * 第二道保险：exact >= 4 是强验证（评分硬门槛已保证），
     * 这里只再要求候选至少覆盖 4 个槽位，防止极端巧合下的单点误匹配。
     */
    if (candidate.hitCount < SS_WDDM_MIN_CANDIDATE_SLOTS) {
        ss_log_ctx_wddm(context, "RecoverDxgkrnlDispatchBaseline",
                        "[WDDM-BASELINE] Candidate rejected Hits=%u", candidate.hitCount);
        return FALSE;
    }

    baseline->dxgkrnlBase = dxgContext.imageBase;
    baseline->dxgkrnlImageSize = dxgContext.imageSize;
    baseline->writerFunctionRva = candidate.writerFunctionRva;
    baseline->candidateBaseReg = candidate.baseReg;
    baseline->driverObjectTracked = candidate.driverObjectTracked;
    baseline->hitCount = candidate.hitCount;
    baseline->exactCount = candidate.exactCount;
    baseline->conflictCount = candidate.conflictCount;

    /* Confidence 由 dump 实证强度决定 */
    if (candidate.conflictCount == 0 && candidate.exactCount >= 8) {
        baseline->confidence = 95;
    } else if (candidate.conflictCount == 0 && candidate.exactCount >= 4) {
        baseline->confidence = 90;
    } else {
        baseline->confidence = 80;
    }

    /* ---- 第一层：exact slot 填充 ---- */
    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        ULONG targetRva;

        if (candidate.majorFunction[i].valid == FALSE) {
            continue;
        }

        targetRva = candidate.majorFunction[i].functionRva;

        /* 最后一次确认：baseline 必须指向 dxgkrnl 可执行代码。 */
        if (targetRva == 0 ||
            ss_is_rva_executable(dxgContext.pDump, targetRva) == FALSE) {
            continue;
        }

        baseline->majorFunction[i].valid = TRUE;
        baseline->majorFunction[i].moduleBase = dxgContext.imageBase;
        baseline->majorFunction[i].functionRva = targetRva;
        baseline->majorFunction[i].state = SS_SLOT_RECOVERED;
        baseline->majorFunction[i].ownerKind = SS_OWNER_FRAMEWORK;
        baseline->majorFunction[i].source = SS_SOURCE_FRAMEWORK_BASELINE;
        baseline->majorFunction[i].confidence = baseline->confidence;

        ss_wddm_log(&dxgContext, "RecoverDxgkrnlDispatchBaseline",
                    "[WDDM-BASELINE] %u RVA=0x%X VA=0x%llX",
                    (ULONG)i, targetRva,
                    (unsigned long long)(dxgContext.imageBase + targetRva));
    }

    /* ---- 第二层：uniform default 填充 ---- */
    ss_apply_wddm_uniform_default(context, &dxgContext, &candidate, baseline);

    ss_wddm_log(&dxgContext, "RecoverDxgkrnlDispatchBaseline",
                "[WDDM-BASELINE] Structural baseline accepted WriterRVA=0x%X Base=%s "
                "Hits=%u Exact=%u Confidence=%u",
                baseline->writerFunctionRva,
                ss_dispatch_reg_name(baseline->candidateBaseReg),
                baseline->hitCount, candidate.exactCount, baseline->confidence);

    return TRUE;
}

/* ==================================================================
 * MergeWddmDispatchBaseline
 *
 * baseline 只允许填 FrameworkOwned 槽位；且填入地址必须落在 dxgkrnl 内。
 * ================================================================== */
void ss_merge_wddm_dispatch_baseline(SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                     const SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline,
                                     ULONG64 dxgImageSize)
{
    if (baseline->hitCount == 0 || baseline->dxgkrnlBase == 0) {
        return;
    }

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        ULONG64 baselineVa;

        /* Generic direct recovery 优先级最高。 */
        if (recoverOutput->majorFunction[i].state == SS_SLOT_RECOVERED) {
            if (recoverOutput->majorFunction[i].source != SS_SOURCE_FRAMEWORK_BASELINE) {
                continue;
            }
        }

        /* Baseline 只允许填 FrameworkOwned。 */
        if (recoverOutput->majorFunction[i].state != SS_SLOT_FRAMEWORK_OWNED) {
            continue;
        }

        if (baseline->majorFunction[i].valid == FALSE) {
            continue;
        }

        /* baseline 地址自身必须属于 dxgkrnl.sys。 */
        baselineVa = baseline->majorFunction[i].moduleBase +
                     baseline->majorFunction[i].functionRva;

        if (ss_wddm_address_in_module(baselineVa, baseline->dxgkrnlBase,
                                      dxgImageSize) == FALSE) {
            continue;
        }

        recoverOutput->majorFunction[i].valid = TRUE;
        recoverOutput->majorFunction[i].moduleBase = baseline->majorFunction[i].moduleBase;
        recoverOutput->majorFunction[i].functionRva = baseline->majorFunction[i].functionRva;
        recoverOutput->majorFunction[i].state = SS_SLOT_RECOVERED;
        recoverOutput->majorFunction[i].ownerKind = SS_OWNER_FRAMEWORK;
        recoverOutput->majorFunction[i].source = baseline->majorFunction[i].source;
        recoverOutput->majorFunction[i].confidence = baseline->majorFunction[i].confidence;

        recoverOutput->hitCount += 1;
    }
}

/* ==================================================================
 * MergeWddmDispatchResult
 *
 * 对 current 属于 dxgkrnl.sys 的槽位：State=FrameworkOwned /
 * OwnerKind=Framework / Source=FrameworkClassification，
 * 且 Valid=False、ModuleBase=0、FunctionRva=0 —— 绝不伪造 OriginalFunction。
 * 其它槽位不覆盖 Generic 结果。
 * ================================================================== */
void ss_merge_wddm_dispatch_result(SS_DRIVER_RECOVERY_OUTPUT* recoverOutput,
                                   const SS_DRIVER_MODEL_INFO* modelInfo,
                                   const SS_RECOVERY_CONTEXT* context,
                                   ULONG64 dxgRuntimeBase,
                                   ULONG64 dxgImageSize)
{
    if (modelInfo->isWddm == FALSE) {
        return;
    }

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        ULONG64 curAddr = context->hasCurrentMajorFunction ? context->currentMajorFunction[i] : 0;

        if (curAddr == 0) {
            continue;
        }

        if (ss_wddm_address_in_module(curAddr, dxgRuntimeBase, dxgImageSize)) {
            recoverOutput->majorFunction[i].valid = FALSE;
            recoverOutput->majorFunction[i].moduleBase = 0;
            recoverOutput->majorFunction[i].functionRva = 0;
            recoverOutput->majorFunction[i].state = SS_SLOT_FRAMEWORK_OWNED;
            recoverOutput->majorFunction[i].ownerKind = SS_OWNER_FRAMEWORK;
            recoverOutput->majorFunction[i].source = SS_SOURCE_FRAMEWORK_CLASSIFY;
        }
    }
}

/* ==================================================================
 * Phase 2 调试转储（仅内部，**不导出**到 dispatch.h）
 *
 * 用于判断一个样本的 baseline 是「扫描没找到 / 评分淘汰 / merge 丢失」。
 * ================================================================== */
void ss_wddm_debug_dump_baseline(const SS_WDDM_DISPATCH_BASELINE_OUTPUT* baseline,
                                 SS_DISPATCH_LOG_CALLBACK sink, void* logContext)
{
    char line[256];

    if (sink == NULL || baseline == NULL) {
        return;
    }

    _snprintf(line, sizeof(line),
                "[WDDM-DUMP] hits=%u exact=%u conflict=%u confidence=%u "
                "dxgBase=0x%llX dxgImageSize=0x%llX writerRva=0x%X baseReg=%d "
                "tracked=%d runtimeFns=%u uniformDefault=%d defaultRva=0x%X "
                "defaultSlots=%u",
                baseline->hitCount, baseline->exactCount, baseline->conflictCount,
                baseline->confidence,
                (unsigned long long)baseline->dxgkrnlBase,
                (unsigned long long)baseline->dxgkrnlImageSize,
                baseline->writerFunctionRva, baseline->candidateBaseReg,
                baseline->driverObjectTracked,
                baseline->runtimeFunctionCount,
                baseline->hasUniformDefault, baseline->defaultRva,
                baseline->defaultSlotCount);
    sink(logContext, "WddmDebugDumpBaseline", line);

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (baseline->majorFunction[i].valid == FALSE) {
            continue;
        }

        _snprintf(line, sizeof(line),
                    "[WDDM-DUMP] slot[%d] rva=0x%X moduleBase=0x%llX state=%d owner=%d "
                    "source=%d confidence=%u",
                    i, baseline->majorFunction[i].functionRva,
                    (unsigned long long)baseline->majorFunction[i].moduleBase,
                    baseline->majorFunction[i].state,
                    baseline->majorFunction[i].ownerKind,
                    baseline->majorFunction[i].source,
                    baseline->majorFunction[i].confidence);
        sink(logContext, "WddmDebugDumpBaseline", line);
    }
}

/* ==================================================================
 * 已知缺口（Phase 2 进行中，显式记录，不得静默）
 *
 * 1. DispatchFastIo.inc（884 行）未移植 => FastIoDispatch 只上报
 *    fastIoDispatchRva，不恢复 27 个 FastIO 函数原始地址。
 * 2. DispatchKmdf.Inc（184 行）未移植 => KMDF 驱动不走框架 baseline 重写路径。
 * 3. DispatchFrameworkHid.inc（226 行）未移植 => 见
 *    ss_recover_hid_register_minidriver_dispatch 占位实现。
 * ================================================================== */
