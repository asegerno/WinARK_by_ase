/*
 * dispatch_generic.c -- Generic WDM（以及 WDDM 前置的通用）派遣表恢复
 *
 * 逐行等价移植自 ring3/modules/KernelHook/DispatchGeneric.Inc。
 * 结构：CFG 构建 -> 抽象状态数据流定点迭代 -> 稳定态重放产出恢复证据。
 * 判定阈值（±4096、DISPATCH_BASE、槽位边界等）全部保持原值。
 */
#include "pch.h"
#include "third_party/udis86/udis86.h"
#include "dispatch_internal.h"

#define SS_IRP_SLOT_NAME_COUNT 0x1C

static const WCHAR* const g_irpMjNames[SS_IRP_SLOT_NAME_COUNT] = {
    L"IRP_MJ_CREATE",
    L"IRP_MJ_CREATE_NAMED_PIPE",
    L"IRP_MJ_CLOSE",
    L"IRP_MJ_READ",
    L"IRP_MJ_WRITE",
    L"IRP_MJ_QUERY_INFORMATION",
    L"IRP_MJ_SET_INFORMATION",
    L"IRP_MJ_QUERY_EA",
    L"IRP_MJ_SET_EA",
    L"IRP_MJ_FLUSH_BUFFERS",
    L"IRP_MJ_QUERY_VOLUME_INFORMATION",
    L"IRP_MJ_SET_VOLUME_INFORMATION",
    L"IRP_MJ_DIRECTORY_CONTROL",
    L"IRP_MJ_FILE_SYSTEM_CONTROL",
    L"IRP_MJ_DEVICE_CONTROL",
    L"IRP_MJ_INTERNAL_DEVICE_CONTROL",
    L"IRP_MJ_SHUTDOWN",
    L"IRP_MJ_LOCK_CONTROL",
    L"IRP_MJ_CLEANUP",
    L"IRP_MJ_CREATE_MAILSLOT",
    L"IRP_MJ_QUERY_SECURITY",
    L"IRP_MJ_SET_SECURITY",
    L"IRP_MJ_POWER",
    L"IRP_MJ_SYSTEM_CONTROL",
    L"IRP_MJ_DEVICE_CHANGE",
    L"IRP_MJ_QUERY_QUOTA",
    L"IRP_MJ_SET_QUOTA",
    L"IRP_MJ_PNP"
};

const WCHAR* ss_irp_mj_name(ULONG irpIndex)
{
    if (irpIndex < SS_IRP_SLOT_NAME_COUNT) {
        return g_irpMjNames[irpIndex];
    }
    return L"IRP_MJ_UNKNOWN";
}

/* ==================================================================
 * SetRecoveredDispatch
 *
 * SS_SOURCE_NAME 定义在 dispatch_internal.h：框架语义恢复扫描（HID 注册）需要
 * 经 SS_SCAN_CONTEXT.recoveredSourceName 覆盖来源，而不是只看指令形态。
 * ================================================================== */
static SS_SOURCE_NAME ss_effective_source_name(const SS_SCAN_CONTEXT* ctx, SS_SOURCE_NAME fallback)
{
    if (ctx != NULL && ctx->recoveredSourceName != SS_SOURCE_NAME_MOV) {
        return (SS_SOURCE_NAME)ctx->recoveredSourceName;
    }
    return fallback;
}

static void ss_set_recovered_dispatch(SS_RECOVERY_OUTPUT* output, INT irpIndex,
                                      ULONG64 moduleBase, ULONG functionRva,
                                      SS_SOURCE_NAME sourceName)
{
    SS_FUNCTION_REF* ref;

    if (irpIndex < 0 || irpIndex > SS_IRP_MJ_MAXIMUM_FUNCTION) {
        return;
    }
    if (moduleBase == 0 || functionRva == 0) {
        return;
    }

    ref = &output->majorFunction[irpIndex];

    if (!ref->valid) {
        output->hitCount += 1;
    }

    ref->valid = TRUE;
    ref->moduleBase = moduleBase;
    ref->functionRva = functionRva;

    ref->state = SS_SLOT_RECOVERED;
    ref->ownerKind = SS_OWNER_DRIVER;

    if (sourceName == SS_SOURCE_NAME_REP_STOSQ) {
        ref->source = SS_SOURCE_REP_STOSQ;
    } else if (sourceName == SS_SOURCE_NAME_HID) {
        ref->source = SS_SOURCE_IMPORTED_FRAMEWORK;
    } else {
        ref->source = SS_SOURCE_DIRECT_STORE;
    }

    ref->confidence = 0;
}

/* ==================================================================
 * 条件跳转识别
 * ================================================================== */
static BOOL ss_is_dispatch_conditional_jump(int mnemonic)
{
    switch (mnemonic) {
    case UD_Ijo:
    case UD_Ijno:
    case UD_Ijb:
    case UD_Ijae:
    case UD_Ijz:
    case UD_Ijnz:
    case UD_Ijbe:
    case UD_Ija:
    case UD_Ijs:
    case UD_Ijns:
    case UD_Ijp:
    case UD_Ijnp:
    case UD_Ijl:
    case UD_Ijge:
    case UD_Ijle:
    case UD_Ijg:
    case UD_Ijcxz:
    case UD_Ijecxz:
    case UD_Ijrcxz:
        return TRUE;
    default:
        break;
    }
    return FALSE;
}

/* ==================================================================
 * 抽象状态：拷贝 / 相等 / join / 调用参数投影
 * ================================================================== */
static void ss_copy_abstract_state(SS_ABSTRACT_STATE* dst, const SS_ABSTRACT_STATE* src)
{
    dst->rspDelta = src->rspDelta;
    dst->rspKnown = src->rspKnown;
    for (INT i = 0; i < 16; i++) {
        ss_copy_reg(&dst->regState[i], &src->regState[i]);
    }
    for (INT i = 0; i < 32; i++) {
        dst->stackOffset[i] = src->stackOffset[i];
        ss_copy_reg(&dst->stackValue[i], &src->stackValue[i]);
    }
}

static BOOL ss_reg_equal(const SS_REG_STATE* a, const SS_REG_STATE* b)
{
    return (a->valueType == b->valueType) && (a->value == b->value);
}

static BOOL ss_abstract_state_equal(const SS_ABSTRACT_STATE* a, const SS_ABSTRACT_STATE* b)
{
    if (a->rspKnown != b->rspKnown) {
        return FALSE;
    }
    if (a->rspKnown && a->rspDelta != b->rspDelta) {
        return FALSE;
    }
    for (INT i = 0; i < 16; i++) {
        if (!ss_reg_equal(&a->regState[i], &b->regState[i])) {
            return FALSE;
        }
    }
    for (INT i = 0; i < 32; i++) {
        if (!ss_reg_equal(&a->stackValue[i], &b->stackValue[i])) {
            return FALSE;
        }
        if (a->stackValue[i].valueType != SS_REG_UNKNOWN &&
            a->stackOffset[i] != b->stackOffset[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

/*
 * Unknown is the conservative top value; only identical facts survive a join.
 * 返回 TRUE 表示 Dst 被改变（需要重新传播）。
 */
static BOOL ss_join_abstract_state(SS_ABSTRACT_STATE* dst, const SS_ABSTRACT_STATE* incoming)
{
    BOOL changed = FALSE;

    for (INT i = 0; i < 16; i++) {
        if (!ss_reg_equal(&dst->regState[i], &incoming->regState[i])) {
            if (dst->regState[i].valueType != SS_REG_UNKNOWN) {
                changed = TRUE;
            }
            ss_clear_reg(&dst->regState[i]);
        }
    }

    if (dst->rspKnown) {
        if (!incoming->rspKnown || dst->rspDelta != incoming->rspDelta) {
            dst->rspKnown = FALSE;
            dst->rspDelta = 0;
            changed = TRUE;
        }
    }

    for (INT i = 0; i < 32; i++) {
        if (dst->stackValue[i].valueType == SS_REG_UNKNOWN) {
            continue;
        }

        BOOL found = FALSE;
        if (dst->rspKnown) {
            for (INT n = 0; n < 32; n++) {
                if (incoming->stackValue[n].valueType != SS_REG_UNKNOWN &&
                    dst->stackOffset[i] == incoming->stackOffset[n] &&
                    ss_reg_equal(&dst->stackValue[i], &incoming->stackValue[n])) {
                    found = TRUE;
                    break;
                }
            }
        }

        if (!found) {
            ss_clear_reg(&dst->stackValue[i]);
            changed = TRUE;
        }
    }

    return changed;
}

static void ss_project_call_arguments(const SS_REG_STATE* regState, SS_ABSTRACT_STATE* entryState)
{
    memset(entryState, 0, sizeof(*entryState));
    entryState->rspKnown = TRUE;
    ss_copy_reg(&entryState->regState[1], &regState[1]);
    ss_copy_reg(&entryState->regState[2], &regState[2]);
    ss_copy_reg(&entryState->regState[8], &regState[8]);
    ss_copy_reg(&entryState->regState[9], &regState[9]);
}

/* ==================================================================
 * CFG 构建
 * ================================================================== */
static INT ss_dispatch_instruction_index(const INT* instructionMap, ULONG beginRva, ULONG rva)
{
    if (rva < beginRva || rva >= beginRva + SS_DISPATCH_FUNCTION_SCAN_RANGE) {
        return -1;
    }
    return instructionMap[rva - beginRva] - 1;
}

static INT ss_find_dispatch_cfg_block(const SS_CFG_FUNCTION* cfg, ULONG rva)
{
    for (INT i = 0; i < cfg->blockCount; i++) {
        if (cfg->blocks[i].startRva == rva) {
            return i;
        }
    }
    return -1;
}

static BOOL ss_build_dispatch_cfg(const SS_SCAN_CONTEXT* ctx, ULONG entryRva, SS_CFG_FUNCTION* cfg)
{
    SS_CFG_INSTRUCTION* instructions = NULL;
    INT*    instructionMap = NULL;
    BYTE*   covered = NULL;
    BYTE*   leaders = NULL;
    ULONG*  pending = NULL;
    BOOL    ok = FALSE;

    memset(cfg, 0, sizeof(*cfg));

    ULONG beginRva = entryRva;
    ULONG endRva = 0;
    ULONG pdataBegin = 0;
    ULONG pdataEnd = 0;

    if (ss_get_runtime_function_bounds(ctx->pDump, ctx->fileSize, entryRva, &pdataBegin, &pdataEnd)) {
        beginRva = pdataBegin;
        endRva = pdataEnd;
        if (endRva - beginRva > SS_DISPATCH_FUNCTION_SCAN_RANGE) {
            beginRva = entryRva;
            endRva = pdataEnd;
        }
    } else {
        if (entryRva > 0xFFFFFFFFUL - SS_DISPATCH_FUNCTION_SCAN_RANGE) {
            return FALSE;
        }
        endRva = entryRva + SS_DISPATCH_FUNCTION_SCAN_RANGE;
    }

    if (endRva - beginRva > SS_DISPATCH_FUNCTION_SCAN_RANGE) {
        endRva = beginRva + SS_DISPATCH_FUNCTION_SCAN_RANGE;
    }
    if (entryRva < beginRva || entryRva >= endRva) {
        return FALSE;
    }

    cfg->entryRva = entryRva;
    cfg->beginRva = beginRva;
    cfg->endRva = endRva;

    instructions = (SS_CFG_INSTRUCTION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                  sizeof(SS_CFG_INSTRUCTION) * SS_DISPATCH_CFG_MAX_INSTRUCTIONS);
    instructionMap = (INT*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     sizeof(INT) * SS_DISPATCH_FUNCTION_SCAN_RANGE);
    covered = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SS_DISPATCH_FUNCTION_SCAN_RANGE);
    leaders = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SS_DISPATCH_FUNCTION_SCAN_RANGE);
    pending = (ULONG*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                sizeof(ULONG) * SS_DISPATCH_CFG_MAX_INSTRUCTIONS * 2);

    if (!instructions || !instructionMap || !covered || !leaders || !pending) {
        goto cleanup;
    }

    INT pendingHead = 0;
    INT pendingTail = 1;
    INT instructionCount = 0;
    BOOL truncated = FALSE;

    pending[0] = entryRva;
    leaders[entryRva - beginRva] = 1;

    while (pendingHead < pendingTail) {
        ULONG rva = pending[pendingHead];
        pendingHead++;

        if (rva < beginRva || rva >= endRva) {
            continue;
        }

        ULONG offset = rva - beginRva;
        if (covered[offset] != 0) {
            continue;
        }
        if (instructionCount >= SS_DISPATCH_CFG_MAX_INSTRUCTIONS) {
            truncated = TRUE;
            break;
        }

        ULONG64 foa = ss_rva_to_foa(ctx->pDump, rva);
        if (foa == 0 || foa >= ctx->fileSize || !ss_is_rva_executable(ctx->pDump, rva)) {
            continue;
        }

        ULONG64 available = ctx->fileSize - foa;
        if (available > endRva - rva) {
            available = endRva - rva;
        }
        if (available > 15) {
            available = 15;
        }

        struct ud u;
        ud_init(&u);
        ud_set_mode(&u, 64);
        ud_set_pc(&u, rva);
        ud_set_input_buffer(&u, ctx->pDump + foa, (size_t)available);

        if (ud_decode(&u) == 0) {
            continue;
        }

        ULONG nextRva = (ULONG)(ud_insn_off(&u) + ud_insn_len(&u));
        if (nextRva <= rva || nextRva > endRva) {
            continue;
        }

        int mnemonic = (int)ud_insn_mnemonic(&u);
        const struct ud_operand* operand = ud_insn_opr(&u, 0);

        INT index = instructionCount;
        instructionCount++;

        instructions[index].startRva = rva;
        instructions[index].endRva = nextRva;
        instructionMap[offset] = index + 1;

        for (ULONG n = offset; n < nextRva - beginRva; n++) {
            covered[n] = 1;
        }

        if (mnemonic == UD_Iret || mnemonic == UD_Iretf) {
            instructions[index].terminator = 3;
        } else if (mnemonic == UD_Iinvalid || mnemonic == UD_Iint3) {
            instructions[index].terminator = 5;
        } else if (mnemonic == UD_Ijmp) {
            instructions[index].terminator = 4;
            if (operand != NULL && operand->typ == UD_OP_JIMM) {
                instructions[index].terminator = 2;
                instructions[index].successorRva[0] = ss_ud_relative_target_rva(&u, operand);
                instructions[index].successorCount = 1;
            }
        } else if (ss_is_dispatch_conditional_jump(mnemonic)) {
            instructions[index].terminator = 1;
            if (operand != NULL && operand->typ == UD_OP_JIMM) {
                instructions[index].successorRva[0] = ss_ud_relative_target_rva(&u, operand);
                instructions[index].successorCount = 1;
            }
            instructions[index].successorRva[1] = nextRva;
            instructions[index].successorCount = 2;
        } else {
            instructions[index].successorRva[0] = nextRva;
            instructions[index].successorCount = 1;
        }

        for (INT n = 0; n < instructions[index].successorCount; n++) {
            ULONG successor = instructions[index].successorRva[n];
            if (successor < beginRva || successor >= endRva) {
                continue;
            }
            if (instructions[index].terminator != 0) {
                leaders[successor - beginRva] = 1;
            }
            if (pendingTail <= SS_DISPATCH_CFG_MAX_INSTRUCTIONS * 2 - 1) {
                pending[pendingTail] = successor;
                pendingTail++;
            } else {
                truncated = TRUE;
            }
        }
    }

    if (truncated) {
        ss_log_ctx(ctx, "BuildDispatchCfg",
                   "[CFG-LIMIT] Function=0x%X Instructions=%d Pending=%d",
                   entryRva, instructionCount, pendingTail);
        goto cleanup;
    }

    cfg->blocks = (SS_CFG_BLOCK*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                           sizeof(SS_CFG_BLOCK) * SS_DISPATCH_CFG_MAX_BLOCKS);
    if (cfg->blocks == NULL) {
        goto cleanup;
    }

    for (ULONG offset = 0; offset + 1 <= endRva - beginRva; offset++) {
        if (offset >= endRva - beginRva) {
            break;
        }
        if (leaders[offset] == 0 || instructionMap[offset] == 0) {
            continue;
        }
        if (cfg->blockCount >= SS_DISPATCH_CFG_MAX_BLOCKS) {
            truncated = TRUE;
            break;
        }

        SS_CFG_BLOCK* block = &cfg->blocks[cfg->blockCount];
        cfg->blockCount++;

        block->startRva = beginRva + offset;

        ULONG cursor = block->startRva;
        while (cursor < endRva) {
            if (cursor != block->startRva && leaders[cursor - beginRva] != 0) {
                block->successorCount = 1;
                block->successorRva[0] = cursor;
                break;
            }

            INT index = ss_dispatch_instruction_index(instructionMap, beginRva, cursor);
            if (index < 0) {
                break;
            }

            block->instructionCount += 1;
            block->endRva = instructions[index].endRva;
            block->terminator = instructions[index].terminator;

            if (block->terminator != 0) {
                block->successorCount = instructions[index].successorCount;
                for (INT n = 0; n < block->successorCount; n++) {
                    block->successorRva[n] = instructions[index].successorRva[n];
                }
                break;
            }

            cursor = instructions[index].endRva;
        }

        if (block->endRva == 0) {
            cfg->blockCount -= 1;
        }
    }

    if (truncated) {
        ss_log_ctx(ctx, "BuildDispatchCfg",
                   "[CFG-LIMIT] Function=0x%X Blocks=%d", entryRva, cfg->blockCount);
        goto cleanup;
    }

    ss_log_ctx(ctx, "BuildDispatchCfg",
               "[CFG-BUILD] Function=0x%X Bounds=0x%X..0x%X Blocks=%d Instructions=%d",
               entryRva, beginRva, endRva, cfg->blockCount, instructionCount);

    for (INT i = 0; i < cfg->blockCount; i++) {
        SS_CFG_BLOCK* block = &cfg->blocks[i];
        char successors[64];
        successors[0] = '\0';

        for (INT n = 0; n < block->successorCount && n < 2; n++) {
            char one[24];
            _snprintf(one, sizeof(one), " 0x%X", block->successorRva[n]);
            strncat_s(successors, sizeof(successors), one, _TRUNCATE);
        }

        ss_log_ctx(ctx, "BuildDispatchCfg",
                   "[CFG-BLOCK] Start=0x%X End=0x%X Instructions=%d Terminator=%d Successors=%s",
                   block->startRva, block->endRva, block->instructionCount,
                   block->terminator, successors);
    }

    ok = (cfg->blockCount > 0) && (ss_find_dispatch_cfg_block(cfg, entryRva) >= 0);

cleanup:
    if (instructions) HeapFree(GetProcessHeap(), 0, instructions);
    if (instructionMap) HeapFree(GetProcessHeap(), 0, instructionMap);
    if (covered) HeapFree(GetProcessHeap(), 0, covered);
    if (leaders) HeapFree(GetProcessHeap(), 0, leaders);
    if (pending) HeapFree(GetProcessHeap(), 0, pending);

    if (!ok && cfg->blocks != NULL) {
        HeapFree(GetProcessHeap(), 0, cfg->blocks);
        cfg->blocks = NULL;
        cfg->blockCount = 0;
    }

    return ok;
}

/* ==================================================================
 * 诊断：DriverObject 写入候选
 * ================================================================== */
static void ss_log_driver_object_write_candidate(struct ud* u, int mnemonic,
                                                 const SS_REG_STATE* regState,
                                                 const SS_SCAN_CONTEXT* ctx)
{
    const struct ud_operand* op0 = ud_insn_opr(u, 0);
    const struct ud_operand* op1 = ud_insn_opr(u, 1);

    if (op0 == NULL || op0->typ != UD_OP_MEM) {
        return;
    }

    BOOL mayWrite = ss_ud_mnemonic_writes_op0(mnemonic);
    if (mnemonic == UD_Icmpxchg || mnemonic == UD_Ixchg) {
        mayWrite = TRUE;
    }
    if (!mayWrite) {
        return;
    }

    INT baseReg = ss_ud_reg_to_gpr_index(op0->Base);
    if (baseReg < 0) {
        return;
    }

    INT64 baseOffset = 0;
    BOOL baseIsDriverObject = FALSE;

    if (regState[baseReg].valueType == SS_REG_DRIVER_OBJECT) {
        baseIsDriverObject = TRUE;
    } else if (regState[baseReg].valueType == SS_REG_DRIVER_OBJECT_ADDRESS) {
        baseIsDriverObject = TRUE;
        baseOffset = (INT64)regState[baseReg].value;
    }

    if (!baseIsDriverObject) {
        return;
    }

    INT64 disp = ss_ud_memory_displacement(op0);

    INT indexReg = -1;
    BOOL indexKnown = TRUE;
    INT64 indexValue = 0;

    if (op0->index != UD_NONE) {
        indexReg = ss_ud_reg_to_gpr_index(op0->index);
        indexKnown = FALSE;

        if (indexReg >= 0 && regState[indexReg].valueType == SS_REG_IMMEDIATE) {
            ULONG scale = op0->scale;
            if (scale == 0) {
                scale = 1;
            }
            indexValue = (INT64)regState[indexReg].value * (INT64)scale;
            indexKnown = TRUE;
        }
    }

    INT srcState = SS_REG_UNKNOWN;
    ULONG64 srcValue = 0;

    if (op1 != NULL && op1->typ == UD_OP_REG) {
        INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);
        if (srcReg >= 0) {
            srcState = regState[srcReg].valueType;
            srcValue = regState[srcReg].value;
        }
    }

    INT64 totalDisp = baseOffset + disp + indexValue;

    ss_log_ctx(ctx, "ScanDispatchBasicBlock",
               "[DO-WRITE-CANDIDATE] RVA=0x%llX Mnemonic=%d BaseReg=%s Disp=0x%llX "
               "IndexReg=%d IndexKnown=%d TotalDisp=0x%llX SrcState=%s SrcValue=0x%llX",
               (ULONG64)ud_insn_off(u), mnemonic, ss_dispatch_reg_name(baseReg),
               (ULONG64)disp, indexReg, (int)indexKnown, (ULONG64)totalDisp,
               ss_dispatch_state_name(srcState), srcValue);
}

/* ==================================================================
 * 地址长度覆盖前缀检测
 * ================================================================== */
static BOOL ss_has_dispatch_address_override(struct ud* u)
{
    const uint8_t* bytes = ud_insn_ptr(u);
    if (bytes == NULL) {
        return FALSE;
    }

    ULONG len = (ULONG)ud_insn_len(u);
    for (ULONG i = 0; i < len; i++) {
        uint8_t value = bytes[i];

        if (value == 0x67) {
            return TRUE;
        }
        if (value == 0x66 || value == 0xF0 || value == 0xF2 || value == 0xF3 ||
            value == 0x2E || value == 0x36 || value == 0x3E || value == 0x26 ||
            value == 0x64 || value == 0x65 || (value >= 0x40 && value <= 0x4F)) {
            continue;
        }
        break;
    }
    return FALSE;
}

/* ==================================================================
 * 前向声明（相互递归）
 * ================================================================== */
void ss_scan_dispatch_function_with_args(const SS_SCAN_CONTEXT* ctx, SS_SCAN_STATE* state,
                                         ULONG currentFunctionRva,
                                         const SS_ABSTRACT_STATE* entryState,
                                         INT depth, SS_RECOVERY_OUTPUT* output);

static void ss_scan_imported_dispatch_call(const SS_SCAN_CONTEXT* callerCtx, SS_SCAN_STATE* state,
                                           struct ud* u, const struct ud_operand* callOperand,
                                           const SS_ABSTRACT_STATE* entryState,
                                           INT depth, SS_RECOVERY_OUTPUT* output);

/* ==================================================================
 * ExecuteDispatchBlock
 * ================================================================== */
static void ss_execute_dispatch_block(const SS_SCAN_CONTEXT* ctx, SS_SCAN_STATE* scanState,
                                      ULONG functionStartRva, INT depth,
                                      const SS_CFG_BLOCK* block,
                                      const SS_ABSTRACT_STATE* inState,
                                      SS_ABSTRACT_STATE* outState,
                                      BOOL emitEffects,
                                      SS_RECOVERY_OUTPUT* output)
{
    ULONG64 blockFoa = ss_rva_to_foa(ctx->pDump, block->startRva);
    if (blockFoa == 0 || blockFoa >= ctx->fileSize) {
        return;
    }
    if (block->endRva <= block->startRva) {
        return;
    }

    ULONG64 scanSize = block->endRva - block->startRva;
    if (scanSize > ctx->fileSize - blockFoa) {
        return;
    }

    SS_REG_STATE regState[16];
    INT64        stackOffset[32];
    SS_REG_STATE stackValue[32];

    INT64 rspDelta = inState->rspDelta;
    BOOL  rspKnown = inState->rspKnown;

    for (INT i = 0; i < 16; i++) {
        ss_copy_reg(&regState[i], &inState->regState[i]);
    }
    for (INT i = 0; i < 32; i++) {
        stackOffset[i] = inState->stackOffset[i];
        ss_copy_reg(&stackValue[i], &inState->stackValue[i]);
    }

    struct ud u;
    ud_init(&u);
    ud_set_mode(&u, 64);
    ud_set_pc(&u, block->startRva);
    ud_set_input_buffer(&u, ctx->pDump + blockFoa, (size_t)scanSize);

    while (ud_decode(&u) != 0) {
        ULONG insnRva = (ULONG)ud_insn_off(&u);
        int mnemonic = (int)ud_insn_mnemonic(&u);
        const struct ud_operand* op0 = ud_insn_opr(&u, 0);
        const struct ud_operand* op1 = ud_insn_opr(&u, 1);

        if (insnRva < block->startRva || insnRva >= block->endRva) {
            break;
        }

        /* CALL 可以破坏 outgoing home area */
        if (mnemonic == UD_Icall && rspKnown) {
            for (INT n = 0; n < 32; n++) {
                if (stackOffset[n] < rspDelta + 32 && stackOffset[n] + 8 > rspDelta) {
                    ss_clear_reg(&stackValue[n]);
                }
            }
        }

        /* RSP tracking */
        if (rspKnown && (mnemonic == UD_Ipush || mnemonic == UD_Ipop)) {
            if (op0 == NULL || op0->SIZE != 64) {
                rspKnown = FALSE;
            } else if (mnemonic == UD_Ipush) {
                rspDelta -= 8;
                for (INT n = 0; n < 32; n++) {
                    if (stackOffset[n] < rspDelta + 8 && stackOffset[n] + 8 > rspDelta) {
                        ss_clear_reg(&stackValue[n]);
                    }
                }
            } else {
                rspDelta += 8;
            }
        }

        if (op0 != NULL && op0->typ == UD_OP_REG) {
            if (ss_ud_reg_to_gpr_index(op0->Base) == 4) {
                if ((mnemonic == UD_Iadd || mnemonic == UD_Isub) &&
                    op0->SIZE == 64 && op1 != NULL && op1->typ == UD_OP_IMM) {

                    INT64 adjustment = ss_ud_signed_value(&op1->lval, op1->SIZE);

                    if (adjustment < -4096 || adjustment > 4096) {
                        rspKnown = FALSE;
                    } else if (mnemonic == UD_Iadd) {
                        rspDelta += adjustment;
                    } else {
                        rspDelta -= adjustment;
                    }
                } else if (mnemonic == UD_Imov || mnemonic == UD_Ilea ||
                           ss_ud_mnemonic_writes_op0(mnemonic)) {
                    rspKnown = FALSE;
                }
            }
        }

        if (rspDelta < -4096 || rspDelta > 4096) {
            rspKnown = FALSE;
        }

        /* stack store */
        if (op0 != NULL && op0->typ == UD_OP_MEM) {
            if (op0->Base == UD_R_RSP && op0->index == UD_NONE && rspKnown) {
                INT64 stackSlot = rspDelta + ss_ud_memory_displacement(op0);

                for (INT n = 0; n < 32; n++) {
                    if (stackOffset[n] < stackSlot + (((INT64)op0->SIZE + 7) / 8) &&
                        stackOffset[n] + 8 > stackSlot) {
                        ss_clear_reg(&stackValue[n]);
                    }
                }

                if (mnemonic == UD_Imov && op0->SIZE == 64 && ss_ud_is_64bit_gpr(op1)) {
                    INT sourceReg = ss_ud_reg_to_gpr_index(op1->Base);

                    if (sourceReg >= 0 && stackSlot >= -4096 && stackSlot <= 4096) {
                        for (INT n = 0; n < 32; n++) {
                            if (stackValue[n].valueType == SS_REG_UNKNOWN) {
                                stackOffset[n] = stackSlot;
                                ss_copy_reg(&stackValue[n], &regState[sourceReg]);
                                break;
                            }
                        }
                    }
                }
            } else {
                for (INT n = 0; n < 32; n++) {
                    ss_clear_reg(&stackValue[n]);
                }
            }
        }

        /* stack reload */
        if (mnemonic == UD_Imov && ss_ud_is_64bit_gpr(op0) && op1 != NULL) {
            if (op1->typ == UD_OP_MEM && op1->Base == UD_R_RSP &&
                op1->index == UD_NONE && op1->SIZE == 64 && rspKnown) {

                INT destReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (destReg >= 0) {
                    ss_clear_reg(&regState[destReg]);

                    INT64 stackSlot = rspDelta + ss_ud_memory_displacement(op1);

                    for (INT n = 0; n < 32; n++) {
                        if (stackValue[n].valueType != SS_REG_UNKNOWN &&
                            stackOffset[n] == stackSlot) {
                            ss_copy_reg(&regState[destReg], &stackValue[n]);
                            break;
                        }
                    }
                }

                continue;
            }
        }

        /* ======================= CALL ======================= */
        if (mnemonic == UD_Icall) {
            SS_ABSTRACT_STATE callEntry;
            ss_project_call_arguments(regState, &callEntry);

            INT driverObjectArgReg = ss_find_driver_object_argument_register(regState);
            BOOL passDriverObject = (driverObjectArgReg >= 0);

            if (op0 != NULL) {
                if (op0->typ == UD_OP_JIMM) {
                    ULONG callTarget = ss_ud_relative_target_rva(&u, op0);

                    if (emitEffects) {
                        ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                   "[CFG-CALL] Caller=0x%X CallRVA=0x%X Target=0x%X DriverObject=%d ArgReg=%d",
                                   functionStartRva, insnRva, callTarget,
                                   (int)passDriverObject, driverObjectArgReg);
                    }

                    if (emitEffects && passDriverObject &&
                        callTarget != 0 && callTarget != functionStartRva &&
                        depth < SS_DISPATCH_MAX_CALL_DEPTH &&
                        ss_is_rva_executable(ctx->pDump, callTarget) &&
                        ss_rva_to_foa(ctx->pDump, callTarget) != 0) {

                        ss_scan_dispatch_function_with_args(ctx, scanState, callTarget,
                                                            &callEntry, depth + 1, output);
                    }
                } else if (op0->typ == UD_OP_REG) {
                    INT targetReg = ss_ud_reg_to_gpr_index(op0->Base);
                    ULONG callTarget = 0;
                    BOOL targetKnown = FALSE;

                    if (targetReg >= 0) {
                        if (regState[targetReg].valueType == SS_REG_IMAGE_ADDRESS ||
                            regState[targetReg].valueType == SS_REG_STATIC_POINTER) {

                            callTarget = (ULONG)regState[targetReg].value;

                            if (callTarget != 0 &&
                                ss_is_rva_executable(ctx->pDump, callTarget) &&
                                ss_rva_to_foa(ctx->pDump, callTarget) != 0) {
                                targetKnown = TRUE;
                            }
                        }
                    }

                    if (targetKnown) {
                        if (emitEffects) {
                            ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                       "[CFG-INDIRECT-CALL] Caller=0x%X CallRVA=0x%X TargetReg=%s "
                                       "Target=0x%X DriverObject=%d ArgReg=%d",
                                       functionStartRva, insnRva, ss_dispatch_reg_name(targetReg),
                                       callTarget, (int)passDriverObject, driverObjectArgReg);
                        }

                        if (emitEffects && passDriverObject &&
                            depth < SS_DISPATCH_MAX_CALL_DEPTH) {
                            ss_scan_dispatch_function_with_args(ctx, scanState, callTarget,
                                                                &callEntry, depth + 1, output);
                        }
                    } else {
                        INT targetState = SS_REG_UNKNOWN;
                        ULONG64 targetValue = 0;

                        if (targetReg >= 0) {
                            targetState = regState[targetReg].valueType;
                            targetValue = regState[targetReg].value;
                        }

                        if (emitEffects) {
                            ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                       "[CFG-INDIRECT-CALL-UNRESOLVED] Caller=0x%X CallRVA=0x%X "
                                       "TargetReg=%d TargetState=%s TargetValue=0x%llX DriverObject=%d ArgReg=%d",
                                       functionStartRva, insnRva, targetReg,
                                       ss_dispatch_state_name(targetState), targetValue,
                                       (int)passDriverObject, driverObjectArgReg);
                        }
                    }
                } else if (op0->typ == UD_OP_MEM) {
                    if (op0->Base == UD_R_RIP && op0->index == UD_NONE) {
                        if (depth < SS_DISPATCH_MAX_CALL_DEPTH) {
                            ss_scan_imported_dispatch_call(ctx, scanState, &u, op0,
                                                           &callEntry, depth, output);
                        }
                    } else {
                        INT baseReg = ss_ud_reg_to_gpr_index(op0->Base);
                        BOOL targetKnown = FALSE;
                        ULONG callTarget = 0;
                        ULONG slotRva = 0;

                        if (baseReg >= 0 &&
                            (regState[baseReg].valueType == SS_REG_IMAGE_ADDRESS ||
                             regState[baseReg].valueType == SS_REG_STATIC_POINTER)) {

                            INT64 totalOffset = ss_ud_memory_displacement(op0);
                            BOOL indexKnown = TRUE;

                            if (op0->index != UD_NONE) {
                                indexKnown = FALSE;
                                INT indexReg = ss_ud_reg_to_gpr_index(op0->index);

                                if (indexReg >= 0 &&
                                    regState[indexReg].valueType == SS_REG_IMMEDIATE) {
                                    ULONG scale = op0->scale;
                                    if (scale == 0) {
                                        scale = 1;
                                    }
                                    totalOffset += (INT64)regState[indexReg].value * (INT64)scale;
                                    indexKnown = TRUE;
                                }
                            }

                            if (indexKnown) {
                                INT64 slot64 = (INT64)regState[baseReg].value + totalOffset;

                                if (slot64 > 0 && slot64 <= 0xFFFFFFFFLL) {
                                    slotRva = (ULONG)slot64;

                                    if (ss_read_image_pointer_rva(ctx, slotRva, &callTarget)) {
                                        if (ss_is_rva_executable(ctx->pDump, callTarget)) {
                                            targetKnown = TRUE;
                                        }
                                    }
                                }
                            }
                        }

                        if (targetKnown) {
                            if (emitEffects) {
                                ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                           "[CFG-MEM-CALL] Caller=0x%X CallRVA=0x%X SlotRVA=0x%X "
                                           "Target=0x%X DriverObject=%d ArgReg=%d",
                                           functionStartRva, insnRva, slotRva, callTarget,
                                           (int)passDriverObject, driverObjectArgReg);
                            }

                            if (emitEffects && passDriverObject && depth < SS_DISPATCH_MAX_CALL_DEPTH) {
                                ss_scan_dispatch_function_with_args(ctx, scanState, callTarget,
                                                                    &callEntry, depth + 1, output);
                            }
                        } else {
                            INT baseState = SS_REG_UNKNOWN;
                            if (baseReg >= 0) {
                                baseState = regState[baseReg].valueType;
                            }

                            if (emitEffects) {
                                ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                           "[CFG-MEM-CALL-UNRESOLVED] Caller=0x%X CallRVA=0x%X "
                                           "BaseReg=%d BaseState=%s Disp=0x%llX DriverObject=%d ArgReg=%d",
                                           functionStartRva, insnRva, baseReg,
                                           ss_dispatch_state_name(baseState),
                                           (ULONG64)ss_ud_memory_displacement(op0),
                                           (int)passDriverObject, driverObjectArgReg);
                            }
                        }
                    }
                } else {
                    if (emitEffects) {
                        ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                   "[CFG-CALL-UNSUPPORTED] Caller=0x%X CallRVA=0x%X OperandType=%d "
                                   "DriverObject=%d ArgReg=%d",
                                   functionStartRva, insnRva, (int)op0->typ,
                                   (int)passDriverObject, driverObjectArgReg);
                    }
                }
            }

            ss_invalidate_volatile_regs(regState);
            continue;
        }

        /* ======================= RET ======================= */
        if (mnemonic == UD_Iret || mnemonic == UD_Iretf) {
            break;
        }

        /* ============== 无条件 JMP / 条件跳转（块边界） ============== */
        if (mnemonic == UD_Ijmp || ss_is_dispatch_conditional_jump(mnemonic)) {
            break;
        }

        if (emitEffects) {
            ss_log_driver_object_write_candidate(&u, mnemonic, regState, ctx);
        }

        if (emitEffects && mnemonic == UD_Icmpxchg &&
            op0 != NULL && op1 != NULL &&
            op0->typ == UD_OP_MEM && op0->SIZE == 64 && ss_ud_is_64bit_gpr(op1)) {

            INT baseReg = ss_ud_reg_to_gpr_index(op0->Base);
            INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);

            if (baseReg >= 0 && srcReg >= 0) {
                if ((regState[srcReg].valueType == SS_REG_IMAGE_ADDRESS ||
                     regState[srcReg].valueType == SS_REG_STATIC_POINTER) &&
                    ss_is_rva_executable(ctx->pDump, (ULONG)regState[srcReg].value)) {

                    ss_log_ctx(ctx, "ExecuteDispatchBlock",
                               "[UNRESOLVED-CMPXCHG] Function=0x%X RVA=0x%X Base=%s BaseState=%s "
                               "Disp=0x%llX SourceRVA=0x%llX",
                               functionStartRva, insnRva, ss_dispatch_reg_name(baseReg),
                               ss_dispatch_state_name(regState[baseReg].valueType),
                               (ULONG64)ss_ud_memory_displacement(op0), regState[srcReg].value);
                }
            }
        }

        switch (mnemonic) {
        /* Full-register zero idiom. A 32-bit write zero-extends on x64;
         * 8/16-bit writes cannot establish the full register value. */
        case UD_Ixor:
            if (op0 != NULL && op1 != NULL &&
                op0->typ == UD_OP_REG && op1->typ == UD_OP_REG &&
                op0->Base == op1->Base &&
                (op0->SIZE == 32 || op0->SIZE == 64)) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                if (dst >= 0) {
                    ss_clear_reg(&regState[dst]);
                    regState[dst].valueType = SS_REG_IMMEDIATE;
                    regState[dst].value = 0;
                }
            } else {
                ss_invalidate_unknown_instruction_destination(&u, regState);
            }
            break;

        /*
         * A bounded affine adjustment retains DriverObject provenance.
         * At a loop join, different offsets still collapse to Unknown.
         */
        case UD_Iadd:
        case UD_Isub:
            if (mnemonic == UD_Isub && op0 != NULL && op1 != NULL &&
                op0->typ == UD_OP_REG && op1->typ == UD_OP_REG &&
                op0->Base == op1->Base &&
                (op0->SIZE == 32 || op0->SIZE == 64)) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                if (dst >= 0) {
                    ss_clear_reg(&regState[dst]);
                    regState[dst].valueType = SS_REG_IMMEDIATE;
                    regState[dst].value = 0;
                }
                break;
            }
            if (ss_ud_is_64bit_gpr(op0) && op1 != NULL && op1->typ == UD_OP_IMM) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                if (dst >= 0) {
                    INT64 delta = ss_ud_signed_value(&op1->lval, op1->SIZE);
                    if (mnemonic == UD_Isub) {
                        delta = -delta;
                    }

                    INT64 currentOffset = 0;
                    BOOL objectBase = FALSE;

                    if (regState[dst].valueType == SS_REG_DRIVER_OBJECT) {
                        objectBase = TRUE;
                    } else if (regState[dst].valueType == SS_REG_DRIVER_OBJECT_ADDRESS) {
                        objectBase = TRUE;
                        currentOffset = (INT64)regState[dst].value;
                    }

                    if (objectBase && delta >= -4096 && delta <= 4096 &&
                        currentOffset + delta >= -4096 && currentOffset + delta <= 4096) {
                        regState[dst].valueType = SS_REG_DRIVER_OBJECT_ADDRESS;
                        regState[dst].value = (ULONG64)(currentOffset + delta);
                    } else {
                        ss_clear_reg(&regState[dst]);
                    }
                }
            } else {
                ss_invalidate_unknown_instruction_destination(&u, regState);
            }
            break;

        /* ======================= IMUL ======================= */
        case UD_Iimul: {
            const struct ud_operand* op2 = ud_insn_opr(&u, 2);

            if (op0 != NULL && op1 != NULL && op0->typ == UD_OP_REG) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                SS_REG_STATE lhs;
                SS_REG_STATE rhs;

                memset(&lhs, 0, sizeof(lhs));
                memset(&rhs, 0, sizeof(rhs));

                if (dst >= 0) {
                    lhs = regState[dst];
                    ss_clear_reg(&regState[dst]);

                    if (op2 != NULL && op2->typ == UD_OP_IMM) {
                        if (op1->typ == UD_OP_REG) {
                            INT src = ss_ud_reg_to_gpr_index(op1->Base);

                            if (src >= 0) {
                                if (src != dst) {
                                    lhs = regState[src];
                                }
                            } else {
                                ss_clear_reg(&lhs);
                            }
                        } else {
                            ss_clear_reg(&lhs);
                        }

                        rhs.valueType = SS_REG_IMMEDIATE;
                        rhs.value = (ULONG64)ss_ud_signed_value(&op2->lval, op2->SIZE);
                    } else if (op1->typ == UD_OP_REG) {
                        INT src = ss_ud_reg_to_gpr_index(op1->Base);

                        if (src == dst) {
                            rhs = lhs;
                        } else if (src >= 0) {
                            rhs = regState[src];
                        }
                    }

                    if ((op0->SIZE == 32 || op0->SIZE == 64) &&
                        lhs.valueType == SS_REG_IMMEDIATE &&
                        rhs.valueType == SS_REG_IMMEDIATE) {

                        regState[dst].valueType = SS_REG_IMMEDIATE;
                        regState[dst].value = lhs.value * rhs.value;

                        if (op0->SIZE == 32) {
                            regState[dst].value &= 0xFFFFFFFFULL;
                        }
                    }
                }
            }

            if (op1 == NULL || op1->typ == UD_NONE) {
                ss_clear_reg(&regState[0]);
                ss_clear_reg(&regState[2]);
            }
            break;
        }

        /* ======================= MOV ======================= */
        case UD_Imov:

            /* MOV reg,reg */
            if (ss_ud_is_64bit_gpr(op0) && ss_ud_is_64bit_gpr(op1)) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);
                INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);

                if (dstReg >= 0 && srcReg >= 0) {
                    ss_copy_reg(&regState[dstReg], &regState[srcReg]);

                    if (emitEffects && regState[dstReg].valueType != SS_REG_UNKNOWN) {
                        ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                   "[FLOW] RVA=0x%X %s <- %s State=%s Value=0x%llX",
                                   insnRva, ss_dispatch_reg_name(dstReg),
                                   ss_dispatch_reg_name(srcReg),
                                   ss_dispatch_state_name(regState[dstReg].valueType),
                                   regState[dstReg].value);
                    }
                }

                continue;
            }

            /* MOV reg,[mem64] : 常数指针表或运行时对象指针 */
            if (ss_ud_is_64bit_gpr(op0) && op1 != NULL &&
                op1->typ == UD_OP_MEM && op1->SIZE == 64) {

                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    BOOL slotKnown = FALSE;
                    ULONG slotRva = 0;

                    if (op1->Base == UD_R_RIP && op1->index == UD_NONE) {
                        slotRva = ss_get_rip_relative_operand_rva(&u, op1);
                        slotKnown = (slotRva != 0);
                    } else {
                        INT baseReg = ss_ud_reg_to_gpr_index(op1->Base);

                        if (baseReg >= 0 &&
                            (regState[baseReg].valueType == SS_REG_IMAGE_ADDRESS ||
                             regState[baseReg].valueType == SS_REG_STATIC_POINTER)) {

                            INT64 totalOffset = ss_ud_memory_displacement(op1);
                            BOOL indexKnown = TRUE;

                            if (op1->index != UD_NONE) {
                                indexKnown = FALSE;
                                INT indexReg = ss_ud_reg_to_gpr_index(op1->index);

                                if (indexReg >= 0 &&
                                    regState[indexReg].valueType == SS_REG_IMMEDIATE) {
                                    ULONG scale = op1->scale;
                                    if (scale == 0) {
                                        scale = 1;
                                    }
                                    totalOffset += (INT64)regState[indexReg].value * (INT64)scale;
                                    indexKnown = TRUE;
                                }
                            }

                            if (indexKnown) {
                                INT64 candidate64 = (INT64)regState[baseReg].value + totalOffset;

                                if (candidate64 > 0 && candidate64 <= 0xFFFFFFFFLL) {
                                    slotRva = (ULONG)candidate64;
                                    slotKnown = TRUE;
                                }
                            }
                        }
                    }

                    if (slotKnown) {
                        ULONG loadedRva = 0;

                        if (ss_read_image_pointer_rva(ctx, slotRva, &loadedRva)) {
                            ss_clear_reg(&regState[dstReg]);
                            regState[dstReg].valueType = SS_REG_STATIC_POINTER;
                            regState[dstReg].value = loadedRva;

                            if (emitEffects) {
                                ss_log_ctx(ctx, "ScanDispatchBasicBlock",
                                           "[FLOW-PTR] RVA=0x%X %s <- [Image+0x%X] TargetRVA=0x%X State=%s",
                                           insnRva, ss_dispatch_reg_name(dstReg), slotRva,
                                           loadedRva, ss_dispatch_state_name(regState[dstReg].valueType));
                            }

                            continue;
                        }
                    }

                    /*
                     * 框架注册块字段 load：registration->DriverObject。
                     * 真实 HIDCLASS 形状是
                     *     lea r14,[rcx+8] ; mov r14,[r14]
                     * 这里补上「字段地址 -> 字段值」这一段，此后完全走既有的
                     * DriverObject 数据流（lea [DO+0x70] / mov [DO+slot*8]）。
                     */
                    if (op1->index == UD_NONE) {
                        INT fieldBase = ss_ud_reg_to_gpr_index(op1->Base);

                        if (fieldBase >= 0 &&
                            regState[fieldBase].valueType == SS_REG_FRAMEWORK_REGISTRATION_FIELD) {

                            INT64 fieldOffset = (INT64)regState[fieldBase].value +
                                                ss_ud_memory_displacement(op1);

                            if (fieldOffset == SS_FRAMEWORK_REGISTRATION_DRIVER_OBJECT_OFFSET) {
                                ss_clear_reg(&regState[dstReg]);
                                regState[dstReg].valueType = SS_REG_DRIVER_OBJECT;
                                continue;
                            }
                        }
                    }

                    ss_clear_reg(&regState[dstReg]);
                    regState[dstReg].valueType = SS_REG_OBJECT_POINTER;
                }

                continue;
            }

            /* MOV [DriverObject+disp], FunctionReg */
            if (op0 != NULL && op1 != NULL &&
                op0->typ == UD_OP_MEM && op1->typ == UD_OP_REG) {

                INT baseReg = ss_ud_reg_to_gpr_index(op0->Base);
                INT srcReg = ss_ud_reg_to_gpr_index(op1->Base);
                INT64 disp = ss_ud_memory_displacement(op0);

                INT64 baseOffset = 0;
                BOOL baseIsDriverObject = FALSE;

                if (baseReg >= 0) {
                    if (regState[baseReg].valueType == SS_REG_DRIVER_OBJECT) {
                        baseIsDriverObject = TRUE;
                    } else if (regState[baseReg].valueType == SS_REG_DRIVER_OBJECT_ADDRESS) {
                        baseIsDriverObject = TRUE;
                        baseOffset = (INT64)regState[baseReg].value;
                    }
                }

                BOOL indexKnown = TRUE;
                INT64 indexOffset = 0;

                if (op0->index != UD_NONE) {
                    INT indexReg = ss_ud_reg_to_gpr_index(op0->index);
                    ULONG indexScale = op0->scale;
                    if (indexScale == 0) {
                        indexScale = 1;
                    }

                    indexKnown = FALSE;

                    if (indexReg >= 0 &&
                        (indexScale == 1 || indexScale == 2 || indexScale == 4 || indexScale == 8)) {
                        if (regState[indexReg].valueType == SS_REG_IMMEDIATE &&
                            regState[indexReg].value <= 4096) {
                            indexOffset = (INT64)regState[indexReg].value * (INT64)indexScale;
                            indexKnown = TRUE;
                        }
                    }
                }

                if (baseOffset < -4096 || baseOffset > 4096 || disp < -4096 || disp > 4096) {
                    indexKnown = FALSE;
                }

                if (indexKnown && !ss_has_dispatch_address_override(&u) &&
                    op0->SIZE == 64 && op1->SIZE == 64) {

                    INT64 totalDisp = baseOffset + disp + indexOffset;

                    if (baseIsDriverObject && srcReg >= 0) {
                        if (totalDisp == SS_DRIVER_OBJECT_FAST_IO_DISPATCH &&
                            (regState[srcReg].valueType == SS_REG_IMAGE_ADDRESS ||
                             regState[srcReg].valueType == SS_REG_STATIC_POINTER)) {

                            if (emitEffects) {
                                output->fastIoDispatchRva = (ULONG)regState[srcReg].value;
                            }
                        }
                    }

                    if (emitEffects && !baseIsDriverObject && baseReg >= 0 && srcReg >= 0 &&
                        op0->SIZE == 64 && op1->SIZE == 64 &&
                        (regState[srcReg].valueType == SS_REG_IMAGE_ADDRESS ||
                         regState[srcReg].valueType == SS_REG_STATIC_POINTER) &&
                        ss_is_rva_executable(ctx->pDump, (ULONG)regState[srcReg].value)) {

                        ss_log_ctx(ctx, "ExecuteDispatchBlock",
                                   "[UNRESOLVED-STORE] Function=0x%X RVA=0x%X Base=%s BaseState=%s "
                                   "Disp=0x%llX SourceRVA=0x%llX",
                                   functionStartRva, insnRva, ss_dispatch_reg_name(baseReg),
                                   ss_dispatch_state_name(regState[baseReg].valueType),
                                   (ULONG64)disp, regState[srcReg].value);
                    }

                    if (baseIsDriverObject && srcReg >= 0 &&
                        (regState[srcReg].valueType == SS_REG_IMAGE_ADDRESS ||
                         regState[srcReg].valueType == SS_REG_STATIC_POINTER) &&
                        ss_is_rva_executable(ctx->pDump, (ULONG)regState[srcReg].value)) {

                        if (totalDisp >= SS_DISPATCH_BASE &&
                            totalDisp <= SS_DISPATCH_BASE +
                                          (INT64)SS_IRP_MJ_MAXIMUM_FUNCTION * SS_DISPATCH_STEP) {

                            INT64 delta = totalDisp - SS_DISPATCH_BASE;

                            if ((delta % SS_DISPATCH_STEP) == 0) {
                                INT64 irpIndex = delta / SS_DISPATCH_STEP;

                                if (irpIndex >= 0 && irpIndex <= SS_IRP_MJ_MAXIMUM_FUNCTION) {
                                    if (emitEffects) {
                                        ss_set_recovered_dispatch(output, (INT)irpIndex,
                                                                  ctx->imageBase,
                                                                  (ULONG)regState[srcReg].value,
                                                                  ss_effective_source_name(ctx,
                                                                      SS_SOURCE_NAME_MOV));
                                    }
                                }
                            }
                        }
                    }
                }

                continue;
            }

            /* MOV reg,imm */
            if (op0 != NULL && op1 != NULL &&
                op0->typ == UD_OP_REG && op1->typ == UD_OP_IMM) {

                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    ss_clear_reg(&regState[dstReg]);

                    if (op0->SIZE == 32 || op0->SIZE == 64) {
                        ULONG64 immValue = 0;

                        switch (op1->SIZE) {
                        case 8:  immValue = op1->lval.UByte;  break;
                        case 16: immValue = op1->lval.UWORD;  break;
                        case 32: immValue = op1->lval.udword; break;
                        case 64: immValue = op1->lval.uqword; break;
                        default: break;
                        }

                        regState[dstReg].valueType = SS_REG_IMMEDIATE;
                        regState[dstReg].value = immValue;
                    }
                }

                continue;
            }

            if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);
                if (dstReg >= 0) {
                    ss_clear_reg(&regState[dstReg]);
                }
            }
            break;

        /* ======================= LEA ======================= */
        case UD_Ilea:
            if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dstReg = ss_ud_reg_to_gpr_index(op0->Base);

                if (dstReg >= 0) {
                    ss_clear_reg(&regState[dstReg]);

                    if (op1 != NULL && op1->typ == UD_OP_MEM && op1->index == UD_NONE) {
                        INT baseReg = ss_ud_reg_to_gpr_index(op1->Base);

                        if (baseReg >= 0) {
                            INT64 objectDisp = ss_ud_memory_displacement(op1);

                            if (regState[baseReg].valueType == SS_REG_DRIVER_OBJECT) {
                                regState[dstReg].valueType = SS_REG_DRIVER_OBJECT_ADDRESS;
                                regState[dstReg].value = (ULONG64)objectDisp;
                                continue;
                            } else if (regState[baseReg].valueType == SS_REG_DRIVER_OBJECT_ADDRESS) {
                                INT64 totalDisp = (INT64)regState[baseReg].value + objectDisp;
                                regState[dstReg].valueType = SS_REG_DRIVER_OBJECT_ADDRESS;
                                regState[dstReg].value = (ULONG64)totalDisp;
                                continue;
                            } else if (regState[baseReg].valueType == SS_REG_FRAMEWORK_REGISTRATION) {
                                /* 注册块 -> 注册块内字段地址（偏移进 value） */
                                regState[dstReg].valueType = SS_REG_FRAMEWORK_REGISTRATION_FIELD;
                                regState[dstReg].value = (ULONG64)objectDisp;
                                continue;
                            } else if (regState[baseReg].valueType == SS_REG_FRAMEWORK_REGISTRATION_FIELD) {
                                INT64 fieldDisp = (INT64)regState[baseReg].value + objectDisp;
                                regState[dstReg].valueType = SS_REG_FRAMEWORK_REGISTRATION_FIELD;
                                regState[dstReg].value = (ULONG64)fieldDisp;
                                continue;
                            } else if (regState[baseReg].valueType == SS_REG_IMMEDIATE) {
                                regState[dstReg].valueType = SS_REG_IMMEDIATE;
                                regState[dstReg].value = regState[baseReg].value + objectDisp;

                                if (op0->SIZE == 32) {
                                    regState[dstReg].value &= 0xFFFFFFFFULL;
                                } else if (op0->SIZE != 64) {
                                    ss_clear_reg(&regState[dstReg]);
                                }
                                continue;
                            }
                        }
                    }

                    /* RIP-relative function/image RVA */
                    if (op0->SIZE == 64 && op1 != NULL &&
                        op1->typ == UD_OP_MEM && op1->Base == UD_R_RIP && op1->index == UD_NONE) {

                        INT64 ripDisp = ss_ud_memory_displacement(op1);
                        INT64 target64 = (INT64)insnRva + (INT64)ud_insn_len(&u) + ripDisp;

                        if (target64 > 0 && target64 <= 0xFFFFFFFFLL) {
                            ULONG targetRva = (ULONG)target64;

                            if (ss_rva_to_foa(ctx->pDump, targetRva) != 0) {
                                /* 原实现在可执行/不可执行两个分支都写 ImageAddress */
                                regState[dstReg].valueType = SS_REG_IMAGE_ADDRESS;
                                regState[dstReg].value = targetRva;
                            }
                        }
                    }
                }
            }
            break;

        /* ======================= REP STOSQ ======================= */
        case UD_Istosq:
            if (regState[7].valueType == SS_REG_DRIVER_OBJECT_ADDRESS &&
                (regState[0].valueType == SS_REG_IMAGE_ADDRESS ||
                 regState[0].valueType == SS_REG_STATIC_POINTER) &&
                ss_is_rva_executable(ctx->pDump, (ULONG)regState[0].value) &&
                regState[1].valueType == SS_REG_IMMEDIATE) {

                INT64 startOffset = (INT64)regState[7].value;
                ULONG64 count = regState[1].value;
                ULONG64 functionRva = regState[0].value;

                if (startOffset >= SS_DISPATCH_BASE &&
                    ((startOffset - SS_DISPATCH_BASE) % SS_DISPATCH_STEP) == 0) {

                    INT64 startIndex = (startOffset - SS_DISPATCH_BASE) / SS_DISPATCH_STEP;

                    if (startIndex >= 0 && startIndex <= SS_IRP_MJ_MAXIMUM_FUNCTION) {
                        ULONG64 maxCount = SS_IRP_MJ_MAXIMUM_FUNCTION - startIndex + 1;

                        if (count <= maxCount) {
                            for (INT n = 0; n < (INT)count; n++) {
                                if (emitEffects) {
                                    ss_set_recovered_dispatch(output, (INT)startIndex + n,
                                                              ctx->imageBase,
                                                              (ULONG)functionRva,
                                                              ss_effective_source_name(ctx,
                                                                  SS_SOURCE_NAME_REP_STOSQ));
                                }
                            }
                        }
                    }
                }
            }

            ss_clear_reg(&regState[1]);
            ss_clear_reg(&regState[7]);
            break;

        default:
            ss_invalidate_unknown_instruction_destination(&u, regState);
            break;
        }
    }

    outState->rspDelta = rspDelta;
    outState->rspKnown = rspKnown;
    for (INT i = 0; i < 16; i++) {
        ss_copy_reg(&outState->regState[i], &regState[i]);
    }
    for (INT i = 0; i < 32; i++) {
        outState->stackOffset[i] = stackOffset[i];
        ss_copy_reg(&outState->stackValue[i], &stackValue[i]);
    }
}

/* ==================================================================
 * ScanDispatchFunctionWithArgs
 * ================================================================== */
void ss_scan_dispatch_function_with_args(const SS_SCAN_CONTEXT* ctx, SS_SCAN_STATE* state,
                                         ULONG currentFunctionRva,
                                         const SS_ABSTRACT_STATE* entryState,
                                         INT depth, SS_RECOVERY_OUTPUT* output)
{
    SS_CFG_FUNCTION cfg;
    INT entryIndex;
    INT iterations = 0;
    BOOL anyDirty = TRUE;

    if (ctx->pDump == NULL || ctx->fileSize == 0) {
        return;
    }
    if (currentFunctionRva == 0 || depth > SS_DISPATCH_MAX_CALL_DEPTH) {
        return;
    }
    if (!ss_add_visited_dispatch_function(state, ctx->imageBase, currentFunctionRva, entryState)) {
        return;
    }

    if (!ss_build_dispatch_cfg(ctx, currentFunctionRva, &cfg)) {
        if (cfg.blocks != NULL) {
            HeapFree(GetProcessHeap(), 0, cfg.blocks);
        }
        return;
    }

    entryIndex = ss_find_dispatch_cfg_block(&cfg, currentFunctionRva);
    if (entryIndex < 0) {
        HeapFree(GetProcessHeap(), 0, cfg.blocks);
        return;
    }

    ss_log_ctx(ctx, "ScanDispatchFunction",
               "[CFG-FUNCTION] Module=%s Depth=%d FunctionRVA=0x%X Bounds=0x%X..0x%X",
               ctx->moduleName, depth, currentFunctionRva, cfg.beginRva, cfg.endRva);

    ss_copy_abstract_state(&cfg.blocks[entryIndex].inState, entryState);
    cfg.blocks[entryIndex].hasIn = TRUE;
    cfg.blocks[entryIndex].dirty = TRUE;

    while (anyDirty && iterations < SS_DISPATCH_CFG_MAX_ITERATIONS) {
        anyDirty = FALSE;

        for (INT i = 0; i < cfg.blockCount; i++) {
            SS_CFG_BLOCK* block = &cfg.blocks[i];
            SS_ABSTRACT_STATE nextOut;

            if (!block->dirty || !block->hasIn) {
                continue;
            }

            block->dirty = FALSE;
            iterations += 1;

            memset(&nextOut, 0, sizeof(nextOut));

            ss_execute_dispatch_block(ctx, state, currentFunctionRva, depth,
                                      block, &block->inState, &nextOut, FALSE, output);

            if (!block->hasOut || !ss_abstract_state_equal(&block->outState, &nextOut)) {
                ss_copy_abstract_state(&block->outState, &nextOut);
                block->hasOut = TRUE;

                ss_log_ctx(ctx, "ScanDispatchFunction",
                           "[DF-OUT] Block=0x%X Iteration=%d", block->startRva, iterations);

                for (INT n = 0; n < block->successorCount; n++) {
                    INT successor = ss_find_dispatch_cfg_block(&cfg, block->successorRva[n]);
                    if (successor < 0) {
                        continue;
                    }

                    SS_CFG_BLOCK* nextBlock = &cfg.blocks[successor];

                    if (!nextBlock->hasIn) {
                        ss_copy_abstract_state(&nextBlock->inState, &block->outState);
                        nextBlock->hasIn = TRUE;
                        nextBlock->dirty = TRUE;
                    } else if (ss_join_abstract_state(&nextBlock->inState, &block->outState)) {
                        nextBlock->dirty = TRUE;
                        ss_log_ctx(ctx, "ScanDispatchFunction",
                                   "[DF-JOIN] Into=0x%X From=0x%X",
                                   nextBlock->startRva, block->startRva);
                    }
                }
            }
        }

        for (INT i = 0; i < cfg.blockCount; i++) {
            if (cfg.blocks[i].dirty) {
                anyDirty = TRUE;
            }
        }
    }

    if (anyDirty) {
        ss_log_ctx(ctx, "ScanDispatchFunction", "[DF-LIMIT] FunctionRVA=0x%X", currentFunctionRva);
        HeapFree(GetProcessHeap(), 0, cfg.blocks);
        return;
    }

    /*
     * Re-execute once with stable IN states. Recovery evidence from transient
     * worklist states is never emitted.
     */
    for (INT i = 0; i < cfg.blockCount; i++) {
        SS_CFG_BLOCK* block = &cfg.blocks[i];
        SS_ABSTRACT_STATE finalOut;

        if (!block->hasIn) {
            continue;
        }

        memset(&finalOut, 0, sizeof(finalOut));

        ss_log_ctx(ctx, "ScanDispatchFunction",
                   "[DF-IN] Block=0x%X RAX=%s:0x%llX RCX=%s:0x%llX RDX=%s:0x%llX RBX=%s:0x%llX "
                   "R11=%s:0x%llX RSI=%s RDI=%s",
                   block->startRva,
                   ss_dispatch_state_name(block->inState.regState[0].valueType), block->inState.regState[0].value,
                   ss_dispatch_state_name(block->inState.regState[1].valueType), block->inState.regState[1].value,
                   ss_dispatch_state_name(block->inState.regState[2].valueType), block->inState.regState[2].value,
                   ss_dispatch_state_name(block->inState.regState[3].valueType), block->inState.regState[3].value,
                   ss_dispatch_state_name(block->inState.regState[11].valueType), block->inState.regState[11].value,
                   ss_dispatch_state_name(block->inState.regState[6].valueType),
                   ss_dispatch_state_name(block->inState.regState[7].valueType));

        ss_execute_dispatch_block(ctx, state, currentFunctionRva, depth,
                                  block, &block->inState, &finalOut, TRUE, output);
    }

    ss_log_ctx(ctx, "ScanDispatchFunction",
               "[CFG-FUNCTION-END] Module=%s FunctionRVA=0x%X Blocks=%d Iterations=%d HitCount=%u",
               ctx->moduleName, currentFunctionRva, cfg.blockCount, iterations, output->hitCount);

    HeapFree(GetProcessHeap(), 0, cfg.blocks);
}

/* ==================================================================
 * ScanDispatchFunction
 * ================================================================== */
static void ss_scan_dispatch_function(const SS_SCAN_CONTEXT* ctx, SS_SCAN_STATE* state,
                                      ULONG currentFunctionRva, INT driverObjectArgReg,
                                      INT depth, SS_RECOVERY_OUTPUT* output)
{
    SS_ABSTRACT_STATE entryState;
    memset(&entryState, 0, sizeof(entryState));
    entryState.rspKnown = TRUE;

    if (driverObjectArgReg >= 0 && driverObjectArgReg <= 15) {
        entryState.regState[driverObjectArgReg].valueType = SS_REG_DRIVER_OBJECT;
    }

    ss_scan_dispatch_function_with_args(ctx, state, currentFunctionRva, &entryState, depth, output);
}

/* ==================================================================
 * ScanImportedDispatchCall
 * ================================================================== */
static void ss_scan_imported_dispatch_call(const SS_SCAN_CONTEXT* callerCtx, SS_SCAN_STATE* state,
                                           struct ud* u, const struct ud_operand* callOperand,
                                           const SS_ABSTRACT_STATE* entryState,
                                           INT depth, SS_RECOVERY_OUTPUT* output)
{
    SS_IMPORT_TARGET target;
    SS_SCAN_CONTEXT externalCtx;
    ULONG targetRva = 0;
    WCHAR lowerModule[260];

    INT driverObjectArgReg = ss_find_driver_object_argument_register(entryState->regState);
    BOOL passDriverObject = (driverObjectArgReg >= 0);

    ULONG iatRva = ss_get_rip_relative_operand_rva(u, callOperand);
    if (iatRva == 0) {
        return;
    }

    if (!ss_resolve_import_by_iat_rva(callerCtx->pDump, callerCtx->fileSize, iatRva, &target)) {
        return;
    }

    /*
     * 普通导入函数如果没有 DriverObject 参数，不需要为了它加载外部模块。
     * Framework API 例外：HidRegisterMinidriver 的 RCX 是 PHID_MINIDRIVER_REGISTRATION，
     * 但它会间接改写其中 DriverObject 的派遣表。
     */
    BOOL isHidRegister = FALSE;

    if (!target.byOrdinal) {
        isHidRegister = (_stricmp(target.functionName, "hidregisterminidriver") == 0) &&
                        (_wcsicmp(target.moduleName, L"hidclass.sys") == 0);
    }

    if (!passDriverObject && !isHidRegister) {
        ss_log_ctx(callerCtx, "ScanImportedDispatchCall",
                   "[SKIP] Imported call does not receive DriverObject Caller=%s Function=%s IatRVA=0x%X",
                   callerCtx->moduleName, target.functionName, iatRva);
        return;
    }

    wcscpy_s(lowerModule, 260, target.moduleName);

    if (_wcsicmp(lowerModule, L"ntoskrnl.exe") == 0 ||
        _wcsicmp(lowerModule, L"ntkrnlmp.exe") == 0 ||
        _wcsicmp(lowerModule, L"ntkrnlpa.exe") == 0 ||
        _wcsicmp(lowerModule, L"ntkrpamp.exe") == 0) {

        ss_log_ctx(callerCtx, "ScanImportedDispatchCall",
                   "[IMPORT-SKIP-KERNEL] Function=%s DriverObjectArgReg=%d",
                   target.functionName, driverObjectArgReg);
        return;
    }

    if (!ss_load_dispatch_module_context(callerCtx, target.moduleName, &externalCtx)) {
        return;
    }

    if (!ss_resolve_export_rva(externalCtx.pDump, externalCtx.fileSize,
                               target.functionName, target.ordinal, target.byOrdinal,
                               &targetRva)) {
        return;
    }

    if (!ss_is_rva_executable(externalCtx.pDump, targetRva)) {
        ss_log_ctx(callerCtx, "ScanImportedDispatchCall",
                   "[REJECT] Export is not executable Module=%s Function=%s RVA=0x%X",
                   externalCtx.moduleName, target.functionName, targetRva);
        return;
    }

    ss_log_ctx(callerCtx, "ScanImportedDispatchCall",
               "[IMPORT-CALL] Caller=%s CallRVA=0x%llX IatRVA=0x%X TargetModule=%s Function=%s "
               "TargetRVA=0x%X PassDriverObject=%d",
               callerCtx->moduleName, (ULONG64)ud_insn_off(u), iatRva,
               externalCtx.moduleName, target.functionName, targetRva, (int)passDriverObject);

    /* ---- HID minidriver registration ---- */
    if (isHidRegister) {
        ss_log_ctx(callerCtx, "ScanImportedDispatchCall",
                   "[HID] HidRegisterMinidriver semantic scan Module=%s RVA=0x%X",
                   externalCtx.moduleName, targetRva);

        if (!ss_recover_hid_register_minidriver_dispatch(&externalCtx, targetRva, output)) {
            ss_log_ctx(callerCtx, "ScanImportedDispatchCall",
                       "[HID] HidRegisterMinidriver semantic scan produced no dispatch overrides");
        }
        return;
    }

    /* ---- 普通跨模块 DriverObject 初始化 ---- */
    if (!passDriverObject) {
        return;
    }
    if (depth >= SS_DISPATCH_MAX_CALL_DEPTH) {
        return;
    }

    ss_scan_dispatch_function_with_args(&externalCtx, state, targetRva,
                                        entryState, depth + 1, output);
}

/* ==================================================================
 * RecoverDispatchFromDump
 * ================================================================== */
SS_DISPATCH_STATUS ss_recover_dispatch_from_dump(const SS_SCAN_CONTEXT* ctx, SS_RECOVERY_OUTPUT* output)
{
    ULONG imageEntryRva = 0;
    ULONG entryRva = 0;
    SS_SCAN_STATE* scanState;

    memset(output, 0, sizeof(*output));

    if (ctx->pDump == NULL || ctx->fileSize == 0) {
        return SS_DISPATCH_STATUS_PARSE_FAILED;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)ctx->pDump;
    if (dos->e_magic != 0x5A4D) {
        return SS_DISPATCH_STATUS_PARSE_FAILED;
    }

    if (!ss_get_image_entry_point_rva(ctx->pDump, ctx->fileSize, &imageEntryRva)) {
        return SS_DISPATCH_STATUS_PARSE_FAILED;
    }

    entryRva = ss_resolve_real_driver_entry_rva(ctx, imageEntryRva);
    if (entryRva == 0) {
        return SS_DISPATCH_STATUS_PARSE_FAILED;
    }

    scanState = (SS_SCAN_STATE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SS_SCAN_STATE));
    if (scanState == NULL) {
        return SS_DISPATCH_STATUS_OUT_OF_MEMORY;
    }

    ss_scan_dispatch_function(ctx, scanState, entryRva, 1, 0, output);

    HeapFree(GetProcessHeap(), 0, scanState);

    if (output->hitCount == 0) {
        output->confidence = 0;
        ss_log_ctx(ctx, "RecoverDispatchFromDump",
                   "[Debug] No generic WDM MajorFunction initialization matched");
        return SS_DISPATCH_STATUS_NO_MATCH;
    }

    output->confidence = (output->hitCount >= 20) ? 100 : (output->hitCount * 5);

    ss_log_ctx(ctx, "RecoverDispatchFromDump",
               "[Debug] Finished HitCount=%u Confidence=%u",
               output->hitCount, output->confidence);

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (output->majorFunction[i].valid) {
            output->majorFunction[i].confidence = output->confidence;
        }
    }

    return SS_DISPATCH_STATUS_RECOVERED;
}
