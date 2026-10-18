/*
 * dispatch_disasm.c -- 反汇编辅助与函数入口解析
 *
 * 逐行等价移植自 ring3/modules/KernelHook/DispatchDisasm.inc。
 * 引擎为 udis86，直接链接仓库内既有的 MSVC 静态库 libudis86.lib，
 * 以保证与 FreeBASIC 版本指令解码行为一致。
 */
#include "pch.h"
#include "third_party/udis86/udis86.h"
#include "dispatch_internal.h"

/* ------------------------------------------------------------------
 * 日志辅助（VB: MyLog.PrintInfo）
 * ------------------------------------------------------------------ */
void ss_log_ctx(const SS_SCAN_CONTEXT* ctx, const char* functionName, const char* format, ...)
{
    char message[1024];
    va_list args;

    if (ctx == NULL || ctx->logSink == NULL) {
        return;
    }

    va_start(args, format);
    _vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    message[sizeof(message) - 1] = '\0';

    ctx->logSink(ctx->logContext, functionName, message);
}

/* ------------------------------------------------------------------
 * 寄存器/状态名（诊断用）
 * ------------------------------------------------------------------ */
const char* ss_dispatch_reg_name(INT regIndex)
{
    static const char* names[16] = {
        "RAX", "RCX", "RDX", "RBX",
        "RSP", "RBP", "RSI", "RDI",
        "R8",  "R9",  "R10", "R11",
        "R12", "R13", "R14", "R15"
    };

    if (regIndex < 0 || regIndex > 15) {
        return "?";
    }
    return names[regIndex];
}

const char* ss_dispatch_state_name(INT valueType)
{
    switch (valueType) {
    case SS_REG_DRIVER_OBJECT:          return "DriverObject";
    case SS_REG_FUNCTION_RVA:           return "FunctionRva";
    case SS_REG_IMAGE_RVA:              return "ImageRva";
    case SS_REG_IMMEDIATE:              return "Immediate";
    case SS_REG_DRIVER_OBJECT_ADDRESS:  return "DriverObjectAddress";
    case SS_REG_IMAGE_ADDRESS:          return "ImageAddress";
    case SS_REG_STATIC_POINTER:         return "StaticPointer";
    case SS_REG_OBJECT_POINTER:         return "ObjectPointer";
    default: break;
    }
    return "Unknown";
}

/* ------------------------------------------------------------------
 * 原 UdRegToGprIndex
 * ------------------------------------------------------------------ */
INT ss_ud_reg_to_gpr_index(int udRegType)
{
    switch (udRegType) {
    case UD_R_RAX: case UD_R_EAX: case UD_R_AX: case UD_R_AL: case UD_R_AH: return 0;
    case UD_R_RCX: case UD_R_ECX: case UD_R_CX: case UD_R_CL: case UD_R_CH: return 1;
    case UD_R_RDX: case UD_R_EDX: case UD_R_DX: case UD_R_DL: case UD_R_DH: return 2;
    case UD_R_RBX: case UD_R_EBX: case UD_R_BX: case UD_R_BL: case UD_R_BH: return 3;
    case UD_R_RSP: case UD_R_ESP: case UD_R_SP: case UD_R_SPL:            return 4;
    case UD_R_RBP: case UD_R_EBP: case UD_R_BP: case UD_R_BPL:            return 5;
    case UD_R_RSI: case UD_R_ESI: case UD_R_SI: case UD_R_SIL:            return 6;
    case UD_R_RDI: case UD_R_EDI: case UD_R_DI: case UD_R_DIL:            return 7;
    case UD_R_R8:  case UD_R_R8D:  case UD_R_R8W:  case UD_R_R8B:         return 8;
    case UD_R_R9:  case UD_R_R9D:  case UD_R_R9W:  case UD_R_R9B:         return 9;
    case UD_R_R10: case UD_R_R10D: case UD_R_R10W: case UD_R_R10B:        return 10;
    case UD_R_R11: case UD_R_R11D: case UD_R_R11W: case UD_R_R11B:        return 11;
    case UD_R_R12: case UD_R_R12D: case UD_R_R12W: case UD_R_R12B:        return 12;
    case UD_R_R13: case UD_R_R13D: case UD_R_R13W: case UD_R_R13B:        return 13;
    case UD_R_R14: case UD_R_R14D: case UD_R_R14W: case UD_R_R14B:        return 14;
    case UD_R_R15: case UD_R_R15D: case UD_R_R15W: case UD_R_R15B:        return 15;
    default: break;
    }
    return -1;
}

BOOL ss_ud_is_64bit_gpr(const struct ud_operand* opr)
{
    if (opr == NULL || opr->typ != UD_OP_REG || opr->SIZE != 64) {
        return FALSE;
    }
    return ss_ud_reg_to_gpr_index(opr->Base) >= 0;
}

/* ------------------------------------------------------------------
 * 原 UdSignedValue
 * ------------------------------------------------------------------ */
INT64 ss_ud_signed_value(const union ud_lval* value, INT bits)
{
    switch (bits) {
    case 8: {
        int8_t v8;
        memcpy(&v8, &value->UByte, 1);
        return (INT64)v8;
    }
    case 16: {
        int16_t v16;
        memcpy(&v16, &value->UWORD, 2);
        return (INT64)v16;
    }
    case 32: {
        int32_t v32;
        memcpy(&v32, &value->udword, 4);
        return (INT64)v32;
    }
    case 64:
        return value->sqword;
    default:
        break;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * 原 UdMemoryDisplacement
 * ------------------------------------------------------------------ */
INT64 ss_ud_memory_displacement(const struct ud_operand* opr)
{
    if (opr == NULL || opr->typ != UD_OP_MEM) {
        return 0;
    }

    /* x64 RIP-relative memory operand 使用 signed disp32 */
    if (opr->Base == UD_R_RIP) {
        return (INT64)opr->lval.sdword;
    }

    switch (opr->offset) {
    case 0:  return 0;
    case 8:  return (INT64)opr->lval.sbyte;
    case 16: return (INT64)opr->lval.sword;
    case 32: return (INT64)opr->lval.sdword;
    case 64: return opr->lval.sqword;
    default: break;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * 原 UdRelativeTargetRva
 * ------------------------------------------------------------------ */
ULONG ss_ud_relative_target_rva(struct ud* u, const struct ud_operand* opr)
{
    INT64 rel;

    if (u == NULL || opr == NULL || opr->typ != UD_OP_JIMM) {
        return 0;
    }

    switch (opr->SIZE) {
    case 8:  rel = (INT64)opr->lval.sbyte; break;
    case 16: rel = (INT64)opr->lval.sword; break;
    case 32: rel = (INT64)opr->lval.sdword; break;
    case 64: rel = opr->lval.sqword; break;
    default: return 0;
    }

    INT64 target = (INT64)ud_insn_off(u) + (INT64)ud_insn_len(u) + rel;

    if (target <= 0 || target > 0xFFFFFFFFLL) {
        return 0;
    }

    return (ULONG)target;
}

/* ------------------------------------------------------------------
 * 原 UdMnemonicWritesOp0
 * ------------------------------------------------------------------ */
BOOL ss_ud_mnemonic_writes_op0(int mnemonic)
{
    switch (mnemonic) {
    case UD_Iadd:
    case UD_Iadc:
    case UD_Isub:
    case UD_Isbb:
    case UD_Iand:
    case UD_Ior:
    case UD_Ixor:
    case UD_Iimul:
    case UD_Iinc:
    case UD_Idec:
    case UD_Ineg:
    case UD_Inot:
    case UD_Ishl:
    case UD_Ishr:
    case UD_Isar:
    case UD_Irol:
    case UD_Iror:
    case UD_Ircl:
    case UD_Ircr:
    case UD_Ipop:
    case UD_Imovsx:
    case UD_Imovsxd:
    case UD_Imovzx:
    case UD_Ibswap:
    case UD_Ixchg:
    case UD_Ixadd:
        return TRUE;
    default:
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 GetRipRelativeOperandRva
 * ------------------------------------------------------------------ */
ULONG ss_get_rip_relative_operand_rva(struct ud* u, const struct ud_operand* opr)
{
    if (u == NULL || opr == NULL) {
        return 0;
    }
    if (opr->typ != UD_OP_MEM) {
        return 0;
    }
    if (opr->Base != UD_R_RIP) {
        return 0;
    }
    if (opr->index != UD_NONE) {
        return 0;
    }

    INT64 disp = ss_ud_memory_displacement(opr);
    INT64 target64 = (INT64)ud_insn_off(u) + (INT64)ud_insn_len(u) + disp;

    if (target64 <= 0 || target64 > 0xFFFFFFFFLL) {
        return 0;
    }

    return (ULONG)target64;
}

/* ------------------------------------------------------------------
 * 状态操作
 * ------------------------------------------------------------------ */
void ss_clear_reg(SS_REG_STATE* regState)
{
    regState->valueType = SS_REG_UNKNOWN;
    regState->value = 0;
}

void ss_copy_reg(SS_REG_STATE* dst, const SS_REG_STATE* src)
{
    dst->valueType = src->valueType;
    dst->value = src->value;
}

void ss_invalidate_volatile_regs(SS_REG_STATE* regState)
{
    ss_clear_reg(&regState[0]);
    ss_clear_reg(&regState[1]);
    ss_clear_reg(&regState[2]);
    ss_clear_reg(&regState[8]);
    ss_clear_reg(&regState[9]);
    ss_clear_reg(&regState[10]);
    ss_clear_reg(&regState[11]);
}

void ss_invalidate_unknown_instruction_destination(struct ud* u, SS_REG_STATE* regState)
{
    if (u == NULL) {
        return;
    }

    int mnemonic = (int)ud_insn_mnemonic(u);
    if (!ss_ud_mnemonic_writes_op0(mnemonic)) {
        return;
    }

    const struct ud_operand* op0 = ud_insn_opr(u, 0);
    if (op0 == NULL || op0->typ != UD_OP_REG) {
        return;
    }

    INT regIndex = ss_ud_reg_to_gpr_index(op0->Base);
    if (regIndex >= 0) {
        ss_clear_reg(&regState[regIndex]);
    }
}

/* ------------------------------------------------------------------
 * 原 FindDriverObjectArgumentRegister
 * ------------------------------------------------------------------ */
INT ss_find_driver_object_argument_register(const SS_REG_STATE* regState)
{
    if (regState[1].valueType == SS_REG_DRIVER_OBJECT) return 1;   /* RCX */
    if (regState[2].valueType == SS_REG_DRIVER_OBJECT) return 2;   /* RDX */
    if (regState[8].valueType == SS_REG_DRIVER_OBJECT) return 8;   /* R8  */
    if (regState[9].valueType == SS_REG_DRIVER_OBJECT) return 9;   /* R9  */
    return -1;
}

/* ------------------------------------------------------------------
 * 已访问函数集合
 * ------------------------------------------------------------------ */
BOOL ss_dispatch_function_visited(const SS_SCAN_STATE* state, ULONG64 moduleBase, ULONG functionRva)
{
    if (state->visitedCount == 0) {
        return FALSE;
    }

    for (INT i = 0; i < state->visitedCount; i++) {
        if (state->visited[i].moduleBase == moduleBase &&
            state->visited[i].functionRva == functionRva) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL ss_add_visited_reachable_function(SS_SCAN_STATE* state,
                                       ULONG64 moduleBase, ULONG functionRva)
{
    for (INT i = 0; i < state->reachableVisitedCount; i++) {
        if (state->reachableVisited[i].moduleBase == moduleBase &&
            state->reachableVisited[i].functionRva == functionRva) {
            return FALSE;
        }
    }

    if (state->reachableVisitedCount >= SS_DISPATCH_MAX_VISITED) {
        return FALSE;
    }

    state->reachableVisited[state->reachableVisitedCount].moduleBase = moduleBase;
    state->reachableVisited[state->reachableVisitedCount].functionRva = functionRva;
    state->reachableVisitedCount += 1;

    return TRUE;
}

BOOL ss_add_visited_dispatch_function(SS_SCAN_STATE* state, ULONG64 moduleBase,
                                      ULONG functionRva, const SS_ABSTRACT_STATE* entryState)
{
    static const INT argReg[4] = { 1, 2, 8, 9 };

    for (INT i = 0; i < state->visitedCount; i++) {
        if (state->visited[i].moduleBase != moduleBase ||
            state->visited[i].functionRva != functionRva) {
            continue;
        }
        BOOL same = TRUE;
        for (INT n = 0; n < 4; n++) {
            if (state->visited[i].entryArg[n].valueType != entryState->regState[argReg[n]].valueType ||
                state->visited[i].entryArg[n].value != entryState->regState[argReg[n]].value) {
                same = FALSE;
            }
        }
        if (same) {
            return FALSE;
        }
    }

    if (state->visitedCount >= SS_DISPATCH_MAX_VISITED) {
        return FALSE;
    }

    INT index = state->visitedCount;
    state->visited[index].moduleBase = moduleBase;
    state->visited[index].functionRva = functionRva;
    for (INT n = 0; n < 4; n++) {
        ss_copy_reg(&state->visited[index].entryArg[n], &entryState->regState[argReg[n]]);
    }
    state->visitedCount += 1;

    return TRUE;
}

/* ------------------------------------------------------------------
 * 原 IsTailForwardCall
 * ------------------------------------------------------------------ */
static BOOL ss_is_tail_forward_call(const BYTE* pDump, ULONG64 fileSize, ULONG64 callFoa)
{
    const ULONG64 MAX_TAIL_DISTANCE = 0x30;

    if (pDump == NULL || callFoa >= fileSize) {
        return FALSE;
    }

    ULONG64 callRva = ss_foa_to_rva(pDump, callFoa);
    if (callRva == 0) {
        return FALSE;
    }

    ULONG64 available = MAX_TAIL_DISTANCE;
    if (callFoa + available > fileSize) {
        available = fileSize - callFoa;
    }

    struct ud u;
    ud_init(&u);
    ud_set_mode(&u, 64);
    ud_set_pc(&u, callRva);
    ud_set_input_buffer(&u, pDump + callFoa, (size_t)available);

    /* 第一条应该是候选 CALL 本身 */
    if (ud_decode(&u) == 0) {
        return FALSE;
    }
    if (ud_insn_mnemonic(&u) != UD_Icall) {
        return FALSE;
    }

    while (ud_decode(&u) != 0) {
        switch (ud_insn_mnemonic(&u)) {
        case UD_Iret:
        case UD_Iretf:
            return TRUE;
        case UD_Icall:
            /* 后面又发生 CALL，就不是简单 tail forwarding */
            return FALSE;
        default:
            break;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 FindForwardedDriverEntryRVA
 * ------------------------------------------------------------------ */
static ULONG ss_find_forwarded_driver_entry_rva(const SS_SCAN_CONTEXT* ctx, ULONG funcRva)
{
    const ULONG64 FUNCTION_SCAN_SIZE = 0x600;
    #define SS_MAX_FORWARD_CANDIDATES 16

    ULONG64 funcFoa = ss_rva_to_foa(ctx->pDump, funcRva);
    if (funcFoa == 0 || funcFoa >= ctx->fileSize) {
        return 0;
    }

    ULONG64 scanSize = FUNCTION_SCAN_SIZE;
    if (funcFoa + scanSize > ctx->fileSize) {
        scanSize = ctx->fileSize - funcFoa;
    }

    struct ud u;
    ud_init(&u);
    ud_set_mode(&u, 64);
    ud_set_pc(&u, funcRva);
    ud_set_input_buffer(&u, ctx->pDump + funcFoa, (size_t)scanSize);

    INT regValue[16];
    memset(regValue, 0, sizeof(regValue));
    regValue[1] = SS_ENTRY_REG_DRIVER_OBJECT;
    regValue[2] = SS_ENTRY_REG_REGISTRY_PATH;

    ULONG candidateTarget[SS_MAX_FORWARD_CANDIDATES];
    ULONG candidateCallRva[SS_MAX_FORWARD_CANDIDATES];
    INT candidateCount = 0;

    while (ud_decode(&u) != 0) {
        int mnemonic = (int)ud_insn_mnemonic(&u);
        const struct ud_operand* op0 = ud_insn_opr(&u, 0);
        const struct ud_operand* op1 = ud_insn_opr(&u, 1);

        switch (mnemonic) {
        case UD_Imov:
            if (ss_ud_is_64bit_gpr(op0)) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                if (ss_ud_is_64bit_gpr(op1)) {
                    INT src = ss_ud_reg_to_gpr_index(op1->Base);
                    regValue[dst] = regValue[src];
                } else {
                    regValue[dst] = SS_ENTRY_REG_UNKNOWN;
                }
            }
            break;

        case UD_Ilea:
            if (op0 != NULL && op0->typ == UD_OP_REG) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                if (dst >= 0) {
                    regValue[dst] = SS_ENTRY_REG_UNKNOWN;
                }
            }
            break;

        case UD_Ijmp:
            if (op0 != NULL && op0->typ == UD_OP_JIMM) {
                ULONG jumpTarget = ss_ud_relative_target_rva(&u, op0);

                if (jumpTarget != 0 && jumpTarget != funcRva &&
                    regValue[1] == SS_ENTRY_REG_DRIVER_OBJECT &&
                    regValue[2] == SS_ENTRY_REG_REGISTRY_PATH &&
                    ss_is_rva_executable(ctx->pDump, jumpTarget)) {
                    return jumpTarget;
                }
            }
            break;

        case UD_Icall: {
            ULONG callTarget = ss_ud_relative_target_rva(&u, op0);
            ULONG callRva = (ULONG)ud_insn_off(&u);

            if (callTarget != 0 && callTarget != funcRva &&
                ss_rva_to_foa(ctx->pDump, callTarget) != 0 &&
                regValue[1] == SS_ENTRY_REG_DRIVER_OBJECT &&
                regValue[2] == SS_ENTRY_REG_REGISTRY_PATH) {

                if (candidateCount < SS_MAX_FORWARD_CANDIDATES) {
                    candidateTarget[candidateCount] = callTarget;
                    candidateCallRva[candidateCount] = callRva;

                    ss_log_ctx(ctx, "FindForwardedDriverEntryRVA",
                               "[Debug] Candidate#%d CallRVA=0x%X TargetRVA=0x%X",
                               candidateCount, callRva, callTarget);

                    candidateCount += 1;
                }
            }

            regValue[0] = SS_ENTRY_REG_UNKNOWN;
            regValue[1] = SS_ENTRY_REG_UNKNOWN;
            regValue[2] = SS_ENTRY_REG_UNKNOWN;
            regValue[8] = SS_ENTRY_REG_UNKNOWN;
            regValue[9] = SS_ENTRY_REG_UNKNOWN;
            regValue[10] = SS_ENTRY_REG_UNKNOWN;
            regValue[11] = SS_ENTRY_REG_UNKNOWN;
            break;
        }

        case UD_Iret:
        case UD_Iretf:
            goto scan_done;

        default:
            if (ss_ud_mnemonic_writes_op0(mnemonic) && op0 != NULL && op0->typ == UD_OP_REG) {
                INT dst = ss_ud_reg_to_gpr_index(op0->Base);
                if (dst >= 0) {
                    regValue[dst] = SS_ENTRY_REG_UNKNOWN;
                }
            }
            break;
        }
    }

scan_done:
    if (candidateCount == 0) {
        ss_log_ctx(ctx, "FindForwardedDriverEntryRVA", "[Debug] No forwarding candidates");
        return 0;
    }

    /* 1. 优先选择真正的 tail-forward：call candidate ... ret；从后往前找 */
    for (INT i = candidateCount - 1; i >= 0; i--) {
        ULONG64 callFoa = ss_rva_to_foa(ctx->pDump, candidateCallRva[i]);

        if (callFoa != 0 && ss_is_tail_forward_call(ctx->pDump, ctx->fileSize, callFoa)) {
            ss_log_ctx(ctx, "FindForwardedDriverEntryRVA",
                       "[Debug] Accept tail forwarding Candidate#%d CallRVA=0x%X TargetRVA=0x%X",
                       i, candidateCallRva[i], candidateTarget[i]);
            return candidateTarget[i];
        }
    }

    /* 2. 所有候选指向同一个目标 */
    BOOL sameTarget = TRUE;
    for (INT i = 1; i < candidateCount; i++) {
        if (candidateTarget[i] != candidateTarget[0]) {
            sameTarget = FALSE;
            break;
        }
    }

    if (candidateCount >= 2 && sameTarget) {
        ss_log_ctx(ctx, "FindForwardedDriverEntryRVA",
                   "[Debug] Accept common forwarding target Count=%d RVA=0x%X",
                   candidateCount, candidateTarget[0]);
        return candidateTarget[0];
    }

    /* 3. 多个不同 target 且无明确 tail-forward：返回 0，避免假阳性 */
    if (candidateCount == 1) {
        ss_log_ctx(ctx, "FindForwardedDriverEntryRVA",
                   "[Debug] Single candidate rejected: function is not a forwarding wrapper"
                   " CallRVA=0x%X TargetRVA=0x%X",
                   candidateCallRva[0], candidateTarget[0]);
    } else {
        ss_log_ctx(ctx, "FindForwardedDriverEntryRVA",
                   "[Debug] Ambiguous forwarding candidates Count=%d", candidateCount);
    }

    for (INT i = 0; i < candidateCount; i++) {
        ss_log_ctx(ctx, "FindForwardedDriverEntryRVA",
                   "[Debug] Candidate#%d CallRVA=0x%X TargetRVA=0x%X",
                   i, candidateCallRva[i], candidateTarget[i]);
    }

    return 0;
}

/* ------------------------------------------------------------------
 * 原 FindDirectEntryTailJumpRVA
 * ------------------------------------------------------------------ */
static ULONG ss_find_direct_entry_tail_jump_rva(const SS_SCAN_CONTEXT* ctx, ULONG entryRva)
{
    if (ctx->pDump == NULL || ctx->fileSize == 0 || entryRva == 0) {
        return 0;
    }

    ULONG64 foa = ss_rva_to_foa(ctx->pDump, entryRva);
    if (foa == 0 || foa >= ctx->fileSize) {
        return 0;
    }

    ULONG64 scanSize = SS_DISPATCH_ENTRY_THUNK_SCAN_RANGE;
    if (foa + scanSize > ctx->fileSize) {
        scanSize = ctx->fileSize - foa;
    }
    if (scanSize == 0) {
        return 0;
    }

    struct ud u;
    ud_init(&u);
    ud_set_mode(&u, 64);
    ud_set_pc(&u, entryRva);
    ud_set_input_buffer(&u, ctx->pDump + foa, (size_t)scanSize);

    while (ud_decode(&u) != 0) {
        int mnemonic = (int)ud_insn_mnemonic(&u);
        const struct ud_operand* op0 = ud_insn_opr(&u, 0);

        if (mnemonic == UD_Iret || mnemonic == UD_Iretf) {
            break;
        }

        if (mnemonic == UD_Ijmp && op0 != NULL && op0->typ == UD_OP_JIMM) {
            ULONG targetRva = ss_ud_relative_target_rva(&u, op0);

            if (targetRva != 0 && targetRva != entryRva &&
                ss_rva_to_foa(ctx->pDump, targetRva) != 0 &&
                ss_is_rva_executable(ctx->pDump, targetRva)) {

                BOOL targetInsideThunk =
                    (targetRva >= entryRva && targetRva < entryRva + (ULONG)scanSize);

                if (!targetInsideThunk) {
                    ss_log_ctx(ctx, "FindDirectEntryTailJumpRVA",
                               "[ENTRY-TAILJMP] EntryRVA=0x%X JmpRVA=0x%llX TargetRVA=0x%X",
                               entryRva, (ULONG64)ud_insn_off(&u), targetRva);
                    return targetRva;
                }
            }

            break;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------
 * 原 ResolveRealDriverEntryRVA
 * ------------------------------------------------------------------ */
ULONG ss_resolve_real_driver_entry_rva(const SS_SCAN_CONTEXT* ctx, ULONG imageEntryRva)
{
    if (ctx->pDump == NULL || ctx->fileSize == 0 || imageEntryRva == 0) {
        return 0;
    }

    ss_log_ctx(ctx, "ResolveRealDriverEntryRVA", "[Debug] Begin ImageEntryRVA=0x%X", imageEntryRva);

    ULONG currentRva = imageEntryRva;

    for (INT depth = 0; depth <= SS_DISPATCH_MAX_CALL_DEPTH; depth++) {
        ss_log_ctx(ctx, "ResolveRealDriverEntryRVA",
                   "[Debug] Depth=%d CurrentRVA=0x%X", depth, currentRva);

        ULONG nextRva = 0;

        /* 只在最外层 image entry 检查函数外 tail-jump */
        if (depth == 0) {
            nextRva = ss_find_direct_entry_tail_jump_rva(ctx, currentRva);
        }

        if (nextRva == 0) {
            nextRva = ss_find_forwarded_driver_entry_rva(ctx, currentRva);
        }

        ss_log_ctx(ctx, "ResolveRealDriverEntryRVA",
                   "[Debug] Depth=%d CurrentRVA=0x%X NextRVA=0x%X", depth, currentRva, nextRva);

        if (nextRva == 0 || nextRva == currentRva) {
            ss_log_ctx(ctx, "ResolveRealDriverEntryRVA",
                       "[Debug] No forwarding target, stop at RVA=0x%X", currentRva);
            break;
        }

        currentRva = nextRva;
    }

    ss_log_ctx(ctx, "ResolveRealDriverEntryRVA",
               "[Debug] Final RealDriverEntryRVA=0x%X", currentRva);

    return currentRva;
}
