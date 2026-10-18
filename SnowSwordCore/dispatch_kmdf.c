/*
 * dispatch_kmdf.c -- KMDF（Wdf01000）派遣基线后端
 *
 * Phase 3 迁入，严格等价于 ring3/modules/KernelHook/DispatchKmdf.Inc：
 *   - BuildKmdfDispatchBaseline  -> ss_build_kmdf_dispatch_baseline
 *   - IsKmdfBaselineExecutable   -> ss_is_kmdf_baseline_executable
 *   - ApplyKmdfDispatchBaseline  -> SS_BuildKmdfDispatchBaseline（仅纯算法段：
 *                                   build -> PE 校验 -> fallback；不含 IOCTL、
 *                                   文件 IO、ApplyDispatchRecoveryResult 地址映射）
 *
 * 迁移约束：行为等价优先，禁止顺手改算法 / 常量 / tie-break。
 *   - QueryKmdfDriverInfo、Wdf01000 文件读取、ApplyDispatchRecoveryResult
 *     仍留在宿主（方案 A）。
 *   - PE 校验刻意保留独立的有界实现，不得改用 ss_is_rva_executable 等通用 helper。
 */
#include "pch.h"
#include "dispatch_internal.h"

/* SS_KMDF_DRIVER_INFO 经 IOCTL 跨 ring3/ring0 传递，必须维持 40 字节。 */
C_ASSERT(sizeof(SS_KMDF_DRIVER_INFO) == 40);

/* ==================================================================
 * BuildKmdfDispatchBaseline（DispatchKmdf.Inc:5-47）
 * ================================================================== */
BOOL ss_build_kmdf_dispatch_baseline(const SS_KMDF_DRIVER_INFO* info,
                                     ULONG64 wdfBase,
                                     ULONG   wdfSize,
                                     SS_DRIVER_RECOVERY_OUTPUT* baseline)
{
    ULONG64 target;

    memset(baseline, 0, sizeof(*baseline));

    if (info->isKmdf != 1 || info->ownsDispatch != 1) {
        return FALSE;
    }
    if ((info->driverInitFlags & 0x2) != 0) {
        return FALSE;
    }
    if (info->dispatchPolicyKnown != 1) {
        return FALSE;
    }
    if (wdfBase < 0xFFFF800000000000ULL || wdfSize == 0) {
        return FALSE;
    }
    if (wdfBase > 0xFFFFFFFFFFFFFFFFULL - (ULONG64)wdfSize) {
        return FALSE;
    }

    switch (info->dispatchPolicy) {
    case SS_KMDF_POLICY_ALL_DISPATCH:
        target = info->dispatch;
        break;
    case SS_KMDF_POLICY_ALL_DISPATCH_WITH_LOCK:
        target = info->dispatchWithLock;
        break;
    default:
        /* Mixed requires a verified per-slot map; never guess one. */
        return FALSE;
    }

    if (target <= wdfBase) {
        return FALSE;
    }
    if (target - wdfBase >= (ULONG64)wdfSize) {
        return FALSE;
    }

    baseline->modelKind = SS_MODEL_KMDF;
    baseline->modelConfidence = 100;
    baseline->hitCount = SS_DISPATCH_SLOT_COUNT;
    baseline->confidence = 100;

    for (INT i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        SS_FUNCTION_REF* slot = &baseline->majorFunction[i];

        slot->valid = TRUE;
        slot->moduleBase = wdfBase;
        slot->functionRva = (ULONG)(target - wdfBase);
        slot->state = SS_SLOT_RECOVERED;
        slot->ownerKind = SS_OWNER_FRAMEWORK;
        slot->source = SS_SOURCE_FRAMEWORK_BASELINE;
        slot->confidence = 100;
    }

    return TRUE;
}

/* ==================================================================
 * IsKmdfBaselineExecutable（DispatchKmdf.Inc:50-81）
 *
 * Bounds-checked PE validation: do not use the unbounded generic PE helpers here.
 * 节区命中式判定（不是包络式），逐行保留原顺序与比较方向。
 * ================================================================== */
BOOL ss_is_kmdf_baseline_executable(const BYTE* dump,
                                    ULONG fileSize,
                                    ULONG imageSize,
                                    ULONG targetRva)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt;
    ULONG64 ntOffset;
    ULONG64 sectionOffset;
    ULONG   sectionCount;
    const IMAGE_SECTION_HEADER* section;

    if (dump == NULL || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }

    dos = (const IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != 0x5A4D || dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }

    ntOffset = (ULONG64)(ULONG)dos->e_lfanew;
    if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > (ULONG64)fileSize) {
        return FALSE;
    }

    nt = (const IMAGE_NT_HEADERS64*)(dump + ntOffset);
    if (nt->Signature != 0x4550 || nt->FileHeader.Machine != 0x8664) {
        return FALSE;
    }
    if (nt->OptionalHeader.Magic != 0x20B) {
        return FALSE;
    }
    if (nt->OptionalHeader.SizeOfImage != imageSize) {
        return FALSE;
    }
    if (targetRva == 0 || targetRva >= imageSize) {
        return FALSE;
    }
    if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        return FALSE;
    }

    sectionOffset = ntOffset + 4 + sizeof(IMAGE_FILE_HEADER)
                    + nt->FileHeader.SizeOfOptionalHeader;
    sectionCount = nt->FileHeader.NumberOfSections;
    if (sectionCount == 0 || sectionCount > 96) {
        return FALSE;
    }
    if (sectionOffset + (ULONG64)sectionCount * sizeof(IMAGE_SECTION_HEADER)
        > (ULONG64)fileSize) {
        return FALSE;
    }

    section = (const IMAGE_SECTION_HEADER*)(dump + sectionOffset);
    for (ULONG i = 0; i < sectionCount; i++) {
        ULONG span = section[i].Misc.VirtualSize;
        ULONG delta;

        if (span < section[i].SizeOfRawData) {
            span = section[i].SizeOfRawData;
        }
        if (targetRva < section[i].VirtualAddress) {
            continue;
        }
        delta = targetRva - section[i].VirtualAddress;
        if (delta >= span) {
            continue;
        }
        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            return FALSE;
        }
        if (delta >= section[i].SizeOfRawData) {
            return FALSE;
        }
        return (ULONG64)section[i].PointerToRawData + delta < (ULONG64)fileSize;
    }

    return FALSE;
}

/* ==================================================================
 * SS_BuildKmdfDispatchBaseline（公开 API）
 *
 * 复刻 ApplyKmdfDispatchBaseline 的纯算法处置（DispatchKmdf.Inc:141-175）：
 *   OwnsDispatch!=1 / NoDispatchOverride -> SKIP（原实现 Exit Sub）
 *   build + PE 通过                      -> FRAMEWORK_BASELINE
 *   其余（框架拥有但不可验证）           -> FRAMEWORK_OWNED_FALLBACK
 * query 失败不在本函数：宿主 query 不可用时不应调用本 API。
 * ================================================================== */
SS_API SS_DISPATCH_STATUS SS_BuildKmdfDispatchBaseline(
    const SS_KMDF_DRIVER_INFO* info,
    ULONG64 wdfBase,
    ULONG   wdfSize,
    const BYTE* wdfImage,
    ULONG   wdfFileSize,
    ULONG   wdfImageSize,
    SS_KMDF_BASELINE_OUTPUT* out)
{
    SS_DRIVER_RECOVERY_OUTPUT baseline;
    BOOL    available;
    ULONG   targetRva;

    if (out == NULL || info == NULL) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }

    memset(out, 0, sizeof(*out));
    out->modelKind = SS_MODEL_KMDF;

    /* DispatchKmdf.Inc:141 —— 注意这里不检查 IsKmdf（与 BuildKmdfDispatchBaseline
     * 入口的完整校验不同），严格保留原顺序。 */
    if (info->ownsDispatch != 1 || (info->driverInitFlags & 0x2) != 0) {
        out->disposition = SS_KMDF_SKIP;
        return SS_DISPATCH_STATUS_RECOVERED;
    }

    available = ss_build_kmdf_dispatch_baseline(info, wdfBase, wdfSize, &baseline);
    targetRva = available ? baseline.majorFunction[0].functionRva : 0;
    out->targetRva = targetRva;

    /* 原 VB：仅当 build 接受时才 ValidateKmdfBaselineImage。
     * wdfImage == NULL 表示宿主无法提供镜像（读文件失败），等价于 imageOk=false。 */
    if (available) {
        if (wdfImage != NULL) {
            available = ss_is_kmdf_baseline_executable(wdfImage, wdfFileSize,
                                                       wdfImageSize, targetRva);
        } else {
            available = FALSE;
        }
    }

    if (!available) {
        /* Do not expose pre-WdfDriverCreate generic stores as framework originals.
         * DispatchKmdf.Inc:163-169：memset 后仅设 modelKind 与 28 槽 owned 三元组，
         * Valid/ModuleBase/Rva/Confidence 全部保持 0。 */
        out->disposition = SS_KMDF_FRAMEWORK_OWNED_FALLBACK;
        for (INT i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
            out->slots[i].irpIndex = (ULONG)i;
            out->slots[i].state = SS_SLOT_FRAMEWORK_OWNED;
            out->slots[i].ownerKind = SS_OWNER_FRAMEWORK;
            out->slots[i].source = SS_SOURCE_FRAMEWORK_CLASSIFY;
        }
        return SS_DISPATCH_STATUS_RECOVERED;
    }

    out->disposition = SS_KMDF_FRAMEWORK_BASELINE;
    out->modelConfidence = baseline.modelConfidence;
    out->hitCount = baseline.hitCount;
    out->confidence = baseline.confidence;
    for (INT i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        const SS_FUNCTION_REF* src = &baseline.majorFunction[i];
        SS_DISPATCH_SLOT* dst = &out->slots[i];

        dst->irpIndex = (ULONG)i;
        dst->valid = src->valid;
        dst->moduleBase = src->moduleBase;
        dst->functionRva = src->functionRva;
        dst->state = src->state;
        dst->ownerKind = src->ownerKind;
        dst->source = src->source;
        dst->confidence = src->confidence;
    }

    return SS_DISPATCH_STATUS_RECOVERED;
}
