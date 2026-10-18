/*
 * dispatch_orchestrator.c -- 派遣恢复编排
 *
 * 逐行等价移植自 ring3/modules/KernelHook/DispatchOrchestrator.inc 中
 * Generic WDM 路径。
 *
 * 本阶段范围（第一阶段）：
 *   - MergeGenericDispatchResult / FinalizeDispatchRecovery / 默认语义补齐：已移植
 *   - ClassifyDriverDispatchModel：DetectWddmDriver（DispatchWddm.inc）未移植，
 *     因此模型分类恒为 GenericWdm、ModelConfidence=30（与原实现"非 WDDM"分支一致）
 *   - WDDM / FrameworkWdm / KMDF 后端：未移植，见文件末尾「已知缺口」
 */
#include "pch.h"
#include "dispatch_internal.h"

/* ==================================================================
 * MergeGenericDispatchResult
 * ================================================================== */
static void ss_merge_generic_dispatch_result(SS_DRIVER_RECOVERY_OUTPUT* out,
                                             const SS_RECOVERY_OUTPUT* generic)
{
    out->fastIoDispatchRva = generic->fastIoDispatchRva;

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (generic->majorFunction[i].valid) {
            out->majorFunction[i].valid = TRUE;
            out->majorFunction[i].moduleBase = generic->majorFunction[i].moduleBase;
            out->majorFunction[i].functionRva = generic->majorFunction[i].functionRva;
            out->majorFunction[i].state = SS_SLOT_RECOVERED;
            out->majorFunction[i].ownerKind = SS_OWNER_DRIVER;
            /*
             * Source 不再硬编码为 DirectStore：Generic 层已经按语义分好类
             * （DirectStore / RepStosq / ImportedFramework=HID 框架注册覆盖），
             * 丢弃它会让「这个槽是驱动自己写的还是框架接管的」在 API 层不可见。
             * 与原 VB 实现（DispatchOrchestrator.inc.pre-phase21:168 硬写
             * DispatchSourceDirectStore）的唯一差异就是这个字段；地址判定
             * （ModuleBase / FunctionRva / State / OwnerKind）逐行不变，
             * 且 Core/ring3 中唯一按 Source 分支的地方只认 FrameworkBaseline。
             */
            out->majorFunction[i].source = generic->majorFunction[i].source;
            out->majorFunction[i].confidence = generic->confidence;

            out->hitCount += 1;
        }
    }
}

/* ==================================================================
 * FinalizeDispatchRecovery（仅统计与日志）
 * ================================================================== */
static void ss_finalize_dispatch_recovery(const SS_RECOVERY_CONTEXT* ctx,
                                          const SS_DRIVER_RECOVERY_OUTPUT* out)
{
    ULONG recoveredCount = 0;
    ULONG frameworkBaselineCount = 0;
    ULONG frameworkOwnedCount = 0;
    ULONG defaultCount = 0;
    ULONG unresolvedCount = 0;

    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        switch (out->majorFunction[i].state) {
        case SS_SLOT_RECOVERED:
            recoveredCount += 1;
            if (out->majorFunction[i].source == SS_SOURCE_FRAMEWORK_BASELINE) {
                frameworkBaselineCount += 1;
            }
            break;
        case SS_SLOT_FRAMEWORK_OWNED:
            frameworkOwnedCount += 1;
            break;
        case SS_SLOT_DEFAULT:
            defaultCount += 1;
            break;
        default:
            unresolvedCount += 1;
            break;
        }
    }

    if (ctx->logSink != NULL) {
        char message[256];
        _snprintf(message, sizeof(message),
                    "[FINALIZE] Model=%d FrameworkKind=%d Recovered=%u FrameworkBaseline=%u "
                    "FrameworkOwned=%u Default=%u Unresolved=%u ModelConfidence=%u",
                    out->modelKind, out->frameworkKind, recoveredCount, frameworkBaselineCount,
                    frameworkOwnedCount, defaultCount, unresolvedCount, out->modelConfidence);
        ctx->logSink(ctx->logContext, "FinalizeDispatchRecovery", message);
    }
}

/* ==================================================================
 * RecoverHidRegisterMinidriverDispatch 见 dispatch_hid.c
 *
 * 该函数由 Generic 扫描器在识别到
 *   hidclass.sys!HidRegisterMinidriver
 * 导入调用时调用（dispatch_generic.c 的 ScanImportedDispatchCall）。此前这里是
 * 显式 NOT-IMPLEMENTED 占位，现已移植为真实语义恢复。
 * ================================================================== */

/* ==================================================================
 * RecoverDriverDispatch
 * ================================================================== */
SS_DISPATCH_STATUS ss_recover_driver_dispatch(SS_RECOVERY_CONTEXT* context,
                                              SS_DRIVER_RECOVERY_OUTPUT* output)
{
    SS_SCAN_CONTEXT scanCtx;
    SS_RECOVERY_OUTPUT genericOutput;
    SS_DISPATCH_STATUS genericStatus;
    ULONG totalResolved = 0;

    memset(output, 0, sizeof(*output));
    output->modelKind = SS_MODEL_UNKNOWN;
    output->frameworkKind = SS_FRAMEWORK_NONE;
    output->modelConfidence = 0;

    /* 分类结果在 VB 里落在 Context 上；这里同样清零，避免读到宿主的残留值。 */
    context->modelKind = SS_MODEL_UNKNOWN;
    context->frameworkKind = SS_FRAMEWORK_NONE;
    context->modelConfidence = 0;
    memset(&context->modelInfo, 0, sizeof(context->modelInfo));

    /* ---- 1. 组装扫描上下文（原 BuildDriverDispatchRecoveryContext） ---- */
    memset(&scanCtx, 0, sizeof(scanCtx));
    scanCtx.pDump = context->pDump;
    scanCtx.fileSize = context->fileSize;
    scanCtx.imageBase = context->imageBase;
    /* imageSize 供 WDDM baseline 的 IsAddressInModule 等价判定使用；
     * 宿主未提供时退化为 0（判定将保守失败，不会放宽）。 */
    scanCtx.imageSize = context->imageSize;
    wcscpy_s(scanCtx.moduleName, SS_MODULE_NAME_MAX, context->moduleName);
    scanCtx.loadModule = context->loadModule;
    scanCtx.loadModuleContext = context->loadModuleContext;
    scanCtx.logSink = context->logSink;
    scanCtx.logContext = context->logContext;

    /* ---- 2. 永远先跑 Generic WDM backend ---- */
    memset(&genericOutput, 0, sizeof(genericOutput));
    genericStatus = ss_recover_dispatch_from_dump(&scanCtx, &genericOutput);

    if (genericStatus == SS_DISPATCH_STATUS_PARSE_FAILED) {
        ss_log_ctx(&scanCtx, "RecoverDriverDispatch", "[ORCH] Generic WDM backend parse failed");
        return SS_DISPATCH_STATUS_PARSE_FAILED;
    }
    if (genericStatus == SS_DISPATCH_STATUS_OUT_OF_MEMORY) {
        return SS_DISPATCH_STATUS_OUT_OF_MEMORY;
    }

    /* ---- 3. 合并 Generic 结果 ---- */
    ss_merge_generic_dispatch_result(output, &genericOutput);

    /*
     * ---- 4. 分类驱动模型 ----
     *
     * ClassifyDriverDispatchModel -> DetectWddmDriver（dispatch_wddm.c）。
     * 默认 GenericWdm / FrameworkNone / 30；判为 WDDM 时写 WDDM 与检测置信度。
     *
     * 写回 context->modelKind / modelInfo：原实现（VB）的分类结果就落在
     * recoveryContext 上，RecoverDxgkrnlDispatchBaseline 随后以
     * Context.ModelKind / Context.ModelInfo.IsWddm 作为入口门读取。
     * 之前只写了 output 与局部变量，导致该入口门恒不通过、baseline 整段空跑。
     */
    {
        INT modelKind = SS_MODEL_GENERIC_WDM;
        INT frameworkKind = SS_FRAMEWORK_NONE;
        ULONG modelConfidence = 30;

        ss_classify_driver_dispatch_model(&scanCtx, &modelKind, &frameworkKind,
                                          &modelConfidence, &context->modelInfo);

        context->modelKind = modelKind;
        context->frameworkKind = frameworkKind;
        context->modelConfidence = modelConfidence;

        output->modelKind = modelKind;
        output->frameworkKind = frameworkKind;
        output->modelConfidence = modelConfidence;
    }

    /*
     * ---- 5. 按模型分流 ----
     *
     * 原实现（DispatchOrchestrator.inc:266 Select Case Context.ModelKind）：
     *   Case DispatchModelWddm:
     *       MergeWddmDispatchResult          <- 第一层：ownership classification
     *       ClearWddmDispatchBaseline
     *       If RecoverDxgkrnlDispatchBaseline(...) Then
     *           MergeWddmDispatchBaseline    <- 第二层：framework baseline
     *       Else
     *           [WDDM-BASELINE] Baseline unavailable, retain FrameworkOwned semantics
     *
     * ClearWddmDispatchBaseline 由 ss_recover_dxgkrnl_dispatch_baseline 内部完成
     * （原实现也是这样：RecoverDxgkrnlDispatchBaseline 第一句即 Clear）。
     */
    if (output->modelKind == SS_MODEL_WDDM) {
        SS_SCAN_CONTEXT dxgContext;
        SS_WDDM_DISPATCH_BASELINE_OUTPUT baseline;

        memset(&dxgContext, 0, sizeof(dxgContext));

        if (ss_load_dispatch_module_context_named(context, L"dxgkrnl.sys",
                                                  &dxgContext)) {
            /* 第一层：ownership classification（绝不伪造 OriginalFunction） */
            ss_merge_wddm_dispatch_result(output, &context->modelInfo, context,
                                          dxgContext.imageBase, dxgContext.imageSize);

            /*
             * 第二层：独立恢复 dxgkrnl framework baseline。
             * 注意顺序：必须先跑 MergeWddmDispatchResult，因为
             * ScoreWddmBaselineCandidate 的 expectedCount 门槛统计的正是
             * FrameworkOwned 槽位。
             */
            if (ss_recover_dxgkrnl_dispatch_baseline(context, output, &baseline)) {
                ss_merge_wddm_dispatch_baseline(output, &baseline, dxgContext.imageSize);
            } else {
                ss_log_ctx(&scanCtx, "RecoverDriverDispatch",
                           "[WDDM-BASELINE] Baseline unavailable, retain FrameworkOwned semantics");
            }

            /* Phase 2 调试转储（内部，非 public API） */
            ss_wddm_debug_dump_baseline(&baseline, context->logSink, context->logContext);
        } else {
            ss_log_ctx(&scanCtx, "RecoverDriverDispatch",
                       "[WDDM-BASELINE] dxgkrnl.sys not available from host, "
                       "retain FrameworkOwned semantics");
        }
    }

    /* ---- 6. 补默认语义 ---- */
    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (output->majorFunction[i].state == SS_SLOT_UNRESOLVED) {
            ULONG64 curAddr = context->hasCurrentMajorFunction ? context->currentMajorFunction[i] : 0;

            if (context->iopInvalidDeviceRequest != 0 &&
                curAddr == context->iopInvalidDeviceRequest) {

                output->majorFunction[i].state = SS_SLOT_DEFAULT;
                output->majorFunction[i].ownerKind = SS_OWNER_KERNEL_DEFAULT;
                output->majorFunction[i].source = SS_SOURCE_DEFAULT;
            }
        }
    }

    /* ---- 7. Finalize ---- */
    ss_finalize_dispatch_recovery(context, output);

    if (output->hitCount > 0) {
        output->confidence = (output->hitCount >= 20) ? 100 : (output->hitCount * 5);
    } else {
        output->confidence = 0;
    }

    /* ---- 8. 状态判定 ---- */
    for (INT i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (output->majorFunction[i].state != SS_SLOT_UNRESOLVED) {
            totalResolved += 1;
        }
    }

    return (totalResolved > 0) ? SS_DISPATCH_STATUS_RECOVERED : SS_DISPATCH_STATUS_NO_MATCH;
}

/* ==================================================================
 * 已知缺口（第一阶段，显式记录，不得静默）
 *
 * 1. DetectWddmDriver / MergeWddmDispatchResult / RecoverDxgkrnlDispatchBaseline
 *    （DispatchWddm.inc，2187 行）未移植 => 模型分类恒为 GenericWdm，
 *    且不存在 DispatchSlotFrameworkOwned 槽。对 slot->原始地址 的影响需以
 *    50 样本回归实测确认（dxgkrnl 系列样本的槽在基线中本就多为 default 语义）。
 * 2. DispatchKmdf.inc（184 行）、ApplyKmdfDispatchBaseline 未移植 =>
 *    KMDF 驱动（Vid.sys / mslldp.sys）不走框架 baseline 重写路径。
 * 3. DispatchFastIo.inc（884 行）未移植 => FastIoDispatch 只上报
 *    fastIoDispatchRva，不恢复 27 个 FastIO 函数原始地址。
 * 4. DispatchFrameworkHid.inc（226 行）：已由 dispatch_hid.c 以真实语义恢复替代
 *    （旧 VB 实现因把 udis86 operand.offset 当位移值用而恒恢复 0 个槽，故不是
 *    逐行移植，而是按 T1 地面真值重新实现；见 dispatch_hid.c 文件头）。
 * ================================================================== */
