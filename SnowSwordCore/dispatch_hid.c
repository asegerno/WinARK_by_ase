/*
 * dispatch_hid.c -- HID 框架派遣覆盖恢复（HIDCLASS.SYS!HidRegisterMinidriver）
 *
 * 语义（T1 地面真值，见 SnowSwordCoreTest/hid_dispatch_test.cpp 文件头）：
 *   mshidkmdf.sys / mshidumdf.sys 的 DriverEntry 先自填 28 个 MajorFunction 槽，
 *   随后 call qword ptr [IAT] 进入 HIDCLASS.SYS!HidRegisterMinidriver；该函数在
 *   返回前把宿主 DriverObject 的 9 个槽改写成 hidclass 自己的 handler：
 *       {0,2,3,4,14,15,22,23,27}
 *   因此 T1（DriverEntry 返回后）这 9 个槽的「原始派遣」应属 hidclass.sys，
 *   而不是驱动自身 DriverEntry 的中间态（该状态在 DriverEntry 返回后已不存在）。
 *
 * 实现：复用生产 Generic 扫描器（CFG 定点迭代 + 稳定态重放），只额外做两件事：
 *
 *   1. 入口状态把 RCX 标成 SS_REG_FRAMEWORK_REGISTRATION。HidRegisterMinidriver 的
 *      第一个参数是 PHID_MINIDRIVER_REGISTRATION（注册块），不是 DriverObject；
 *      注册块 +8 字段才是宿主 DriverObject。Generic 的 LEA/MOV 规则据此派生
 *      &registration->DriverObject 并解引用得到 SS_REG_DRIVER_OBJECT，此后完全
 *      走既有的槽写入规则（含 SS_REG_DRIVER_OBJECT_ADDRESS 派生基址与 slot 0 形式）。
 *      这里没有任何「寄存器编号」硬编码：寄存器全部由指令流跟踪。
 *
 *   2. 效果先落进局部 SS_RECOVERY_OUTPUT，只把 MajorFunction 命中合并回调用方。
 *      这样 hidclass 内部对 FastIo 之类的写入不会被算到宿主驱动头上（旧 VB 实现
 *      直接写调用方输出，会污染宿主 FastIo 归属）。
 *
 * 不跟随嵌套调用：命中只认该函数自身的槽写入 —— 与 T1 语义、与旧 VB 线性实现一致。
 * 实现方式是入口 depth 取到上限 SS_DISPATCH_MAX_CALL_DEPTH，扫描器本身的 CALL
 * 递归门（depth < SS_DISPATCH_MAX_CALL_DEPTH）自然关闭，无需改动通用判定。
 */
#include "pch.h"
#include "dispatch_internal.h"

BOOL ss_recover_hid_register_minidriver_dispatch(const SS_SCAN_CONTEXT* extCtx, ULONG targetRva,
                                                 SS_RECOVERY_OUTPUT* output)
{
    SS_SCAN_CONTEXT hidCtx;
    SS_ABSTRACT_STATE entryState;
    SS_SCAN_STATE* scanState;
    SS_RECOVERY_OUTPUT hidOutput;
    BOOL recovered = FALSE;
    INT i;

    if (extCtx == NULL || output == NULL) {
        return FALSE;
    }
    if (extCtx->pDump == NULL || extCtx->fileSize == 0 || targetRva == 0) {
        return FALSE;
    }
    if (!ss_is_rva_executable(extCtx->pDump, targetRva)) {
        ss_log_ctx(extCtx, "RecoverHidRegisterMinidriverDispatch",
                   "[REJECT] Entry RVA is not executable Module=%ws RVA=0x%X",
                   extCtx->moduleName, targetRva);
        return FALSE;
    }

    /* 局部上下文：只覆盖效果来源，其余（基址 / 回调 / 日志）原样继承。 */
    hidCtx = *extCtx;
    hidCtx.recoveredSourceName = SS_SOURCE_NAME_HID;

    memset(&entryState, 0, sizeof(entryState));
    entryState.rspKnown = TRUE;
    /* RCX = 框架注册块（PHID_MINIDRIVER_REGISTRATION），不是 DriverObject。 */
    entryState.regState[1].valueType = SS_REG_FRAMEWORK_REGISTRATION;
    entryState.regState[1].value = 0;

    memset(&hidOutput, 0, sizeof(hidOutput));

    scanState = (SS_SCAN_STATE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          sizeof(SS_SCAN_STATE));
    if (scanState == NULL) {
        return FALSE;
    }

    ss_scan_dispatch_function_with_args(&hidCtx, scanState, targetRva, &entryState,
                                        SS_DISPATCH_MAX_CALL_DEPTH, &hidOutput);

    HeapFree(GetProcessHeap(), 0, scanState);

    for (i = 0; i <= SS_IRP_MJ_MAXIMUM_FUNCTION; i++) {
        const SS_FUNCTION_REF* hit = &hidOutput.majorFunction[i];

        if (!hit->valid) {
            continue;
        }

        recovered = TRUE;

        ss_log_ctx(&hidCtx, "RecoverHidRegisterMinidriverDispatch",
                   "[HID] Dispatch[%d] %ws ModuleBase=0x%llX RVA=0x%X FinalVA=0x%llX",
                   i, ss_irp_mj_name((ULONG)i), hit->moduleBase, hit->functionRva,
                   hit->moduleBase + hit->functionRva);

        /* 覆盖宿主 DriverEntry 记录下来的中间态；命中计数与 SetRecoveredDispatch 同规则 */
        if (!output->majorFunction[i].valid) {
            output->hitCount += 1;
        }
        output->majorFunction[i] = *hit;
    }

    if (!recovered) {
        ss_log_ctx(&hidCtx, "RecoverHidRegisterMinidriverDispatch",
                   "[HID] No MajorFunction override recovered Module=%ws RVA=0x%X",
                   extCtx->moduleName, targetRva);
    }

    return recovered;
}
