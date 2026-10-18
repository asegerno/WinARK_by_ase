/*
 * dispatch_api.c -- 结构化派遣恢复 API 的公开入口
 *
 * 本文件是 dispatch.h 的唯一实现者，负责：
 *   - 入参校验与所有权边界（调用方缓冲只读、结果由 Core 分配）
 *   - 内部 SS_DRIVER_RECOVERY_OUTPUT -> 公开 SS_DISPATCH_RESULT 的平坦化
 *   - 释放函数
 */
#include "pch.h"
#include "dispatch_internal.h"

/* ==================================================================
 * SS_RecoverDispatchFromImage
 * ================================================================== */
SS_API SS_DISPATCH_STATUS SS_RecoverDispatchFromImage(
    const SS_DISPATCH_REQUEST* request,
    SS_DISPATCH_RESULT** result)
{
    SS_RECOVERY_CONTEXT context;
    SS_DRIVER_RECOVERY_OUTPUT driverOutput;
    SS_DISPATCH_STATUS status;
    SS_DISPATCH_RESULT* out;
    SS_DISPATCH_SLOT* slots;

    if (result == NULL) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }
    *result = NULL;

    if (request == NULL) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }
    if (request->imageBuffer == NULL || request->imageSize == 0) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }
    if (request->imageSize < sizeof(IMAGE_DOS_HEADER)) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }

    memset(&context, 0, sizeof(context));
    context.pDump = request->imageBuffer;
    context.fileSize = request->imageSize;
    context.imageBase = request->imageBase;

    if (request->moduleName != NULL) {
        wcscpy_s(context.moduleName, SS_MODULE_NAME_MAX, request->moduleName);
    }

    context.hasCurrentMajorFunction = request->hasCurrentMajorFunction;
    for (INT i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        context.currentMajorFunction[i] =
            request->hasCurrentMajorFunction ? request->currentMajorFunction[i] : 0;
    }
    context.iopInvalidDeviceRequest = request->iopInvalidDeviceRequest;

    context.loadModule = request->loadModule;
    context.loadModuleContext = request->loadModuleContext;
    context.logSink = request->logSink;
    context.logContext = request->logContext;

    memset(&driverOutput, 0, sizeof(driverOutput));

    status = ss_recover_driver_dispatch(&context, &driverOutput);

    if (status == SS_DISPATCH_STATUS_PARSE_FAILED ||
        status == SS_DISPATCH_STATUS_OUT_OF_MEMORY ||
        status == SS_DISPATCH_STATUS_INVALID_PARAMETER) {
        return status;
    }

    out = (SS_DISPATCH_RESULT*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                         sizeof(SS_DISPATCH_RESULT));
    if (out == NULL) {
        return SS_DISPATCH_STATUS_OUT_OF_MEMORY;
    }

    slots = (SS_DISPATCH_SLOT*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                         sizeof(SS_DISPATCH_SLOT) * SS_DISPATCH_SLOT_COUNT);
    if (slots == NULL) {
        HeapFree(GetProcessHeap(), 0, out);
        return SS_DISPATCH_STATUS_OUT_OF_MEMORY;
    }

    for (INT i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        const SS_FUNCTION_REF* ref = &driverOutput.majorFunction[i];

        slots[i].irpIndex = (ULONG)i;
        slots[i].valid = ref->valid;
        slots[i].moduleBase = ref->moduleBase;
        slots[i].functionRva = ref->functionRva;
        slots[i].state = ref->state;
        slots[i].ownerKind = ref->ownerKind;
        slots[i].source = ref->source;
        slots[i].confidence = ref->confidence;
    }

    out->modelKind = driverOutput.modelKind;
    out->frameworkKind = driverOutput.frameworkKind;
    out->modelConfidence = driverOutput.modelConfidence;
    out->hitCount = driverOutput.hitCount;
    out->confidence = driverOutput.confidence;
    out->fastIoDispatchRva = driverOutput.fastIoDispatchRva;
    out->slotCount = SS_DISPATCH_SLOT_COUNT;
    out->slots = slots;

    *result = out;

    return status;
}

/* ==================================================================
 * SS_DispatchFreeResult
 * ================================================================== */
SS_API void SS_DispatchFreeResult(SS_DISPATCH_RESULT* result)
{
    if (result == NULL) {
        return;
    }

    if (result->slots != NULL) {
        HeapFree(GetProcessHeap(), 0, result->slots);
        result->slots = NULL;
    }

    result->slotCount = 0;

    HeapFree(GetProcessHeap(), 0, result);
}

/* ==================================================================
 * SS_DispatchSlotName
 * ================================================================== */
SS_API ULONG SS_DispatchSlotName(ULONG irpIndex, WCHAR* name, ULONG nameCount)
{
    const WCHAR* source = ss_irp_mj_name(irpIndex);
    ULONG length = (ULONG)wcslen(source);

    if (name != NULL && nameCount > 0) {
        ULONG copy = (length < nameCount - 1) ? length : (nameCount - 1);
        if (copy > 0) {
            memcpy(name, source, copy * sizeof(WCHAR));
        }
        name[copy] = L'\0';
    }

    return length;
}

/* ==================================================================
 * 跨语言友好入口
 * ================================================================== */

SS_API SS_DISPATCH_STATUS SS_DispatchRecoverFlat(
    const SS_DISPATCH_REQUEST_FLAT* request,
    void** resultHandle)
{
    SS_DISPATCH_REQUEST full;
    SS_DISPATCH_RESULT* result = NULL;
    SS_DISPATCH_STATUS status;

    if (resultHandle == NULL) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }
    *resultHandle = NULL;

    if (request == NULL) {
        return SS_DISPATCH_STATUS_INVALID_PARAMETER;
    }

    memset(&full, 0, sizeof(full));
    full.imageBuffer = request->imageBuffer;
    full.imageSize = request->imageSize;
    full.imageBase = request->imageBase;
    full.moduleName = request->moduleName;
    full.iopInvalidDeviceRequest = request->iopInvalidDeviceRequest;

    /* 跨模块扫描：由宿主任宿主提供模块镜像（Core 不自行枚举模块/读文件） */
    full.loadModule = (SS_MODULE_LOAD_CALLBACK)request->loadModule;
    full.loadModuleContext = request->loadModuleContext;

    if (request->currentMajorFunction != NULL) {
        full.hasCurrentMajorFunction = TRUE;
        for (INT i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
            full.currentMajorFunction[i] = request->currentMajorFunction[i];
        }
    }

    /* 日志回调不开放（Core 静默）；模块加载回调见上 */
    full.logSink = NULL;

    status = SS_RecoverDispatchFromImage(&full, &result);

    if (result != NULL) {
        *resultHandle = (void*)result;
    }

    return status;
}

SS_API void SS_DispatchFreeHandle(void* resultHandle)
{
    SS_DispatchFreeResult((SS_DISPATCH_RESULT*)resultHandle);
}

SS_API BOOL SS_DispatchHandleInfo(
    void*  resultHandle,
    INT*   modelKind,
    INT*   frameworkKind,
    ULONG* modelConfidence,
    ULONG* hitCount,
    ULONG* confidence,
    ULONG* fastIoDispatchRva,
    ULONG* slotCount)
{
    SS_DISPATCH_RESULT* r = (SS_DISPATCH_RESULT*)resultHandle;

    if (r == NULL) {
        return FALSE;
    }

    if (modelKind != NULL)         *modelKind = r->modelKind;
    if (frameworkKind != NULL)     *frameworkKind = r->frameworkKind;
    if (modelConfidence != NULL)   *modelConfidence = r->modelConfidence;
    if (hitCount != NULL)          *hitCount = r->hitCount;
    if (confidence != NULL)        *confidence = r->confidence;
    if (fastIoDispatchRva != NULL) *fastIoDispatchRva = r->fastIoDispatchRva;
    if (slotCount != NULL)         *slotCount = r->slotCount;

    return TRUE;
}

SS_API BOOL SS_DispatchHandleSlot(
    void*    resultHandle,
    ULONG    index,
    BOOL*    valid,
    ULONG64* moduleBase,
    ULONG*   functionRva,
    INT*     state,
    INT*     ownerKind,
    INT*     source,
    ULONG*   confidence)
{
    SS_DISPATCH_RESULT* r = (SS_DISPATCH_RESULT*)resultHandle;
    const SS_DISPATCH_SLOT* s;

    if (r == NULL || r->slots == NULL || index >= r->slotCount) {
        return FALSE;
    }

    s = &r->slots[index];

    if (valid != NULL)        *valid = s->valid;
    if (moduleBase != NULL)   *moduleBase = s->moduleBase;
    if (functionRva != NULL)  *functionRva = s->functionRva;
    if (state != NULL)        *state = s->state;
    if (ownerKind != NULL)    *ownerKind = s->ownerKind;
    if (source != NULL)       *source = s->source;
    if (confidence != NULL)   *confidence = s->confidence;

    return TRUE;
}