/*
 * wddm_probe.c -- Phase 2 WDDM 覆盖 oracle 验证器（工作区临时工具）
 *
 * 目的：不经内核、不加载驱动，直接用 Core DLL 对真实驱动镜像跑
 *       SS_RecoverDispatchFromImage，把模型分类结果与
 *       DispatchWddm.inc 的静态 oracle（_wddm_probe/verify_wddm_detect.py）
 *       以及 5 样本地面真值（_wddm_probe/inv/gt.json）逐项对照。
 *
 * 用法：
 *   wddm_probe.exe <image.sys> [<dxgkrnl.sys>]
 *
 * 只读镜像；输出到 stdout。
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "dispatch.h"

static BYTE* load_file(const char* path, ULONG64* sizeOut)
{
    FILE* f = NULL;
    long size;
    BYTE* buffer;

    if (fopen_s(&f, path, "rb") != 0 || f == NULL) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        return NULL;
    }

    buffer = (BYTE*)malloc((size_t)size);
    if (buffer == NULL) {
        fclose(f);
        return NULL;
    }

    if (fread(buffer, 1, (size_t)size, f) != (size_t)size) {
        free(buffer);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *sizeOut = (ULONG64)size;
    return buffer;
}

/* dxgkrnl 加载回调：Core 不自行枚举模块，由宿主提供运行时基址 + 磁盘镜像。
 * 这里用磁盘映像的 OptionalHeader.ImageBase 作为运行时基址——与
 * verify_dispatch_real.py / verify_wddm_baseline.py 的静态 harness 约定一致。 */
typedef struct _PROBE_MODULE {
    const BYTE* buffer;
    ULONG64     size;
    ULONG64     imageBase;
    ULONG       imageSize;
    const char* name;
} PROBE_MODULE;

static const BYTE* g_dxgBuffer = NULL;
static ULONG64     g_dxgSize = 0;

static BOOL WINAPI probe_load_module(const WCHAR* moduleName, void* userContext,
                                     SS_MODULE_IMAGE* image)
{
    PROBE_MODULE* mod = (PROBE_MODULE*)userContext;

    if (mod == NULL || image == NULL || moduleName == NULL) {
        return FALSE;
    }

    if (_wcsicmp(moduleName, L"dxgkrnl.sys") != 0) {
        return FALSE;
    }
    if (g_dxgBuffer == NULL) {
        return FALSE;
    }

    image->buffer = g_dxgBuffer;
    image->size = g_dxgSize;
    image->imageBase = mod->imageBase;

    fprintf(stdout, "  [load-module] %ls imageBase=0x%llX size=0x%llX imageSize=0x%X\n",
            moduleName, (unsigned long long)mod->imageBase,
            (unsigned long long)mod->size, mod->imageSize);
    return TRUE;
}

static void probe_log(void* userContext, const char* functionName, const char* message)
{
    (void)userContext;
    fprintf(stdout, "  LOG [%s] %s\n", functionName, message);
}

int main(int argc, char** argv)
{
    BYTE* image = NULL;
    ULONG64 imageSize = 0;
    SS_DISPATCH_REQUEST_FLAT request;
    void* handle = NULL;
    SS_DISPATCH_STATUS status;
    INT modelKind = -1, frameworkKind = -1;
    ULONG modelConfidence = 0, hitCount = 0, confidence = 0, fastIo = 0, slotCount = 0;
    BYTE* dxgImage = NULL;
    ULONG64 dxgSize = 0;
    PROBE_MODULE dxgModule;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <image.sys> [<dxgkrnl.sys>]\n", argv[0]);
        return 2;
    }

    image = load_file(argv[1], &imageSize);
    if (image == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 2;
    }

    memset(&dxgModule, 0, sizeof(dxgModule));

    if (argc >= 3) {
        dxgImage = load_file(argv[2], &dxgSize);
        if (dxgImage != NULL) {
            dos = (IMAGE_DOS_HEADER*)dxgImage;
            nt = (IMAGE_NT_HEADERS64*)(dxgImage + dos->e_lfanew);
            dxgModule.imageBase = (ULONG64)nt->OptionalHeader.ImageBase;
            dxgModule.imageSize = nt->OptionalHeader.SizeOfImage;
            g_dxgBuffer = dxgImage;
            g_dxgSize = dxgSize;
        }
    }

    dos = (IMAGE_DOS_HEADER*)image;
    nt = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);

    memset(&request, 0, sizeof(request));
    request.imageBuffer = image;
    request.imageSize = imageSize;
    request.imageBase = (ULONG64)nt->OptionalHeader.ImageBase;
    request.moduleName = NULL;
    request.currentMajorFunction = NULL;   /* 无 live 快照（离线） */
    request.iopInvalidDeviceRequest = 0;
    request.loadModule = (dxgImage != NULL) ? probe_load_module : NULL;
    request.loadModuleContext = &dxgModule;

    fprintf(stdout, "IMAGE %s size=0x%llX imageBase=0x%llX\n", argv[1],
            (unsigned long long)imageSize,
            (unsigned long long)request.imageBase);

    status = SS_DispatchRecoverFlat(&request, &handle);
    fprintf(stdout, "STATUS %d\n", (int)status);

    if (handle != NULL) {
        SS_DispatchHandleInfo(handle, &modelKind, &frameworkKind, &modelConfidence,
                              &hitCount, &confidence, &fastIo, &slotCount);
        fprintf(stdout, "RESULT modelKind=%d frameworkKind=%d modelConfidence=%u "
                        "hitCount=%u confidence=%u fastIo=0x%X slots=%u\n",
                modelKind, frameworkKind, modelConfidence, hitCount, confidence,
                fastIo, slotCount);
        SS_DispatchFreeHandle(handle);
    }

    free(image);
    free(dxgImage);
    return 0;
}
