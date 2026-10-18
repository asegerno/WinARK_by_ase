/*
 * wddm_gt_verify.c -- Phase 2 WDDM baseline 真值验证器（工作区临时工具）
 *
 * 目的：用 Core DLL 重放一次真实 CLI 运行的 live 快照，跑完整 WDDM 后端
 *       （Detect -> MergeWddmDispatchResult -> RecoverDxgkrnlDispatchBaseline
 *        -> MergeWddmDispatchBaseline），把结果与 VB 的地面真值
 *       （_wddm_probe/inv/gt.json）逐槽对照。
 *
 * 为什么必须重放 live 快照：
 *   RecoverDxgkrnlDispatchBaseline 的两道硬门槛
 *     expectedCount >= 6  （需要 MergeWddmDispatchResult 产出 FrameworkOwned 槽）
 *     exactCount    >= 4  （需要 CurrentMajorFunction[] 与 dxgkrnl dump 比对）
 *   都依赖 IOCTL 取回的运行时派遣表。离线（不给快照）时 correct 但无意义。
 *
 * 关键约束：
 *   - dxgkrnl 的 ImageBase 必须用 **CLI 观测到的运行时基址**，不能取 PE 的
 *     ImageBase：候选 RVA 与 current 地址做差时用的是运行时基址。
 *   - FileSize 用磁盘字节数（供 RVA->FOA）；ImageSize 取 PE SizeOfImage
 *     （供 IsAddressInModule）。
 *
 * 用法：
 *   wddm_gt_verify.exe <driver.sys> <dxgkrnl.sys> <cli.txt> <imageBaseHex> [dump]
 *
 *   cli.txt  = 该样本的 `<stem>.cli.txt`（提供 live「当前地址」列）
 *   imageBaseHex = 该驱动的运行时基址（如 0xFFFFF8043C220000 是 dxgkrnl 的）
 *   dump     = 额外转储最终 recovery output 的全部 28 槽
 *
 * 只读镜像；输出到 stdout。
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dispatch.h"

/* dispatch.h 的 flat 段未声明本入口（宿主走 flat），这里手工声明以取得 logSink。 */
SS_API SS_DISPATCH_STATUS SS_RecoverDispatchFromImage(
    const SS_DISPATCH_REQUEST* request,
    SS_DISPATCH_RESULT** result);

#define SLOT_COUNT 28

typedef struct _MODULE_IMAGE {
    const BYTE* buffer;
    ULONG64     size;
    ULONG64     imageBase;
    ULONG       imageSize;
} MODULE_IMAGE;

static MODULE_IMAGE g_dxg;
static int         g_loadCalls = 0;

static BYTE* load_file(const char* path, ULONG64* sizeOut)
{
    FILE* f = NULL;
    long size;
    BYTE* buffer;

    if (fopen_s(&f, path, "rb") != 0 || f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
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

static BOOL get_image_layout(const BYTE* image, ULONG64* preferredBase, ULONG* sizeOfImage)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt;

    if (image == NULL) {
        return FALSE;
    }

    dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    nt = (const IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    *preferredBase = (ULONG64)nt->OptionalHeader.ImageBase;
    *sizeOfImage = nt->OptionalHeader.SizeOfImage;
    return TRUE;
}

static BOOL WINAPI probe_load_module(const WCHAR* moduleName, void* userContext,
                                     SS_MODULE_IMAGE* image)
{
    (void)userContext;

    if (moduleName == NULL || image == NULL) {
        return FALSE;
    }

    if (_wcsicmp(moduleName, L"dxgkrnl.sys") != 0) {
        return FALSE;
    }

    if (g_dxg.buffer == NULL) {
        return FALSE;
    }

    g_loadCalls += 1;
    image->buffer = g_dxg.buffer;
    image->size = g_dxg.size;
    image->imageBase = g_dxg.imageBase;

    fprintf(stdout, "[HOST] load-module %ls size=0x%llX imageBase=0x%llX imageSize=0x%X\n",
            moduleName, (unsigned long long)g_dxg.size,
            (unsigned long long)g_dxg.imageBase, g_dxg.imageSize);
    return TRUE;
}

static void WINAPI probe_log(void* userContext, const char* functionName,
                             const char* message)
{
    (void)userContext;
    fprintf(stdout, "[CORE] [%s] %s\n", functionName, message);
}

/*
 * 从 CLI 输出抽取 live 快照。
 * 行格式：名称|当前地址|所属模块|原始地址|所属模块
 * 行首为 IRP_MJ_* 的取「当前地址」列；DriverStartIo 行取 startIo。
 */
static int parse_cli_table(const char* path,
                           ULONG64 currentMajorFunction[SLOT_COUNT],
                           ULONG64* startIo,
                           ULONG64* unload,
                           ULONG64* driverInit)
{
    FILE* f = NULL;
    char line[1024];
    int found = 0;
    char* names[SLOT_COUNT] = {
        "IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE", "IRP_MJ_READ",
        "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION", "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA", "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION", "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL", "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN", "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT", "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER", "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA", "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP"
    };

    if (fopen_s(&f, path, "rb") != 0 || f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }

    while (fgets(line, (int)sizeof(line), f) != NULL) {
        char* bar = strchr(line, '|');
        ULONG64 addr = 0;
        int i;

        if (bar == NULL) {
            continue;
        }
        *bar = '\0';

        if (sscanf_s(bar + 1, "%llx", &addr) != 1) {
            /* 也接受 0x 前缀写法 */
            if (sscanf_s(bar + 1, "0x%llx", &addr) != 1) {
                continue;
            }
        }

        for (i = 0; i < SLOT_COUNT; i++) {
            if (_stricmp(line, names[i]) == 0) {
                currentMajorFunction[i] = addr;
                found += 1;
                break;
            }
        }

        if (i == SLOT_COUNT) {
            if (_stricmp(line, "DriverStartIo") == 0) {
                *startIo = addr;
            } else if (_stricmp(line, "DriverUnload") == 0) {
                *unload = addr;
            } else if (_stricmp(line, "DriverInit") == 0) {
                *driverInit = addr;
            }
        }
    }

    fclose(f);
    return found;
}

int main(int argc, char** argv)
{
    BYTE* driverImage = NULL;
    BYTE* dxgImage = NULL;
    ULONG64 driverSize = 0;
    ULONG64 dxgSize = 0;
    ULONG64 prefBase = 0;
    ULONG  sizeOfImage = 0;
    ULONG64 dxgRuntimeBase = 0;
    ULONG64 dxgSizeOfImage = 0;
    ULONG64 currentMajorFunction[SLOT_COUNT];
    ULONG64 startIo = 0, unload = 0, driverInit = 0;
    SS_DISPATCH_REQUEST request;
    SS_DISPATCH_RESULT* result = NULL;
    SS_DISPATCH_STATUS status;
    int parsed;
    int dump = 0;
    int i;

    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <driver.sys> <dxgkrnl.sys> <cli.txt> <dxgkrnlRuntimeBaseHex> [dump]\n",
                argv[0]);
        return 2;
    }

    if (argc >= 6 && _stricmp(argv[5], "dump") == 0) {
        dump = 1;
    }

    memset(currentMajorFunction, 0, sizeof(currentMajorFunction));

    driverImage = load_file(argv[1], &driverSize);
    if (driverImage == NULL) {
        return 2;
    }

    dxgImage = load_file(argv[2], &dxgSize);
    if (dxgImage == NULL) {
        free(driverImage);
        return 2;
    }

    if (_strnicmp(argv[4], "0x", 2) == 0) {
        dxgRuntimeBase = _strtoui64(argv[4] + 2, NULL, 16);
    } else {
        dxgRuntimeBase = _strtoui64(argv[4], NULL, 16);
    }

    if (get_image_layout(driverImage, &prefBase, &sizeOfImage) == FALSE) {
        fprintf(stderr, "driver image is not a valid PE\n");
        return 2;
    }
    if (get_image_layout(dxgImage, &g_dxg.imageBase, &g_dxg.imageSize) == FALSE) {
        fprintf(stderr, "dxgkrnl image is not a valid PE\n");
        return 2;
    }

    /* 运行时基址覆盖 PE 首选基址 —— 与 VB LoadDispatchModuleContext 一致。 */
    g_dxg.imageBase = dxgRuntimeBase;
    g_dxg.buffer = dxgImage;
    g_dxg.size = dxgSize;
    dxgSizeOfImage = g_dxg.imageSize;

    parsed = parse_cli_table(argv[3], currentMajorFunction, &startIo, &unload, &driverInit);
    if (parsed < 0) {
        return 2;
    }

    fprintf(stdout, "=== wddm_gt_verify ===\n");
    fprintf(stdout, "driver      = %s (%llu bytes, preferredBase=0x%llX imageSize=0x%X)\n",
            argv[1], (unsigned long long)driverSize,
            (unsigned long long)prefBase, sizeOfImage);
    fprintf(stdout, "dxgkrnl     = %s (%llu bytes, runtimeBase=0x%llX imageSize=0x%X)\n",
            argv[2], (unsigned long long)dxgSize,
            (unsigned long long)dxgRuntimeBase, (unsigned)dxgSizeOfImage);
    fprintf(stdout, "live slots  = parsed %d / %d\n", parsed, SLOT_COUNT);
    fprintf(stdout, "DriverInit=0x%llX DriverStartIo=0x%llX DriverUnload=0x%llX\n",
            (unsigned long long)driverInit, (unsigned long long)startIo,
            (unsigned long long)unload);

    memset(&request, 0, sizeof(request));
    request.imageBuffer = driverImage;
    request.imageSize = driverSize;
    /* 驱动自身的运行时基址：_wddm_probe 的静态约定 —— 取 PE 首选基址。
     * 驱动槽位在 WDDM 路径下不由本镜像填充，故不影响 baseline 判定。 */
    request.imageBase = prefBase;
    request.moduleName = NULL;
    request.hasCurrentMajorFunction = (parsed > 0) ? TRUE : FALSE;
    for (i = 0; i < SLOT_COUNT; i++) {
        request.currentMajorFunction[i] = currentMajorFunction[i];
    }
    /* IopInvalidDeviceRequest：栈上传入 0（未知），与静态 harness 一致。
     * 它只用于「curAddr == iopInvalid ⇒ 跳过」这一条，取 0 即该条恒不命中，
     * 对 FrameworkOwned / exact / conflict 三个计数无影响。 */
    request.iopInvalidDeviceRequest = 0;
    request.loadModule = probe_load_module;
    request.loadModuleContext = NULL;
    request.logSink = probe_log;
    request.logContext = NULL;

    status = SS_RecoverDispatchFromImage(&request, &result);
    fprintf(stdout, "STATUS=%d\n", (int)status);

    if (result == NULL) {
        fprintf(stdout, "RESULT=NULL\n");
        free(driverImage);
        free(dxgImage);
        return 1;
    }

    fprintf(stdout, "MODEL modelKind=%d frameworkKind=%d modelConfidence=%u "
                    "hitCount=%u confidence=%u fastIo=0x%X slots=%u\n",
            result->modelKind, result->frameworkKind, result->modelConfidence,
            result->hitCount, result->confidence, result->fastIoDispatchRva,
            result->slotCount);

    fprintf(stdout, "=== SLOT TABLE (state: 1=Recovered 2=FrameworkOwned 3=Default 0=Unresolved;\n"
                    "    owner: 1=Driver 2=Framework 3=KernelDefault; src: 5=FrameworkBaseline 4=FrameworkClassify) ===\n");
    for (i = 0; i < SLOT_COUNT; i++) {
        const SS_DISPATCH_SLOT* s = &result->slots[i];
        WCHAR name[64];
        char narrow[64];

        SS_DispatchSlotName((ULONG)i, name, 64);
        WideCharToMultiByte(CP_ACP, 0, name, -1, narrow, sizeof(narrow), NULL, NULL);

        if (!dump && s->state != SS_SLOT_RECOVERED) {
            continue;
        }

        fprintf(stdout, "SLOT[%2d] %-34s valid=%d state=%d owner=%d src=%d conf=%u "
                        "moduleBase=0x%llX rva=0x%X current=0x%llX\n",
                i, narrow, s->valid, s->state, s->ownerKind, s->source, s->confidence,
                (unsigned long long)s->moduleBase, s->functionRva,
                (unsigned long long)currentMajorFunction[i]);
    }

    {
        int recovered = 0, frameworkOwned = 0, unresolved = 0, dflt = 0;
        for (i = 0; i < SLOT_COUNT; i++) {
            switch (result->slots[i].state) {
            case SS_SLOT_RECOVERED:       recovered += 1; break;
            case SS_SLOT_FRAMEWORK_OWNED: frameworkOwned += 1; break;
            case SS_SLOT_DEFAULT:         dflt += 1; break;
            default:                      unresolved += 1; break;
            }
        }
        fprintf(stdout, "SUMMARY recovered=%d frameworkOwned=%d default=%d unresolved=%d\n",
                recovered, frameworkOwned, dflt, unresolved);
    }

    SS_DispatchFreeResult(result);
    free(driverImage);
    free(dxgImage);
    return 0;
}
