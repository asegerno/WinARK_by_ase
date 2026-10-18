/*
 * SnowSwordCoreDispatchTest -- SnowSwordCore 结构化派遣恢复的离线测试
 *
 * 两种模式：
 *   1. 扫描模式：SnowSwordCoreDispatchTest.exe <image> [<image> ...]
 *      输出与 validation/verify_dispatch_real.py 相同形状的行，便于比对：
 *        IMAGE <path>
 *        SHA256 <hex>
 *        RESULT status=<n> hits=<n> fastio=0x<hex>
 *        SLOT <i> RVA=0x<hex>
 *
 *   2. 静态基准比对模式：SnowSwordCoreDispatchTest.exe --verify-static
 *      对 dispatch_static_baseline.h 中的 16 个镜像逐槽比对。
 *      镜像 SHA-256 与基准不符时报告 SKIP（Windows 更新会改变镜像）。
 *
 * 条件与静态基准保持一致：ImageBase 取 PE OptionalHeader.ImageBase，
 * 不提供模块加载回调（等价于 VB harness 中 stub 掉的 ScanImportedDispatchCall），
 * 不提供 live MajorFunction 快照（因此不产生 DispatchSlotDefault 语义）。
 */
#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include "../dispatch.h"
#include "dispatch_static_baseline.h"

#pragma comment(lib, "bcrypt.lib")

/* hid_dispatch_test.cpp：HID 框架派遣覆盖（HIDCLASS!HidRegisterMinidriver）测试入口 */
int RunHidDispatchTestMain(int argc, char** argv);

/* ------------------------------------------------------------------ */
static BOOL ReadFileBytes(const WCHAR* path, BYTE** outBuffer, ULONG64* outSize)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    BYTE* buffer = NULL;
    DWORD read = 0;
    BOOL ok = FALSE;

    *outBuffer = NULL;
    *outSize = 0;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 0x10000000LL) {
        CloseHandle(file);
        return FALSE;
    }

    buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart);
    if (buffer == NULL) {
        CloseHandle(file);
        return FALSE;
    }

    if (ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL) && read == (DWORD)size.QuadPart) {
        *outBuffer = buffer;
        *outSize = (ULONG64)read;
        ok = TRUE;
    } else {
        HeapFree(GetProcessHeap(), 0, buffer);
    }

    CloseHandle(file);
    return ok;
}

static BOOL ComputeSha256(const BYTE* data, ULONG64 size, char* outHex)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    BOOL ok = FALSE;

    outHex[0] = '\0';

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) {
        return FALSE;
    }
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return FALSE;
    }

    if (BCryptHashData(hash, (PUCHAR)data, (ULONG)size, 0) >= 0 &&
        BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0) {
        for (int i = 0; i < 32; i++) {
            sprintf_s(outHex + i * 2, 3, "%02x", digest[i]);
        }
        outHex[64] = '\0';
        ok = TRUE;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* PE OptionalHeader.ImageBase；用作恢复上下文的 ModuleBase */
static BOOL GetPePreferredImageBase(const BYTE* buffer, ULONG64 size, ULONG64* outBase)
{
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)buffer;
    const IMAGE_NT_HEADERS64* nt;

    *outBase = 0;

    if (size < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != 0x5A4D) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0 ||
        (ULONG64)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) {
        return FALSE;
    }

    nt = (const IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
    if (nt->Signature != 0x4550 || nt->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    *outBase = (ULONG64)nt->OptionalHeader.ImageBase;
    return *outBase != 0;
}

/* ------------------------------------------------------------------ */
typedef struct _SS_SCAN_RESULT_SUMMARY {
    SS_DISPATCH_STATUS status;
    ULONG              hits;
    ULONG              fastIoRva;
    BOOL               slotsValid[SS_DISPATCH_SLOT_COUNT];
    ULONG              slotsRva[SS_DISPATCH_SLOT_COUNT];
    ULONG              slotsState[SS_DISPATCH_SLOT_COUNT];
} SS_SCAN_RESULT_SUMMARY;

static BOOL RunScan(const WCHAR* imagePath, SS_SCAN_RESULT_SUMMARY* summary)
{
    BYTE* buffer = NULL;
    ULONG64 size = 0;
    ULONG64 imageBase = 0;
    SS_DISPATCH_REQUEST request;
    SS_DISPATCH_RESULT* result = NULL;
    SS_DISPATCH_STATUS status;

    memset(summary, 0, sizeof(*summary));

    if (!ReadFileBytes(imagePath, &buffer, &size)) {
        wprintf(L"ERROR cannot read image: %s\n", imagePath);
        return FALSE;
    }

    if (!GetPePreferredImageBase(buffer, size, &imageBase)) {
        wprintf(L"ERROR not a valid x64 PE image: %s\n", imagePath);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    memset(&request, 0, sizeof(request));
    request.imageBuffer = buffer;
    request.imageSize = size;
    request.imageBase = imageBase;
    request.moduleName = imagePath;   /* 与静态基准 harness 一致：传完整路径 */
    request.hasCurrentMajorFunction = FALSE;
    request.iopInvalidDeviceRequest = 0;
    request.loadModule = NULL;        /* 等价于 stub 掉跨模块扫描 */
    request.logSink = NULL;

    status = SS_RecoverDispatchFromImage(&request, &result);

    summary->status = status;

    if (result != NULL) {
        summary->hits = result->hitCount;
        summary->fastIoRva = result->fastIoDispatchRva;

        for (ULONG i = 0; i < result->slotCount && i < SS_DISPATCH_SLOT_COUNT; i++) {
            summary->slotsValid[i] = result->slots[i].valid;
            summary->slotsRva[i] = result->slots[i].functionRva;
            summary->slotsState[i] = (ULONG)result->slots[i].state;
        }

        SS_DispatchFreeResult(result);
    }

    HeapFree(GetProcessHeap(), 0, buffer);
    return TRUE;
}

/* ------------------------------------------------------------------ */
static int ScanAndPrint(const WCHAR* imagePath)
{
    BYTE* buffer = NULL;
    ULONG64 size = 0;
    char sha[65];
    SS_SCAN_RESULT_SUMMARY summary;

    /* SHA-256 需要在 RunScan 之前算，这里单独读一次以复用缓冲 */
    if (ReadFileBytes(imagePath, &buffer, &size)) {
        ComputeSha256(buffer, size, sha);
        HeapFree(GetProcessHeap(), 0, buffer);
    } else {
        wprintf(L"ERROR cannot read image: %s\n", imagePath);
        return 1;
    }

    if (!RunScan(imagePath, &summary)) {
        return 1;
    }

    printf("IMAGE %ls\n", imagePath);
    printf("SHA256 %s\n", sha);
    printf("RESULT status=%d hits=%u fastio=0x%X\n",
           (int)summary.status, summary.hits, summary.fastIoRva);

    for (int i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        if (summary.slotsValid[i]) {
            printf("SLOT %d RVA=0x%X\n", i, summary.slotsRva[i]);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
static int VerifyStatic(void)
{
    WCHAR driverDir[MAX_PATH];
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    if (GetSystemDirectoryW(driverDir, MAX_PATH) == 0) {
        printf("ERROR GetSystemDirectory failed\n");
        return 2;
    }
    wcscat_s(driverDir, MAX_PATH, L"\\drivers");

    printf("=== SnowSwordCore DispatchGeneric static baseline verification ===\n");
    printf("driver dir: %ls\n\n", driverDir);

    for (size_t e = 0; e < SS_STATIC_BASELINE_COUNT; e++) {
        const SS_STATIC_BASELINE* base = &g_staticBaseline[e];
        WCHAR path[MAX_PATH];
        BYTE* buffer = NULL;
        ULONG64 size = 0;
        char sha[65];
        SS_SCAN_RESULT_SUMMARY summary;
        BOOL mismatch = FALSE;

        swprintf_s(path, MAX_PATH, L"%ls\\%ls", driverDir, base->imageName);

        if (!ReadFileBytes(path, &buffer, &size)) {
            printf("[SKIP] %-22ls image not present\n", base->imageName);
            skipped++;
            continue;
        }

        if (!ComputeSha256(buffer, size, sha)) {
            printf("[SKIP] %-22ls sha256 failed\n", base->imageName);
            HeapFree(GetProcessHeap(), 0, buffer);
            skipped++;
            continue;
        }
        HeapFree(GetProcessHeap(), 0, buffer);

        if (strcmp(sha, base->sha256) != 0) {
            printf("[SKIP] %-22ls image version differs (sha=%s)\n", base->imageName, sha);
            skipped++;
            continue;
        }

        if (!RunScan(path, &summary)) {
            printf("[FAIL] %-22ls scan failed\n", base->imageName);
            failed++;
            continue;
        }

        if (summary.hits != base->hits) {
            printf("[FAIL] %-22ls hits: got %u expected %u\n",
                   base->imageName, summary.hits, base->hits);
            mismatch = TRUE;
        }
        if (summary.fastIoRva != base->fastIoRva) {
            printf("[FAIL] %-22ls fastio: got 0x%X expected 0x%X\n",
                   base->imageName, summary.fastIoRva, base->fastIoRva);
            mismatch = TRUE;
        }

        for (const SS_STATIC_SLOT* slot = base->slots; slot->index >= 0; slot++) {
            if (!summary.slotsValid[slot->index]) {
                printf("[FAIL] %-22ls slot %d: not recovered, expected RVA=0x%X\n",
                       base->imageName, slot->index, slot->rva);
                mismatch = TRUE;
            } else if (summary.slotsRva[slot->index] != slot->rva) {
                printf("[FAIL] %-22ls slot %d: got RVA=0x%X expected RVA=0x%X\n",
                       base->imageName, slot->index, summary.slotsRva[slot->index], slot->rva);
                mismatch = TRUE;
            }
        }

        /* 反向：基准未列出的槽不应被恢复（防止多报） */
        for (int i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
            if (!summary.slotsValid[i]) {
                continue;
            }
            BOOL expected = FALSE;
            for (const SS_STATIC_SLOT* slot = base->slots; slot->index >= 0; slot++) {
                if (slot->index == i) {
                    expected = TRUE;
                    break;
                }
            }
            if (!expected) {
                printf("[FAIL] %-22ls slot %d: unexpected recovery RVA=0x%X\n",
                       base->imageName, i, summary.slotsRva[i]);
                mismatch = TRUE;
            }
        }

        if (!mismatch) {
            printf("[PASS] %-22ls hits=%u slots matched\n", base->imageName, base->hits);
            passed++;
        } else {
            failed++;
        }
    }

    printf("\n=== summary: PASS=%d FAIL=%d SKIP=%d ===\n", passed, failed, skipped);

    return (failed == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
static void Usage(void)
{
    printf("usage:\n");
    printf("  SnowSwordCoreDispatchTest.exe <image> [<image> ...]   scan disk images\n");
    printf("  SnowSwordCoreDispatchTest.exe --verify-static         compare against built-in baseline\n");
    printf("  SnowSwordCoreDispatchTest.exe --verify-hid            HID framework override tests\n");
    printf("  SnowSwordCoreDispatchTest.exe --scan-hid <image> ...  real PE scan with module loading\n");
}

/*
 * 入口由 SnowSwordCoreTest.cpp 的 main 分派：带参数时进入派遣恢复测试，
 * 无参数时保持原有驱动通信自检行为。
 */
int RunDispatchTestMain(int argc, char** argv)
{
    int result = 0;

    if (argc < 2) {
        Usage();
        return 2;
    }

    if (_stricmp(argv[1], "--verify-static") == 0) {
        return VerifyStatic();
    }

    if (_stricmp(argv[1], "--verify-hid") == 0 ||
        _stricmp(argv[1], "--scan-hid") == 0) {
        return RunHidDispatchTestMain(argc, argv);
    }

    for (int i = 1; i < argc; i++) {
        WCHAR wide[MAX_PATH];
        if (MultiByteToWideChar(CP_ACP, 0, argv[i], -1, wide, MAX_PATH) == 0) {
            printf("ERROR bad path: %s\n", argv[i]);
            result = 1;
            continue;
        }
        if (ScanAndPrint(wide) != 0) {
            result = 1;
        }
    }

    return result;
}
