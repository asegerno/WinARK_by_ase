/*
 * dispatch_pe.c -- PE 只读解析层
 *
 * 逐行等价移植自 ring3/modules/KernelHook/DispatchPeUtils.inc。
 * 与 VB 版的唯一结构性差异：LoadDispatchModuleContext 不再自行枚举内核模块、
 * 也不再自行读文件，改为经 SS_MODULE_LOAD_CALLBACK 由宿主提供。
 */
#include "pch.h"
#include "dispatch_internal.h"

#define SS_MAX_PE_STRING_LENGTH 1024

/* ------------------------------------------------------------------
 * 原 GetByte：VB 版定义了但生产路径未使用，这里保留等价语义备用
 * ------------------------------------------------------------------ */
int ss_get_byte(const BYTE* pDump, ULONG64 offset, ULONG64 fileSize)
{
    if (pDump == NULL || offset >= fileSize) {
        return -1;
    }
    return (int)pDump[offset];
}

/* ------------------------------------------------------------------
 * 原 ReadRawRvaDword / Qword / Word
 * ------------------------------------------------------------------ */
BOOL ss_read_raw_rva_dword(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, ULONG* value)
{
    *value = 0;

    ULONG64 foa = ss_rva_to_foa(pDump, rva);
    if (foa == 0 || foa + 4 > fileSize) {
        return FALSE;
    }

    memcpy(value, pDump + foa, 4);
    return TRUE;
}

BOOL ss_read_raw_rva_qword(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, ULONG64* value)
{
    *value = 0;

    ULONG64 foa = ss_rva_to_foa(pDump, rva);
    if (foa == 0 || foa + sizeof(ULONG64) > fileSize) {
        return FALSE;
    }

    memcpy(value, pDump + foa, sizeof(ULONG64));
    return TRUE;
}

BOOL ss_read_raw_rva_word(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva, USHORT* value)
{
    *value = 0;

    ULONG64 foa = ss_rva_to_foa(pDump, rva);
    if (foa == 0 || foa + 2 > fileSize) {
        return FALSE;
    }

    memcpy(value, pDump + foa, 2);
    return TRUE;
}

/* ------------------------------------------------------------------
 * 原 ReadAsciiStringByRva
 *
 * 语义与 VB 版一致：最多扫描 SS_MAX_PE_STRING_LENGTH 字节；遇到 NUL 返回 TRUE，
 * 扫满仍未遇到 NUL 返回 FALSE。写入 out 的部分总是 NUL 结尾（可能被 outCount 截断，
 * 但返回值语义只取决于原扫描结果）。
 * ------------------------------------------------------------------ */
BOOL ss_read_ascii_string_by_rva(const BYTE* pDump, ULONG64 fileSize, ULONG64 rva,
                                 char* out, size_t outCount)
{
    if (outCount > 0) {
        out[0] = '\0';
    }
    if (pDump == NULL || rva == 0 || outCount == 0) {
        return FALSE;
    }

    ULONG64 foa = ss_rva_to_foa(pDump, rva);
    if (foa == 0 || foa >= fileSize) {
        return FALSE;
    }

    for (ULONG i = 0; i < SS_MAX_PE_STRING_LENGTH; i++) {
        if (foa + i >= fileSize) {
            return FALSE;
        }

        BYTE ch = pDump[foa + i];

        if (ch == 0) {
            if (i < outCount) {
                out[i] = '\0';
            }
            return TRUE;
        }

        if (i + 1 < outCount) {
            out[i] = (char)ch;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 RvaToFoa
 *
 * 注意：返回 0 同时表示"失败"与"落在节内但 PointerToRawData + delta == 0"。
 * 这是原实现的行为，保持不动（调用方一律把 0 当失败处理）。
 * ------------------------------------------------------------------ */
ULONG64 ss_rva_to_foa(const BYTE* pFile, ULONG64 rva)
{
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pFile;
    if (dos->e_magic != 0x5A4D) {
        return 0;
    }

    const IMAGE_NT_HEADERS64* nt64 =
        (const IMAGE_NT_HEADERS64*)(pFile + dos->e_lfanew);
    if (nt64->Signature != 0x4550) {
        return 0;
    }

    const IMAGE_SECTION_HEADER* secHdr =
        (const IMAGE_SECTION_HEADER*)((ULONG_PTR)nt64 + sizeof(IMAGE_NT_HEADERS64));

    for (ULONG i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
        if (rva >= secHdr->VirtualAddress &&
            rva < (ULONG64)secHdr->VirtualAddress + secHdr->Misc.VirtualSize) {
            return (ULONG64)secHdr->PointerToRawData + (rva - secHdr->VirtualAddress);
        }
        secHdr++;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * 原 FoaToRva
 * ------------------------------------------------------------------ */
ULONG64 ss_foa_to_rva(const BYTE* pFile, ULONG64 foa)
{
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pFile;
    if (dos->e_magic != 0x5A4D) {
        return 0;
    }

    const IMAGE_NT_HEADERS64* nt64 =
        (const IMAGE_NT_HEADERS64*)(pFile + dos->e_lfanew);
    if (nt64->Signature != 0x4550) {
        return 0;
    }

    const IMAGE_SECTION_HEADER* secHdr =
        (const IMAGE_SECTION_HEADER*)((ULONG_PTR)nt64 + sizeof(IMAGE_NT_HEADERS64));

    for (ULONG i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
        if (foa >= secHdr->PointerToRawData &&
            foa < (ULONG64)secHdr->PointerToRawData + secHdr->SizeOfRawData) {
            return (ULONG64)secHdr->VirtualAddress + (foa - secHdr->PointerToRawData);
        }
        secHdr++;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * 原 GetPeImageInfo（生产路径未使用，保留等价语义）
 * ------------------------------------------------------------------ */
BOOL ss_get_pe_image_info(const BYTE* pDump, ULONG64* preferredImageBase, ULONG* sizeOfImage)
{
    *preferredImageBase = 0;
    *sizeOfImage = 0;

    if (pDump == NULL) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550) {
        return FALSE;
    }

    *preferredImageBase = (ULONG64)nt64->OptionalHeader.ImageBase;
    *sizeOfImage = nt64->OptionalHeader.SizeOfImage;

    return (*preferredImageBase != 0) && (*sizeOfImage != 0);
}

/* ------------------------------------------------------------------
 * 原 GetImageEntryPointRVA
 *
 * 相对 VB 版补了两个文件长度上界检查：原实现直接解引用 dos->e_lfanew 偏移，
 * 在截断镜像上会越界读。上界检查不改变良构镜像上的判定结果。
 * ------------------------------------------------------------------ */
BOOL ss_get_image_entry_point_rva(const BYTE* pDump, ULONG64 fileSize, ULONG* outEntryRva)
{
    *outEntryRva = 0;

    if (pDump == NULL) {
        return FALSE;
    }
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((ULONG64)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550 || nt64->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    *outEntryRva = nt64->OptionalHeader.AddressOfEntryPoint;
    return TRUE;
}

/* ------------------------------------------------------------------
 * 原 GetRuntimeFunctionBounds（.pdata / RUNTIME_FUNCTION）
 * ------------------------------------------------------------------ */
BOOL ss_get_runtime_function_bounds(const BYTE* pDump, ULONG64 fileSize, ULONG functionRva,
                                    ULONG* beginRva, ULONG* endRva)
{
    const ULONG IMAGE_DIRECTORY_ENTRY_EXCEPTION_INDEX = 3;
    const ULONG RUNTIME_FUNCTION_SIZE = 12;

    *beginRva = 0;
    *endRva = 0;

    if (pDump == NULL || fileSize == 0 || functionRva == 0) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((ULONG64)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550 || nt64->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    ULONG exceptionRva =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION_INDEX].VirtualAddress;
    ULONG exceptionSize =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION_INDEX].Size;

    if (exceptionRva == 0 || exceptionSize < RUNTIME_FUNCTION_SIZE) {
        return FALSE;
    }

    ULONG entryCount = exceptionSize / RUNTIME_FUNCTION_SIZE;

    for (ULONG i = 0; i < entryCount; i++) {
        INT64 entryRva64 = (INT64)exceptionRva + (INT64)i * RUNTIME_FUNCTION_SIZE;

        if (entryRva64 <= 0 || entryRva64 > 0xFFFFFFFFLL) {
            break;
        }

        ULONG currentBegin = 0;
        ULONG currentEnd = 0;

        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)entryRva64, &currentBegin)) {
            continue;
        }
        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)entryRva64 + 4, &currentEnd)) {
            continue;
        }

        if (currentBegin == 0 || currentEnd <= currentBegin) {
            continue;
        }

        if (functionRva >= currentBegin && functionRva < currentEnd) {
            *beginRva = currentBegin;
            *endRva = currentEnd;
            return TRUE;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 IsRvaExecutable
 * ------------------------------------------------------------------ */
BOOL ss_is_rva_executable(const BYTE* pDump, ULONG64 rva)
{
    if (pDump == NULL) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550) {
        return FALSE;
    }

    const IMAGE_SECTION_HEADER* secHdr =
        (const IMAGE_SECTION_HEADER*)((ULONG_PTR)nt64 + sizeof(IMAGE_NT_HEADERS64));

    for (ULONG i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
        ULONG sectionSize = secHdr->Misc.VirtualSize;
        if (sectionSize < secHdr->SizeOfRawData) {
            sectionSize = secHdr->SizeOfRawData;
        }
        if (rva >= secHdr->VirtualAddress &&
            rva < (ULONG64)secHdr->VirtualAddress + sectionSize) {
            return (secHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
        secHdr++;
    }

    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 LoadDispatchModuleContext
 *
 * 结构性差异（有意）：VB 版自行 GetKernelModuleBase + 拼路径 + 读文件；
 * Core 版只做 PE 校验，模块基址与镜像字节全部来自宿主回调。
 * 校验顺序与拒绝条件与原实现保持一致。
 * ------------------------------------------------------------------ */
BOOL ss_load_dispatch_module_context(const SS_SCAN_CONTEXT* callerCtx,
                                     const WCHAR* moduleName,
                                     SS_SCAN_CONTEXT* outContext)
{
    memset(outContext, 0, sizeof(*outContext));

    if (moduleName == NULL || moduleName[0] == L'\0') {
        return FALSE;
    }

    if (callerCtx == NULL || callerCtx->loadModule == NULL) {
        ss_log_ctx(callerCtx, "LoadDispatchModuleContext",
                   "[REJECT] No module loader callback Module=%ws", moduleName);
        return FALSE;
    }

    SS_MODULE_IMAGE image = { 0 };
    if (!callerCtx->loadModule(moduleName, callerCtx->loadModuleContext, &image)) {
        ss_log_ctx(callerCtx, "LoadDispatchModuleContext",
                   "[REJECT] Module is not loaded Module=%ws", moduleName);
        return FALSE;
    }

    if (image.buffer == NULL || image.imageBase == 0) {
        ss_log_ctx(callerCtx, "LoadDispatchModuleContext",
                   "[REJECT] Module is not loaded Module=%ws", moduleName);
        return FALSE;
    }

    if (image.size < sizeof(IMAGE_DOS_HEADER) || image.size > 0xFFFFFFFFULL) {
        return FALSE;
    }

    const BYTE* pDump = image.buffer;
    ULONG64 fileSize = image.size;

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0 ||
        (INT64)dos->e_lfanew + (INT64)sizeof(IMAGE_NT_HEADERS64) > (INT64)fileSize) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550 || nt64->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    outContext->pDump = pDump;
    outContext->fileSize = fileSize;
    outContext->imageBase = image.imageBase;
    wcscpy_s(outContext->moduleName, SS_MODULE_NAME_MAX, moduleName);

    /* 传播宿主回调，使跨模块扫描可以从被加载模块再递归跨模块 */
    outContext->loadModule = callerCtx->loadModule;
    outContext->loadModuleContext = callerCtx->loadModuleContext;
    outContext->logSink = callerCtx->logSink;
    outContext->logContext = callerCtx->logContext;

    ss_log_ctx(callerCtx, "LoadDispatchModuleContext",
               "[LOAD] Module=%ws ImageBase=0x%llX FileSize=0x%llX",
               moduleName, image.imageBase, fileSize);

    return TRUE;
}

/* ------------------------------------------------------------------
 * 原 ResolveImportByIatRva
 * ------------------------------------------------------------------ */
BOOL ss_resolve_import_by_iat_rva(const BYTE* pDump, ULONG64 fileSize, ULONG64 iatRva,
                                  SS_IMPORT_TARGET* target)
{
    const ULONG IMAGE_DIRECTORY_ENTRY_IMPORT_INDEX = 1;
    const ULONG IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;
    const ULONG64 IMAGE_THUNK_SIZE = 8;
    const ULONG64 IMAGE_ORDINAL_FLAG64_VALUE = 0x8000000000000000ULL;

    memset(target, 0, sizeof(*target));

    if (pDump == NULL || fileSize == 0 || iatRva == 0) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((INT64)dos->e_lfanew + (INT64)sizeof(IMAGE_NT_HEADERS64) > (INT64)fileSize) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550 || nt64->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    ULONG importRva =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT_INDEX].VirtualAddress;
    ULONG importSize =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT_INDEX].Size;

    if (importRva == 0 || importSize < IMAGE_IMPORT_DESCRIPTOR_SIZE) {
        return FALSE;
    }

    INT64 importEnd64 = (INT64)importRva + (INT64)importSize;
    if (importEnd64 <= (INT64)importRva || importEnd64 > 0xFFFFFFFFLL) {
        return FALSE;
    }

    ULONG descriptorRva = importRva;

    while ((INT64)descriptorRva + IMAGE_IMPORT_DESCRIPTOR_SIZE <= importEnd64) {
        ULONG originalFirstThunk = 0;
        ULONG timeDateStamp = 0;
        ULONG forwarderChain = 0;
        ULONG nameRva = 0;
        ULONG firstThunk = 0;

        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)descriptorRva + 0, &originalFirstThunk)) break;
        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)descriptorRva + 4, &timeDateStamp)) break;
        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)descriptorRva + 8, &forwarderChain)) break;
        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)descriptorRva + 12, &nameRva)) break;
        if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)descriptorRva + 16, &firstThunk)) break;

        if (originalFirstThunk == 0 && timeDateStamp == 0 && forwarderChain == 0 &&
            nameRva == 0 && firstThunk == 0) {
            break;
        }

        if (nameRva != 0 && firstThunk != 0) {
            WCHAR moduleName[260];
            BOOL haveName = FALSE;

            /* 原实现这里得到的是 ANSI 字符串并赋给 VB String；这里转成宽字符以统一内部比较 */
            {
                char asciiName[SS_MAX_PE_STRING_LENGTH + 1];
                if (ss_read_ascii_string_by_rva(pDump, fileSize, nameRva,
                                                asciiName, sizeof(asciiName))) {
                    MultiByteToWideChar(CP_ACP, 0, asciiName, -1, moduleName, 260);
                    haveName = TRUE;
                }
            }

            if (haveName) {
                ULONG64 lookupThunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
                ULONG64 thunkIndex = 0;

                for (;;) {
                    INT64 lookupRva64 = (INT64)lookupThunkRva + (INT64)thunkIndex * (INT64)IMAGE_THUNK_SIZE;
                    INT64 currentIatRva64 = (INT64)firstThunk + (INT64)thunkIndex * (INT64)IMAGE_THUNK_SIZE;

                    if (lookupRva64 <= 0 || lookupRva64 > 0xFFFFFFFFLL ||
                        currentIatRva64 <= 0 || currentIatRva64 > 0xFFFFFFFFLL) {
                        break;
                    }

                    ULONG64 thunkValue = 0;
                    if (!ss_read_raw_rva_qword(pDump, fileSize, (ULONG64)lookupRva64, &thunkValue)) {
                        break;
                    }
                    if (thunkValue == 0) {
                        break;
                    }

                    if ((ULONG64)currentIatRva64 == iatRva) {
                        wcscpy_s(target->moduleName, 260, moduleName);

                        if ((thunkValue & IMAGE_ORDINAL_FLAG64_VALUE) != 0) {
                            target->byOrdinal = TRUE;
                            target->ordinal = (ULONG)(thunkValue & 0xFFFFULL);
                            target->functionName[0] = '\0';
                        } else {
                            if (thunkValue > 0xFFFFFFFFULL) {
                                return FALSE;
                            }

                            ULONG importByNameRva = (ULONG)thunkValue;

                            /* IMAGE_IMPORT_BY_NAME: +0 USHORT Hint, +2 CHAR Name[] */
                            if (!ss_read_ascii_string_by_rva(pDump, fileSize,
                                                             (ULONG64)importByNameRva + 2,
                                                             target->functionName,
                                                             sizeof(target->functionName))) {
                                return FALSE;
                            }

                            if (target->functionName[0] == '\0') {
                                return FALSE;
                            }

                            target->byOrdinal = FALSE;
                            target->ordinal = 0;
                        }

                        target->valid = TRUE;

                        ss_log_ctx(NULL, "ResolveImportByIatRva",
                                   "[MATCH] IatRVA=0x%llX Module=%ws Function=%s Ordinal=%u ByOrdinal=%d",
                                   iatRva, target->moduleName, target->functionName,
                                   target->ordinal, (int)target->byOrdinal);

                        return TRUE;
                    }

                    thunkIndex++;

                    if (thunkIndex > 0x10000) {
                        break;
                    }
                }
            }
        }

        descriptorRva += IMAGE_IMPORT_DESCRIPTOR_SIZE;
    }

    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 ResolveExportRva
 * ------------------------------------------------------------------ */
BOOL ss_resolve_export_rva(const BYTE* pDump, ULONG64 fileSize,
                           const char* functionName, ULONG ordinal, BOOL byOrdinal,
                           ULONG* functionRva)
{
    const ULONG IMAGE_DIRECTORY_ENTRY_EXPORT_INDEX = 0;

    *functionRva = 0;

    if (pDump == NULL || fileSize == 0) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pDump;
    if (dos->e_magic != 0x5A4D) {
        return FALSE;
    }
    if (dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((INT64)dos->e_lfanew + (INT64)sizeof(IMAGE_NT_HEADERS64) > (INT64)fileSize) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)(pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550 || nt64->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    ULONG exportRva =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_INDEX].VirtualAddress;
    ULONG exportSize =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_INDEX].Size;

    if (exportRva == 0 || exportSize < 40) {
        return FALSE;
    }

    ULONG ordinalBase = 0;
    ULONG numberOfFunctions = 0;
    ULONG numberOfNames = 0;
    ULONG addressOfFunctions = 0;
    ULONG addressOfNames = 0;
    ULONG addressOfNameOrdinals = 0;

    if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)exportRva + 16, &ordinalBase)) return FALSE;
    if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)exportRva + 20, &numberOfFunctions)) return FALSE;
    if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)exportRva + 24, &numberOfNames)) return FALSE;
    if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)exportRva + 28, &addressOfFunctions)) return FALSE;
    if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)exportRva + 32, &addressOfNames)) return FALSE;
    if (!ss_read_raw_rva_dword(pDump, fileSize, (ULONG64)exportRva + 36, &addressOfNameOrdinals)) return FALSE;

    if (numberOfFunctions == 0 || addressOfFunctions == 0) {
        return FALSE;
    }

    ULONG functionIndex = 0xFFFFFFFF;

    if (byOrdinal) {
        if (ordinal < ordinalBase) {
            return FALSE;
        }

        INT64 ordinalIndex64 = (INT64)ordinal - (INT64)ordinalBase;
        if (ordinalIndex64 < 0 || ordinalIndex64 >= (INT64)numberOfFunctions) {
            return FALSE;
        }

        functionIndex = (ULONG)ordinalIndex64;
    } else {
        if (functionName == NULL || functionName[0] == '\0' ||
            numberOfNames == 0 || addressOfNames == 0 || addressOfNameOrdinals == 0) {
            return FALSE;
        }

        for (ULONG i = 0; i < numberOfNames; i++) {
            ULONG exportNameRva = 0;

            if (!ss_read_raw_rva_dword(pDump, fileSize,
                                       (ULONG64)addressOfNames + (ULONG64)i * 4, &exportNameRva)) {
                continue;
            }

            char exportName[SS_MAX_PE_STRING_LENGTH + 1];
            if (!ss_read_ascii_string_by_rva(pDump, fileSize, exportNameRva,
                                             exportName, sizeof(exportName))) {
                continue;
            }

            if (strcmp(exportName, functionName) == 0) {
                USHORT ordinalIndex = 0;

                if (!ss_read_raw_rva_word(pDump, fileSize,
                                          (ULONG64)addressOfNameOrdinals + (ULONG64)i * 2,
                                          &ordinalIndex)) {
                    return FALSE;
                }

                if (ordinalIndex >= numberOfFunctions) {
                    return FALSE;
                }

                functionIndex = ordinalIndex;
                break;
            }
        }

        if (functionIndex == 0xFFFFFFFF) {
            return FALSE;
        }
    }

    ULONG targetRva = 0;
    if (!ss_read_raw_rva_dword(pDump, fileSize,
                               (ULONG64)addressOfFunctions + (ULONG64)functionIndex * 4,
                               &targetRva)) {
        return FALSE;
    }

    if (targetRva == 0) {
        return FALSE;
    }

    /* 指向 Export Directory 自身范围内 => forwarder 字符串，不是代码 */
    INT64 exportEnd64 = (INT64)exportRva + (INT64)exportSize;
    if ((INT64)targetRva >= (INT64)exportRva && (INT64)targetRva < exportEnd64) {
        char forwarder[SS_MAX_PE_STRING_LENGTH + 1];
        forwarder[0] = '\0';
        ss_read_ascii_string_by_rva(pDump, fileSize, targetRva, forwarder, sizeof(forwarder));

        ss_log_ctx(NULL, "ResolveExportRva",
                   "[REJECT] Forwarded export Function=%s Ordinal=%u Forwarder=%s",
                   functionName ? functionName : "(ordinal)", ordinal, forwarder);

        return FALSE;
    }

    if (ss_rva_to_foa(pDump, targetRva) == 0) {
        return FALSE;
    }

    *functionRva = targetRva;

    ss_log_ctx(NULL, "ResolveExportRva",
               "[MATCH] Function=%s Ordinal=%u RVA=0x%X",
               functionName ? functionName : "(ordinal)", ordinal, *functionRva);

    return TRUE;
}

/* ------------------------------------------------------------------
 * 原 GetPeImageLayout（硬编码偏移解析，供指针归一化使用）
 * ------------------------------------------------------------------ */
BOOL ss_get_image_layout(const BYTE* pDump, ULONG64 fileSize,
                         ULONG64* preferredImageBase, ULONG* sizeOfImage)
{
    *preferredImageBase = 0;
    *sizeOfImage = 0;

    if (pDump == NULL || fileSize < 0x100) {
        return FALSE;
    }
    if (*(const USHORT*)pDump != 0x5A4D) {
        return FALSE;
    }

    ULONG ntOffset = *(const ULONG*)(pDump + 0x3C);

    if ((ULONG64)ntOffset > fileSize - 0x58) {
        return FALSE;
    }
    if (*(const ULONG*)(pDump + ntOffset) != 0x4550) {
        return FALSE;
    }
    /* OptionalHeader.Magic == PE32+ (0x20B) */
    if (*(const USHORT*)(pDump + ntOffset + 0x18) != 0x20B) {
        return FALSE;
    }

    *preferredImageBase = *(const ULONG64*)(pDump + ntOffset + 0x30);
    *sizeOfImage = *(const ULONG*)(pDump + ntOffset + 0x50);

    return (*preferredImageBase != 0 && *sizeOfImage != 0);
}

/* ------------------------------------------------------------------
 * 原 NormalizeImagePointerToRva
 *
 * 依次尝试：当作 RVA；当作 preferred image base 绝对地址；当作运行时基址绝对地址。
 * ------------------------------------------------------------------ */
static BOOL ss_normalize_image_pointer_to_rva(const SS_SCAN_CONTEXT* context,
                                              ULONG64 rawValue, ULONG* outRva)
{
    *outRva = 0;

    ULONG64 preferredBase = 0;
    ULONG sizeOfImage = 0;

    if (!ss_get_image_layout(context->pDump, context->fileSize, &preferredBase, &sizeOfImage)) {
        return FALSE;
    }

    if (rawValue < sizeOfImage) {
        ULONG candidate = (ULONG)rawValue;
        if (ss_rva_to_foa(context->pDump, candidate) != 0) {
            *outRva = candidate;
            return TRUE;
        }
    }

    if (rawValue >= preferredBase && rawValue - preferredBase < sizeOfImage) {
        ULONG candidate = (ULONG)(rawValue - preferredBase);
        if (ss_rva_to_foa(context->pDump, candidate) != 0) {
            *outRva = candidate;
            return TRUE;
        }
    }

    ULONG64 runtimeBase = context->imageBase;
    if (runtimeBase != 0 && rawValue >= runtimeBase && rawValue - runtimeBase < sizeOfImage) {
        ULONG candidate = (ULONG)(rawValue - runtimeBase);
        if (ss_rva_to_foa(context->pDump, candidate) != 0) {
            *outRva = candidate;
            return TRUE;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------
 * 原 ReadImagePointerRva
 * ------------------------------------------------------------------ */
BOOL ss_read_image_pointer_rva(const SS_SCAN_CONTEXT* context, ULONG slotRva, ULONG* outRva)
{
    *outRva = 0;

    if (context->pDump == NULL || context->fileSize < 8) {
        return FALSE;
    }
    if (context->fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)context->pDump;
    if (dos->e_magic != 0x5A4D || dos->e_lfanew <= 0) {
        return FALSE;
    }
    if ((INT64)dos->e_lfanew + (INT64)sizeof(IMAGE_NT_HEADERS64) > (INT64)context->fileSize) {
        return FALSE;
    }

    const IMAGE_NT_HEADERS64* nt64 =
        (const IMAGE_NT_HEADERS64*)(context->pDump + dos->e_lfanew);
    if (nt64->Signature != 0x4550 || nt64->FileHeader.Machine != 0x8664) {
        return FALSE;
    }

    ULONG64 sectionTable = (ULONG64)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    ULONG sectionCount = nt64->FileHeader.NumberOfSections;
    if (sectionCount == 0 || sectionCount > 96) {
        return FALSE;
    }
    if (sectionTable > context->fileSize ||
        (ULONG64)sectionCount * sizeof(IMAGE_SECTION_HEADER) > context->fileSize - sectionTable) {
        return FALSE;
    }

    ULONG64 slotFoa = 0;
    const IMAGE_SECTION_HEADER* sections =
        (const IMAGE_SECTION_HEADER*)(context->pDump + sectionTable);

    for (ULONG i = 0; i < sectionCount; i++) {
        const IMAGE_SECTION_HEADER* section = &sections[i];
        if (slotRva < section->VirtualAddress) {
            continue;
        }
        ULONG rawOffset = slotRva - section->VirtualAddress;
        if (section->SizeOfRawData < 8 || rawOffset > section->SizeOfRawData - 8) {
            continue;
        }
        if (section->PointerToRawData > context->fileSize ||
            rawOffset + 8 > context->fileSize - section->PointerToRawData) {
            continue;
        }
        slotFoa = (ULONG64)section->PointerToRawData + rawOffset;
        break;
    }

    if (slotFoa == 0) {
        return FALSE;
    }

    ULONG64 rawValue = *(const ULONG64*)(context->pDump + slotFoa);
    if (rawValue == 0) {
        return FALSE;
    }

    return ss_normalize_image_pointer_to_rva(context, rawValue, outRva);
}
