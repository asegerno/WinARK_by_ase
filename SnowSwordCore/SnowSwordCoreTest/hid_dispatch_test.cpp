/*
 * hid_dispatch_test.cpp -- HID 框架派遣覆盖（HIDCLASS.SYS!HidRegisterMinidriver）离线测试
 *
 * 背景（T1 地面真值，见 artifacts/dispatch/20261005-hid-*）：
 *   mshidkmdf.sys / mshidumdf.sys 的 DriverEntry 先自填 28 个 MajorFunction 槽，
 *   随后 call qword ptr [IAT] 进入 HIDCLASS.SYS!HidRegisterMinidriver；该函数在
 *   返回前把 9 个槽改写成 hidclass 自己的 handler：
 *     {0,2,3,4,14,15,22,23,27}
 *   因此 T1（DriverEntry 返回后）的「原始派遣」对这 9 个槽应属 hidclass.sys，
 *   而不是驱动自身的 DriverEntry 中间态。
 *
 * 本测试全部走生产入口（SS_RecoverDispatchFromImage / SS_DispatchRecoverFlat），
 * 并提供可用的 loadModule 回调（HID 语义恢复必须能加载 hidclass.sys）。
 * 夹具是自造的极小 PE（可执行 .text + .rdata + .data，导入/导出表，
 * 固定 RVA），因此断言里的 handler RVA 是夹具自有的常量，与机器无关。
 *
 * 运行：
 *   SnowSwordCoreTest.exe --verify-hid        夹具测试 + 真实 PE（mshidkmdf/mshidumdf）
 *   SnowSwordCoreTest.exe --scan-hid <image>  真实 PE 逐槽打印（无需提权）
 *       hidclass.sys 用合成固定基址；其它被导入模块按 System32\drivers 磁盘镜像加载，
 *       基址也是合成值，因此 disk.sys -> classpnp.sys 这类跨模块样本可离线核对
 *       （只比 (模块名, RVA)，不比运行时光址）。
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>
#include "../dispatch.h"

#pragma comment(lib, "bcrypt.lib")

/* ==================================================================
 * 0. 检查框架
 * ================================================================== */
static int g_checks = 0;
static int g_failures = 0;
static int g_skips = 0;
static const char* g_caseName = "";

static void CheckTrue(BOOL ok, const char* format, ...)
{
    char message[512];
    va_list args;

    g_checks += 1;

    va_start(args, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    va_end(args);
    message[sizeof(message) - 1] = '\0';

    if (!ok) {
        g_failures += 1;
        printf("  [FAIL] %s: %s\n", g_caseName, message);
    }
}

/* ==================================================================
 * 1. 最小 PE 构造器（固定三节布局）
 *
 *    .text   RVA 0x1000 / FOA 0x0200 / RX
 *    .rdata  RVA 0x2000 / FOA 0x1200 / R
 *    .data   RVA 0x3000 / FOA 0x2200 / RW
 *
 *    导出表与导入表都放在 .rdata 起始处 0x2000（同一夹具二选一使用）。
 * ================================================================== */
#define FIX_TEXT_RVA      0x1000UL
#define FIX_RDATA_RVA     0x2000UL
#define FIX_DATA_RVA      0x3000UL
#define FIX_TEXT_FOA      0x0200UL
#define FIX_RDATA_FOA     0x1200UL
#define FIX_DATA_FOA      0x2200UL
#define FIX_SECT_RAW      0x1000UL
#define FIX_FILE_SIZE     (FIX_DATA_FOA + FIX_SECT_RAW)
#define FIX_SIZE_OF_IMAGE 0x4000UL
#define FIX_PE_IMAGE_BASE 0x0000000140000000ULL

/* “hidclass.sys” 风格外部镜像内的固定 RVA */
#define FIX_HID_FUNC_RVA    (FIX_TEXT_RVA)              /* 0x1000 导出函数入口 */
#define FIX_HID_HANDLER_A   (FIX_TEXT_RVA + 0x100)      /* 0x1100 可执行 handler */
#define FIX_HID_HANDLER_B   (FIX_TEXT_RVA + 0x140)      /* 0x1140 可执行 handler */
#define FIX_HID_NONEXEC_RVA (FIX_RDATA_RVA + 0x100)     /* 0x2100 不可执行 */

/* minidriver 风格主镜像内的固定 RVA */
#define FIX_MAIN_ENTRY_RVA  (FIX_TEXT_RVA)
#define FIX_MAIN_SELF_RVA   (FIX_TEXT_RVA + 0x100)

/* .rdata 固定布局 */
#define FIX_RDATA_EXPORT     (FIX_RDATA_RVA + 0x000)
#define FIX_RDATA_EXP_FUNCS  (FIX_RDATA_RVA + 0x040)
#define FIX_RDATA_EXP_NAMES  (FIX_RDATA_RVA + 0x044)
#define FIX_RDATA_EXP_ORDS   (FIX_RDATA_RVA + 0x048)
#define FIX_RDATA_EXP_NAME   (FIX_RDATA_RVA + 0x060)
#define FIX_RDATA_EXP_DLL    (FIX_RDATA_RVA + 0x080)
#define FIX_RDATA_EXPORT_SIZE 0x100UL

#define FIX_RDATA_IMPORT     (FIX_RDATA_RVA + 0x000)
#define FIX_RDATA_ILT        (FIX_RDATA_RVA + 0x100)
#define FIX_RDATA_IAT        (FIX_RDATA_RVA + 0x140)
#define FIX_RDATA_IMPN       (FIX_RDATA_RVA + 0x180)
#define FIX_RDATA_IMPDLL     (FIX_RDATA_RVA + 0x1C0)
#define FIX_RDATA_IMPORT_SIZE 40UL

typedef struct _FIX_IMAGE {
    BYTE  bytes[FIX_FILE_SIZE];
    ULONG size;
} FIX_IMAGE;

static BYTE* FixSecPtr(FIX_IMAGE* img, ULONG rva)
{
    ULONG foa = 0;

    if (rva >= FIX_TEXT_RVA && rva < FIX_TEXT_RVA + FIX_SECT_RAW) {
        foa = FIX_TEXT_FOA + (rva - FIX_TEXT_RVA);
    } else if (rva >= FIX_RDATA_RVA && rva < FIX_RDATA_RVA + FIX_SECT_RAW) {
        foa = FIX_RDATA_FOA + (rva - FIX_RDATA_RVA);
    } else if (rva >= FIX_DATA_RVA && rva < FIX_DATA_RVA + FIX_SECT_RAW) {
        foa = FIX_DATA_FOA + (rva - FIX_DATA_RVA);
    }

    if (foa == 0 || foa >= img->size) {
        return NULL;
    }
    return img->bytes + foa;
}

static void FixPutU16(BYTE* p, USHORT v) { memcpy(p, &v, 2); }
static void FixPutU32(BYTE* p, ULONG v) { memcpy(p, &v, 4); }
static void FixPutU64(BYTE* p, ULONG64 v) { memcpy(p, &v, 8); }

static void FixInitImage(FIX_IMAGE* img, ULONG entryRva, ULONG exportRva, ULONG exportSize,
                         ULONG importRva, ULONG importSize)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_SECTION_HEADER* sec;

    memset(img, 0, sizeof(*img));
    img->size = FIX_FILE_SIZE;

    dos = (IMAGE_DOS_HEADER*)img->bytes;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x80;

    nt = (IMAGE_NT_HEADERS64*)(img->bytes + 0x80);
    nt->Signature = 0x4550;
    nt->FileHeader.Machine = 0x8664;
    nt->FileHeader.NumberOfSections = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = 0x2022;

    nt->OptionalHeader.Magic = 0x20B;
    nt->OptionalHeader.AddressOfEntryPoint = entryRva;
    nt->OptionalHeader.BaseOfCode = FIX_TEXT_RVA;
    nt->OptionalHeader.ImageBase = FIX_PE_IMAGE_BASE;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 10;
    nt->OptionalHeader.SizeOfImage = FIX_SIZE_OF_IMAGE;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.Subsystem = 1;              /* native */
    nt->OptionalHeader.DllCharacteristics = 0x160;
    nt->OptionalHeader.SizeOfStackReserve = 0x100000;
    nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    nt->OptionalHeader.SizeOfHeapReserve = 0x100000;
    nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = 16;
    nt->OptionalHeader.DataDirectory[0].VirtualAddress = exportRva;
    nt->OptionalHeader.DataDirectory[0].Size = exportSize;
    nt->OptionalHeader.DataDirectory[1].VirtualAddress = importRva;
    nt->OptionalHeader.DataDirectory[1].Size = importSize;

    sec = (IMAGE_SECTION_HEADER*)((BYTE*)nt + sizeof(IMAGE_NT_HEADERS64));

    memcpy(sec[0].Name, ".text", 6);
    sec[0].Misc.VirtualSize = FIX_SECT_RAW;
    sec[0].VirtualAddress = FIX_TEXT_RVA;
    sec[0].SizeOfRawData = FIX_SECT_RAW;
    sec[0].PointerToRawData = FIX_TEXT_FOA;
    sec[0].Characteristics = 0x60000020;           /* CODE | EXECUTE | READ */

    memcpy(sec[1].Name, ".rdata", 7);
    sec[1].Misc.VirtualSize = FIX_SECT_RAW;
    sec[1].VirtualAddress = FIX_RDATA_RVA;
    sec[1].SizeOfRawData = FIX_SECT_RAW;
    sec[1].PointerToRawData = FIX_RDATA_FOA;
    sec[1].Characteristics = 0x40000040;           /* INITIALIZED_DATA | READ */

    memcpy(sec[2].Name, ".data", 6);
    sec[2].Misc.VirtualSize = FIX_SECT_RAW;
    sec[2].VirtualAddress = FIX_DATA_RVA;
    sec[2].SizeOfRawData = FIX_SECT_RAW;
    sec[2].PointerToRawData = FIX_DATA_FOA;
    sec[2].Characteristics = 0xC0000040;           /* INITIALIZED_DATA | READ | WRITE */
}

static void FixWriteExport(FIX_IMAGE* img, const char* dllName, const char* functionName,
                           ULONG functionRva)
{
    BYTE* dir = FixSecPtr(img, FIX_RDATA_EXPORT);

    FixPutU32(dir + 4, 0);                         /* TimeDateStamp */
    FixPutU32(dir + 12, FIX_RDATA_EXP_DLL);        /* Name */
    FixPutU32(dir + 16, 1);                        /* Base */
    FixPutU32(dir + 20, 1);                        /* NumberOfFunctions */
    FixPutU32(dir + 24, 1);                        /* NumberOfNames */
    FixPutU32(dir + 28, FIX_RDATA_EXP_FUNCS);
    FixPutU32(dir + 32, FIX_RDATA_EXP_NAMES);
    FixPutU32(dir + 36, FIX_RDATA_EXP_ORDS);

    FixPutU32(FixSecPtr(img, FIX_RDATA_EXP_FUNCS), functionRva);
    FixPutU32(FixSecPtr(img, FIX_RDATA_EXP_NAMES), FIX_RDATA_EXP_NAME);
    FixPutU16(FixSecPtr(img, FIX_RDATA_EXP_ORDS), 0);

    strcpy_s((char*)FixSecPtr(img, FIX_RDATA_EXP_NAME), 64, functionName);
    strcpy_s((char*)FixSecPtr(img, FIX_RDATA_EXP_DLL), 64, dllName);
}

static void FixWriteImport(FIX_IMAGE* img, const char* dllName, const char* functionName)
{
    BYTE* desc = FixSecPtr(img, FIX_RDATA_IMPORT);

    FixPutU32(desc + 0, FIX_RDATA_ILT);            /* OriginalFirstThunk */
    FixPutU32(desc + 12, FIX_RDATA_IMPDLL);        /* Name */
    FixPutU32(desc + 16, FIX_RDATA_IAT);           /* FirstThunk —— call [rip+x] 的目标 */

    FixPutU64(FixSecPtr(img, FIX_RDATA_ILT), FIX_RDATA_IMPN);
    FixPutU64(FixSecPtr(img, FIX_RDATA_ILT + 8), 0);
    FixPutU64(FixSecPtr(img, FIX_RDATA_IAT), 0);
    FixPutU64(FixSecPtr(img, FIX_RDATA_IAT + 8), 0);

    FixPutU16(FixSecPtr(img, FIX_RDATA_IMPN), 0);  /* Hint */
    strcpy_s((char*)FixSecPtr(img, FIX_RDATA_IMPN + 2), 64, functionName);
    strcpy_s((char*)FixSecPtr(img, FIX_RDATA_IMPDLL), 64, dllName);
}

/* ---- 极简 x64 发射器（只发射本夹具需要的形状） ---- */
typedef struct _EMIT {
    FIX_IMAGE* img;
    ULONG      rva;
    BYTE*      p;
    ULONG      len;
} EMIT;

static void EmInit(EMIT* e, FIX_IMAGE* img, ULONG rva)
{
    e->img = img;
    e->rva = rva;
    e->p = FixSecPtr(img, rva);
    e->len = 0;
}

static void EmRaw(EMIT* e, const BYTE* bytes, ULONG count)
{
    memcpy(e->p + e->len, bytes, count);
    e->len += count;
}

static void EmU32(EMIT* e, ULONG value)
{
    memcpy(e->p + e->len, &value, 4);
    e->len += 4;
}

static void EmRip32(EMIT* e, ULONG targetRva)
{
    INT32 disp = (INT32)((INT64)targetRva - (INT64)(e->rva + e->len + 4));
    memcpy(e->p + e->len, &disp, 4);
    e->len += 4;
}

static void EmLeaRaxRip(EMIT* e, ULONG targetRva)      /* lea rax,[rip+target] */
{
    static const BYTE op[3] = { 0x48, 0x8D, 0x05 };
    EmRaw(e, op, 3);
    EmRip32(e, targetRva);
}

static void EmCallRip(EMIT* e, ULONG targetRva)        /* call qword ptr [rip+target] */
{
    static const BYTE op[2] = { 0xFF, 0x15 };
    EmRaw(e, op, 2);
    EmRip32(e, targetRva);
}

static void EmMovR14DispRax(EMIT* e, ULONG disp)       /* mov [r14+disp],rax */
{
    static const BYTE op[3] = { 0x49, 0x89, 0x86 };
    EmRaw(e, op, 3);
    EmU32(e, disp);
}

static void EmMovR8DispRax(EMIT* e, ULONG disp)        /* mov [r8+disp],rax */
{
    static const BYTE op[3] = { 0x49, 0x89, 0x80 };
    EmRaw(e, op, 3);
    EmU32(e, disp);
}

static void EmMovR8Rax(EMIT* e)                        /* mov [r8],rax —— slot 0 形式 */
{
    static const BYTE op[3] = { 0x49, 0x89, 0x00 };
    EmRaw(e, op, 3);
}

static void EmMovRcxDispRax(EMIT* e, ULONG disp)       /* mov [rcx+disp],rax */
{
    static const BYTE op[3] = { 0x48, 0x89, 0x81 };
    EmRaw(e, op, 3);
    EmU32(e, disp);
}

static void EmLeaR14RcxPlus8(EMIT* e)                  /* lea r14,[rcx+8] —— 真实形状 */
{
    static const BYTE op[4] = { 0x4C, 0x8D, 0x71, 0x08 };
    EmRaw(e, op, 4);
}

static void EmMovR14R14Deref(EMIT* e)                  /* mov r14,[r14] —— registration->DriverObject */
{
    static const BYTE op[3] = { 0x4D, 0x8B, 0x36 };
    EmRaw(e, op, 3);
}

static void EmLeaR8R14Disp(EMIT* e, ULONG disp)        /* lea r8,[r14+disp] */
{
    static const BYTE op[3] = { 0x4D, 0x8D, 0x86 };
    EmRaw(e, op, 3);
    EmU32(e, disp);
}

static void EmMovR14Rbx(EMIT* e)                       /* mov r14,rbx —— 覆盖 provenance */
{
    static const BYTE op[3] = { 0x4C, 0x89, 0xDE };
    EmRaw(e, op, 3);
}

static void EmRet(EMIT* e)
{
    static const BYTE op[1] = { 0xC3 };
    EmRaw(e, op, 1);
}

/* ==================================================================
 * 2. 夹具变体
 * ================================================================== */
enum {
    HID_BODY_REAL_SHAPE = 0,   /* 1 个 lea + 9 个 store（真实 HIDCLASS 形状，含 mov [r8],rax） */
    HID_BODY_MULTI_STORE,      /* 1 个 lea + 3 个 store：handler 不得被首次 store 消费 */
    HID_BODY_SLOT0_BASE,       /* DriverObject+0x70 派生基址 r8 继续传播 */
    HID_BODY_DISP_EDGE,        /* disp 0x70/0x148 接受，0x68/0x150 拒绝 */
    HID_BODY_TWO_HANDLERS,     /* 两个 handler 各自服务多个槽，不串值 */
    HID_BODY_NONEXEC_HANDLER,  /* lea 指向不可执行区 */
    HID_BODY_LOST_PROVENANCE,  /* DriverObject provenance 被覆盖 */
    HID_BODY_GENERIC_WRITER,   /* 以 DriverObject 为入口的普通跨模块写入（非 HID 特判） */
    HID_BODY_EMPTY
};

static void FixEmitHidBody(FIX_IMAGE* img, int body)
{
    EMIT e;

    EmInit(&e, img, FIX_HID_FUNC_RVA);

    switch (body) {
    case HID_BODY_REAL_SHAPE:
        EmLeaR14RcxPlus8(&e);
        EmMovR14R14Deref(&e);
        EmLeaR8R14Disp(&e, 0x70);
        EmLeaRaxRip(&e, FIX_HID_HANDLER_A);
        EmMovR14DispRax(&e, 0x128);        /* slot 23 */
        EmMovR14DispRax(&e, 0x090);        /* slot 4  */
        EmMovR14DispRax(&e, 0x088);        /* slot 3  */
        EmMovR14DispRax(&e, 0x120);        /* slot 22 */
        EmMovR14DispRax(&e, 0x148);        /* slot 27 */
        EmMovR14DispRax(&e, 0x0E8);        /* slot 15 */
        EmMovR14DispRax(&e, 0x0E0);        /* slot 14 */
        EmMovR8Rax(&e);                    /* slot 0  */
        EmMovR14DispRax(&e, 0x080);        /* slot 2  */
        EmRet(&e);
        break;

    case HID_BODY_MULTI_STORE:
        EmLeaR14RcxPlus8(&e);
        EmMovR14R14Deref(&e);
        EmLeaRaxRip(&e, FIX_HID_HANDLER_A);
        EmMovR14DispRax(&e, 0x088);        /* slot 3  */
        EmMovR14DispRax(&e, 0x128);        /* slot 23 */
        EmMovR14DispRax(&e, 0x080);        /* slot 2  */
        EmRet(&e);
        break;

    case HID_BODY_SLOT0_BASE:
        EmLeaR14RcxPlus8(&e);
        EmMovR14R14Deref(&e);
        EmLeaR8R14Disp(&e, 0x70);
        EmLeaRaxRip(&e, FIX_HID_HANDLER_A);
        EmMovR8Rax(&e);                    /* slot 0  : [base] */
        EmMovR8DispRax(&e, 0x08);          /* slot 1  : [base+8] */
        EmMovR8DispRax(&e, 0xD8);          /* slot 27 : [base+0xD8] = +0x148 */
        EmRet(&e);
        break;

    case HID_BODY_DISP_EDGE:
        EmLeaR14RcxPlus8(&e);
        EmMovR14R14Deref(&e);
        EmLeaRaxRip(&e, FIX_HID_HANDLER_A);
        EmMovR14DispRax(&e, 0x070);        /* slot 0  : 接受 */
        EmMovR14DispRax(&e, 0x148);        /* slot 27 : 接受 */
        EmMovR14DispRax(&e, 0x068);        /* 拒绝（DriverUnload，低于基址） */
        EmMovR14DispRax(&e, 0x150);        /* 拒绝（slot 28，越界） */
        EmRet(&e);
        break;

    case HID_BODY_TWO_HANDLERS:
        EmLeaR14RcxPlus8(&e);
        EmMovR14R14Deref(&e);
        EmLeaRaxRip(&e, FIX_HID_HANDLER_A);
        EmMovR14DispRax(&e, 0x070);        /* slot 0 = A */
        EmMovR14DispRax(&e, 0x080);        /* slot 2 = A */
        EmLeaRaxRip(&e, FIX_HID_HANDLER_B);
        EmMovR14DispRax(&e, 0x088);        /* slot 3 = B */
        EmMovR14DispRax(&e, 0x090);        /* slot 4 = B */
        EmRet(&e);
        break;

    case HID_BODY_NONEXEC_HANDLER:
        EmLeaR14RcxPlus8(&e);
        EmMovR14R14Deref(&e);
        EmLeaRaxRip(&e, FIX_HID_NONEXEC_RVA);
        EmMovR14DispRax(&e, 0x088);        /* slot 3，但 handler 不可执行 */
        EmMovR14DispRax(&e, 0x128);        /* slot 23，同上 */
        EmRet(&e);
        break;

    case HID_BODY_LOST_PROVENANCE:
        EmLeaR14RcxPlus8(&e);
        EmMovR14Rbx(&e);                   /* 覆盖 r14：不再是 registration->DriverObject */
        EmLeaRaxRip(&e, FIX_HID_HANDLER_A);
        EmMovR14DispRax(&e, 0x088);        /* slot 3，应被拒绝 */
        EmMovR14DispRax(&e, 0x128);        /* slot 23，应被拒绝 */
        EmRet(&e);
        break;

    case HID_BODY_GENERIC_WRITER:
        /* 普通跨模块路径：入口 RCX 就是 DriverObject */
        EmLeaRaxRip(&e, FIX_HID_HANDLER_B);
        EmMovRcxDispRax(&e, 0x088);        /* slot 3 */
        EmRet(&e);
        break;

    case HID_BODY_EMPTY:
    default:
        EmRet(&e);
        break;
    }
}

static void FixBuildHidImage(FIX_IMAGE* img, const char* dllName, const char* exportName, int body)
{
    EMIT e;

    FixInitImage(img, FIX_HID_FUNC_RVA, FIX_RDATA_EXPORT, FIX_RDATA_EXPORT_SIZE, 0, 0);
    FixWriteExport(img, dllName, exportName, FIX_HID_FUNC_RVA);
    FixEmitHidBody(img, body);

    EmInit(&e, img, FIX_HID_HANDLER_A);
    EmRet(&e);
    EmInit(&e, img, FIX_HID_HANDLER_B);
    EmRet(&e);
}

static void FixBuildMainImage(FIX_IMAGE* img, const char* importDll, const char* importName,
                              int selfSlotCount, const ULONG* selfSlots)
{
    EMIT e;
    int i;

    FixInitImage(img, FIX_MAIN_ENTRY_RVA, 0, 0, FIX_RDATA_IMPORT, FIX_RDATA_IMPORT_SIZE);
    FixWriteImport(img, importDll, importName);

    EmInit(&e, img, FIX_MAIN_ENTRY_RVA);
    EmLeaRaxRip(&e, FIX_MAIN_SELF_RVA);
    for (i = 0; i < selfSlotCount; i++) {
        EmMovRcxDispRax(&e, 0x70 + selfSlots[i] * 8);
    }
    EmCallRip(&e, FIX_RDATA_IAT);
    EmRet(&e);

    EmInit(&e, img, FIX_MAIN_SELF_RVA);
    EmRet(&e);
}

/* ==================================================================
 * 3. loadModule 回调（按模块名返回镜像字节 + 运行时基址）
 * ================================================================== */
#define MAX_FAKE_MODULES 4

typedef struct _FAKE_MODULE {
    WCHAR        name[64];
    const BYTE*  buffer;
    ULONG64      size;
    ULONG64      base;
    BOOL         fail;
} FAKE_MODULE;

static FAKE_MODULE g_modules[MAX_FAKE_MODULES];
static int g_moduleCount = 0;
static int g_loadCalls = 0;
/* 本次运行是否真的加载过 hidclass.sys（决定 --scan-hid 是否要求 9/9） */
static BOOL g_hidclassLoaded = FALSE;

static void ModulesReset(void)
{
    memset(g_modules, 0, sizeof(g_modules));
    g_moduleCount = 0;
    g_loadCalls = 0;
    g_hidclassLoaded = FALSE;
}

static void ModuleAdd(const WCHAR* name, const BYTE* buffer, ULONG64 size, ULONG64 base, BOOL fail)
{
    if (g_moduleCount >= MAX_FAKE_MODULES) {
        return;
    }
    wcscpy_s(g_modules[g_moduleCount].name, name);
    g_modules[g_moduleCount].buffer = buffer;
    g_modules[g_moduleCount].size = size;
    g_modules[g_moduleCount].base = base;
    g_modules[g_moduleCount].fail = fail;
    g_moduleCount += 1;
}

static BOOL WINAPI TestLoadModule(const WCHAR* moduleName, void* userContext, SS_MODULE_IMAGE* image)
{
    int i;

    UNREFERENCED_PARAMETER(userContext);
    g_loadCalls += 1;

    if (moduleName == NULL || image == NULL) {
        return FALSE;
    }
    if (_wcsicmp(moduleName, L"hidclass.sys") == 0) {
        g_hidclassLoaded = TRUE;
    }

    for (i = 0; i < g_moduleCount; i++) {
        if (_wcsicmp(g_modules[i].name, moduleName) == 0) {
            if (g_modules[i].fail) {
                return FALSE;
            }
            image->buffer = g_modules[i].buffer;
            image->size = g_modules[i].size;
            image->imageBase = g_modules[i].base;
            return TRUE;
        }
    }
    return FALSE;
}

/* ==================================================================
 * 4. 运行与结果采集
 * ================================================================== */
/* 当前生效的 loadModule 回调：夹具测试用 TestLoadModule，
 * --scan-hid（真实 PE 全模块扫描）换成 SystemDiskLoadModule。 */
static SS_MODULE_LOAD_CALLBACK g_activeLoader = TestLoadModule;

typedef struct _HID_RUN {
    SS_DISPATCH_STATUS status;
    ULONG  hitCount;
    INT    modelKind;
    INT    frameworkKind;
    BOOL   valid[SS_DISPATCH_SLOT_COUNT];
    ULONG64 moduleBase[SS_DISPATCH_SLOT_COUNT];
    ULONG  functionRva[SS_DISPATCH_SLOT_COUNT];
    INT    state[SS_DISPATCH_SLOT_COUNT];
    INT    owner[SS_DISPATCH_SLOT_COUNT];
    INT    source[SS_DISPATCH_SLOT_COUNT];
} HID_RUN;

static void RunFillFromResult(const SS_DISPATCH_RESULT* result, HID_RUN* out)
{
    ULONG i;

    out->hitCount = result->hitCount;
    out->modelKind = result->modelKind;
    out->frameworkKind = result->frameworkKind;

    for (i = 0; i < result->slotCount && i < SS_DISPATCH_SLOT_COUNT; i++) {
        out->valid[i] = result->slots[i].valid;
        out->moduleBase[i] = result->slots[i].moduleBase;
        out->functionRva[i] = result->slots[i].functionRva;
        out->state[i] = result->slots[i].state;
        out->owner[i] = result->slots[i].ownerKind;
        out->source[i] = result->slots[i].source;
    }
}

static BOOL RunFixture(const BYTE* image, ULONG64 imageSize, ULONG64 imageBase,
                       const WCHAR* moduleName, BOOL useFlatApi, HID_RUN* out)
{
    memset(out, 0, sizeof(*out));
    out->status = SS_DISPATCH_STATUS_PARSE_FAILED;

    if (!useFlatApi) {
        SS_DISPATCH_REQUEST request;
        SS_DISPATCH_RESULT* result = NULL;

        memset(&request, 0, sizeof(request));
        request.imageBuffer = image;
        request.imageSize = imageSize;
        request.imageBase = imageBase;
        request.moduleName = moduleName;
        request.loadModule = g_activeLoader;
        request.logSink = NULL;

        out->status = SS_RecoverDispatchFromImage(&request, &result);
        if (result == NULL) {
            return FALSE;
        }
        RunFillFromResult(result, out);
        SS_DispatchFreeResult(result);
        return TRUE;
    }

    {
        SS_DISPATCH_REQUEST_FLAT request;
        void* handle = NULL;
        ULONG i;
        ULONG slotCount = 0;

        memset(&request, 0, sizeof(request));
        request.imageBuffer = image;
        request.imageSize = imageSize;
        request.imageBase = imageBase;
        request.moduleName = moduleName;
        request.loadModule = (void*)g_activeLoader;

        out->status = SS_DispatchRecoverFlat(&request, &handle);
        if (handle == NULL) {
            return FALSE;
        }

        SS_DispatchHandleInfo(handle, &out->modelKind, &out->frameworkKind, NULL,
                              &out->hitCount, NULL, NULL, &slotCount);

        for (i = 0; i < slotCount && i < SS_DISPATCH_SLOT_COUNT; i++) {
            SS_DispatchHandleSlot(handle, i, &out->valid[i], &out->moduleBase[i],
                                  &out->functionRva[i], &out->state[i], &out->owner[i],
                                  &out->source[i], NULL);
        }

        SS_DispatchFreeHandle(handle);
        return TRUE;
    }
}

/* 夹具使用的模块基址 */
static FIX_IMAGE g_hidImage;
static FIX_IMAGE g_mainImage;

#define FIX_MAIN_BASE 0xFFFFF80000010000ULL
#define FIX_HID_BASE  0xFFFFF80000020000ULL

/* 真实 PE 用例使用的主基址 / hidclass 基址（合成，仅用于归属判定） */
#define REAL_MAIN_BASE 0xFFFFF80001000000ULL
#define REAL_HID_BASE  0xFFFFF80002000000ULL

static int CountValidSlots(const HID_RUN* run)
{
    int count = 0;
    int i;
    for (i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        if (run->valid[i]) {
            count += 1;
        }
    }
    return count;
}

static int CountSlotsWithBase(const HID_RUN* run, ULONG64 base)
{
    int count = 0;
    int i;
    for (i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        if (run->valid[i] && run->moduleBase[i] == base) {
            count += 1;
        }
    }
    return count;
}

static const ULONG g_hidSlots[9] = { 0, 2, 3, 4, 14, 15, 22, 23, 27 };

static BOOL IsHidSlot(ULONG index)
{
    int i;
    for (i = 0; i < 9; i++) {
        if (g_hidSlots[i] == index) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 公共装配：主镜像导入 (importDll, importName)，外部镜像导出 (exportDll, exportName) */
static void SetupCase(const char* importDll, const char* importName,
                      const char* exportDll, const char* exportName, int body,
                      int selfSlotCount, const ULONG* selfSlots, BOOL loadFails)
{
    WCHAR wideDll[64];

    ModulesReset();
    FixBuildHidImage(&g_hidImage, exportDll, exportName, body);
    FixBuildMainImage(&g_mainImage, importDll, importName, selfSlotCount, selfSlots);

    MultiByteToWideChar(CP_ACP, 0, importDll, -1, wideDll, 64);
    ModuleAdd(wideDll, g_hidImage.bytes, g_hidImage.size, FIX_HID_BASE, loadFails);
}

/* ==================================================================
 * 5. 正向用例
 * ================================================================== */
static void TestRealShape(void)
{
    HID_RUN run;
    HID_RUN flat;
    ULONG selfSlots[3] = { 5, 6, 7 };
    int i;

    g_caseName = "hid-real-shape";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_REAL_SHAPE, 3, selfSlots, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"mshidkmdf-fixture.sys", FALSE, &run),
              "structure API run failed");

    CheckTrue(g_loadCalls > 0, "loadModule was never called (HID scan needs hidclass)");

    for (i = 0; i < 9; i++) {
        ULONG slot = g_hidSlots[i];
        CheckTrue(run.valid[slot], "HID slot %lu not recovered", slot);
        CheckTrue(run.moduleBase[slot] == FIX_HID_BASE,
                  "HID slot %lu moduleBase=0x%llX expected 0x%llX", slot,
                  (unsigned long long)run.moduleBase[slot], (unsigned long long)FIX_HID_BASE);
        CheckTrue(run.functionRva[slot] == FIX_HID_HANDLER_A,
                  "HID slot %lu rva=0x%X expected 0x%X", slot, run.functionRva[slot],
                  FIX_HID_HANDLER_A);
        CheckTrue(run.source[slot] == SS_SOURCE_IMPORTED_FRAMEWORK,
                  "HID slot %lu source=%d expected %d (IMPORTED_FRAMEWORK)", slot,
                  run.source[slot], SS_SOURCE_IMPORTED_FRAMEWORK);
        CheckTrue(run.state[slot] == SS_SLOT_RECOVERED,
                  "HID slot %lu state=%d expected RECOVERED", slot, run.state[slot]);
        CheckTrue(run.owner[slot] == SS_OWNER_DRIVER,
                  "HID slot %lu owner=%d expected DRIVER", slot, run.owner[slot]);
    }

    for (i = 0; i < 3; i++) {
        ULONG slot = selfSlots[i];
        CheckTrue(run.valid[slot], "self slot %lu not recovered", slot);
        CheckTrue(run.moduleBase[slot] == FIX_MAIN_BASE,
                  "self slot %lu moduleBase=0x%llX expected driver base", slot,
                  (unsigned long long)run.moduleBase[slot]);
        CheckTrue(run.functionRva[slot] == FIX_MAIN_SELF_RVA,
                  "self slot %lu rva=0x%X expected 0x%X", slot, run.functionRva[slot],
                  FIX_MAIN_SELF_RVA);
        CheckTrue(run.source[slot] == SS_SOURCE_DIRECT_STORE,
                  "self slot %lu source=%d expected DIRECT_STORE", slot, run.source[slot]);
    }

    /* 非这 9 + 3 个槽不得被误改 */
    CheckTrue(CountValidSlots(&run) == 12, "valid slot count=%d expected 12",
              CountValidSlots(&run));
    CheckTrue(CountSlotsWithBase(&run, FIX_HID_BASE) == 9,
              "slots attributed to hidclass=%d expected 9",
              CountSlotsWithBase(&run, FIX_HID_BASE));

    for (i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        if (IsHidSlot((ULONG)i) || (i == 5) || (i == 6) || (i == 7)) {
            continue;
        }
        CheckTrue(!run.valid[i], "slot %d unexpectedly recovered (rva=0x%X)", i,
                  run.functionRva[i]);
    }

    /* 同一个夹具走 flat API，逐槽必须一致 */
    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"mshidkmdf-fixture.sys", TRUE, &flat),
              "flat API run failed");
    for (i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        CheckTrue(flat.valid[i] == run.valid[i] &&
                  flat.moduleBase[i] == run.moduleBase[i] &&
                  flat.functionRva[i] == run.functionRva[i] &&
                  flat.source[i] == run.source[i],
                  "flat API slot %d differs from structure API", i);
    }
}

static void TestMultiStore(void)
{
    HID_RUN run;
    ULONG slots[3] = { 3, 23, 2 };
    int i;

    g_caseName = "hid-one-lea-many-stores";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_MULTI_STORE, 0, slots, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-multistore.sys", FALSE, &run), "run failed");

    for (i = 0; i < 3; i++) {
        ULONG slot = slots[i];
        CheckTrue(run.valid[slot] && run.moduleBase[slot] == FIX_HID_BASE &&
                  run.functionRva[slot] == FIX_HID_HANDLER_A &&
                  run.source[slot] == SS_SOURCE_IMPORTED_FRAMEWORK,
                  "slot %lu not attributed to the same handler after store #%d "
                  "(valid=%d base=0x%llX rva=0x%X)",
                  slot, i + 1, (int)run.valid[slot], (unsigned long long)run.moduleBase[slot],
                  run.functionRva[slot]);
    }

    CheckTrue(CountValidSlots(&run) == 3, "valid slot count=%d expected 3",
              CountValidSlots(&run));
}

static void TestSlot0Base(void)
{
    HID_RUN run;
    ULONG slots[3] = { 0, 1, 27 };
    int i;

    g_caseName = "hid-slot0-base-form";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_SLOT0_BASE, 0, slots, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-slot0.sys", FALSE, &run), "run failed");

    for (i = 0; i < 3; i++) {
        ULONG slot = slots[i];
        CheckTrue(run.valid[slot] && run.moduleBase[slot] == FIX_HID_BASE &&
                  run.functionRva[slot] == FIX_HID_HANDLER_A,
                  "derived MajorFunction base slot %lu not recovered "
                  "(valid=%d base=0x%llX rva=0x%X)",
                  slot, (int)run.valid[slot], (unsigned long long)run.moduleBase[slot],
                  run.functionRva[slot]);
    }

    CheckTrue(CountValidSlots(&run) == 3, "valid slot count=%d expected 3",
              CountValidSlots(&run));
}

static void TestDisplacementEdges(void)
{
    HID_RUN run;
    int i;

    g_caseName = "hid-displacement-edges";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_DISP_EDGE, 0, NULL, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-disp.sys", FALSE, &run), "run failed");

    /* disp 0x70 -> slot 0 接受；disp 0x148 -> slot 27 接受 */
    CheckTrue(run.valid[0] && run.functionRva[0] == FIX_HID_HANDLER_A,
              "disp 0x70 (slot 0) rejected");
    CheckTrue(run.valid[27] && run.functionRva[27] == FIX_HID_HANDLER_A,
              "disp 0x148 (slot 27) rejected");

    /* disp 0x68（低于基址）与 disp 0x150（slot 28 越界）必须拒绝 */
    for (i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        if (i == 0 || i == 27) {
            continue;
        }
        CheckTrue(!run.valid[i],
                  "slot %d unexpectedly valid: out-of-range displacement accepted", i);
    }
    CheckTrue(CountValidSlots(&run) == 2, "valid slot count=%d expected 2",
              CountValidSlots(&run));
}

static void TestTwoHandlers(void)
{
    HID_RUN run;

    g_caseName = "hid-two-handlers";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_TWO_HANDLERS, 0, NULL, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-two-handlers.sys", FALSE, &run), "run failed");

    CheckTrue(run.valid[0] && run.functionRva[0] == FIX_HID_HANDLER_A,
              "slot 0 handler wrong (rva=0x%X)", run.functionRva[0]);
    CheckTrue(run.valid[2] && run.functionRva[2] == FIX_HID_HANDLER_A,
              "slot 2 handler wrong (rva=0x%X)", run.functionRva[2]);
    CheckTrue(run.valid[3] && run.functionRva[3] == FIX_HID_HANDLER_B,
              "slot 3 handler wrong (rva=0x%X)", run.functionRva[3]);
    CheckTrue(run.valid[4] && run.functionRva[4] == FIX_HID_HANDLER_B,
              "slot 4 handler wrong (rva=0x%X)", run.functionRva[4]);
    CheckTrue(CountValidSlots(&run) == 4, "valid slot count=%d expected 4",
              CountValidSlots(&run));
}

/* ==================================================================
 * 6. 反向用例
 * ================================================================== */
static void TestModuleNameMismatch(void)
{
    HID_RUN run;
    ULONG selfSlots[1] = { 6 };

    g_caseName = "hid-neg-module-name";
    printf("[case] %s\n", g_caseName);

    SetupCase("otherclass.sys", "HidRegisterMinidriver",
              "otherclass.sys", "HidRegisterMinidriver",
              HID_BODY_REAL_SHAPE, 1, selfSlots, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-neg-module.sys", FALSE, &run), "run failed");

    CheckTrue(CountSlotsWithBase(&run, FIX_HID_BASE) == 0,
              "module name != hidclass.sys still produced HID overrides (%d slots)",
              CountSlotsWithBase(&run, FIX_HID_BASE));
    CheckTrue(run.valid[6] && run.moduleBase[6] == FIX_MAIN_BASE,
              "driver's own slot 6 lost");
}

static void TestImportNameMismatch(void)
{
    HID_RUN run;
    ULONG selfSlots[1] = { 6 };

    g_caseName = "hid-neg-import-name";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriverX",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_REAL_SHAPE, 1, selfSlots, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-neg-import.sys", FALSE, &run), "run failed");

    CheckTrue(CountSlotsWithBase(&run, FIX_HID_BASE) == 0,
              "import name != HidRegisterMinidriver still produced HID overrides");
    CheckTrue(run.valid[6] && run.moduleBase[6] == FIX_MAIN_BASE,
              "driver's own slot 6 lost");
}

static void TestLoadModuleFailure(void)
{
    HID_RUN run;
    ULONG selfSlots[1] = { 6 };

    g_caseName = "hid-neg-load-failure";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_REAL_SHAPE, 1, selfSlots, TRUE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-neg-load.sys", FALSE, &run), "run failed");

    CheckTrue(g_loadCalls > 0, "loadModule was not attempted");
    CheckTrue(CountSlotsWithBase(&run, FIX_HID_BASE) == 0,
              "loadModule failure still produced HID overrides");
    CheckTrue(run.valid[6] && run.moduleBase[6] == FIX_MAIN_BASE,
              "driver's own slot 6 lost");
}

static void TestNonExecutableHandler(void)
{
    HID_RUN run;

    g_caseName = "hid-neg-nonexec-handler";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_NONEXEC_HANDLER, 0, NULL, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-neg-nonexec.sys", FALSE, &run), "run failed");

    CheckTrue(CountValidSlots(&run) == 0,
              "handler RVA outside an executable region was accepted (%d slots valid)",
              CountValidSlots(&run));
}

static void TestLostProvenance(void)
{
    HID_RUN run;

    g_caseName = "hid-neg-lost-provenance";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidRegisterMinidriver",
              "hidclass.sys", "HidRegisterMinidriver",
              HID_BODY_LOST_PROVENANCE, 0, NULL, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-neg-provenance.sys", FALSE, &run), "run failed");

    CheckTrue(CountValidSlots(&run) == 0,
              "store accepted after DriverObject provenance was lost (%d slots valid)",
              CountValidSlots(&run));
}

static void TestGenericPathUnaffected(void)
{
    HID_RUN run;
    ULONG selfSlots[1] = { 6 };

    g_caseName = "generic-imported-writer";
    printf("[case] %s\n", g_caseName);

    SetupCase("hidclass.sys", "HidClassGenericWriter",
              "hidclass.sys", "HidClassGenericWriter",
              HID_BODY_GENERIC_WRITER, 1, selfSlots, FALSE);

    CheckTrue(RunFixture(g_mainImage.bytes, g_mainImage.size, FIX_MAIN_BASE,
                         L"fixture-generic.sys", FALSE, &run), "run failed");

    /* 普通跨模块路径：归属外部模块，来源必须是 DIRECT_STORE，不走 HID 特判 */
    CheckTrue(run.valid[3] && run.moduleBase[3] == FIX_HID_BASE &&
              run.functionRva[3] == FIX_HID_HANDLER_B,
              "generic cross-module store lost (valid=%d base=0x%llX rva=0x%X)",
              (int)run.valid[3], (unsigned long long)run.moduleBase[3], run.functionRva[3]);
    CheckTrue(run.source[3] == SS_SOURCE_DIRECT_STORE,
              "generic cross-module store source=%d expected DIRECT_STORE", run.source[3]);
    CheckTrue(run.valid[6] && run.moduleBase[6] == FIX_MAIN_BASE,
              "driver's own slot 6 lost");
    CheckTrue(CountValidSlots(&run) == 2, "valid slot count=%d expected 2",
              CountValidSlots(&run));
}

/* ==================================================================
 * 7. 真实 PE（无需提权：hidclass 基址是合成的，仅用于归属判定）
 * ================================================================== */
#define REAL_FILE_MAX (8 * 1024 * 1024)

typedef struct _REAL_IMAGE {
    BYTE*   bytes;
    ULONG64 size;
} REAL_IMAGE;

static BOOL ReadWholeFile(const WCHAR* path, REAL_IMAGE* out)
{
    HANDLE file;
    LARGE_INTEGER size;
    BYTE* buffer;
    DWORD read = 0;

    out->bytes = NULL;
    out->size = 0;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > (LONGLONG)REAL_FILE_MAX) {
        CloseHandle(file);
        return FALSE;
    }

    buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart);
    if (buffer == NULL) {
        CloseHandle(file);
        return FALSE;
    }

    if (!ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL) ||
        read != (DWORD)size.QuadPart) {
        HeapFree(GetProcessHeap(), 0, buffer);
        CloseHandle(file);
        return FALSE;
    }

    CloseHandle(file);
    out->bytes = buffer;
    out->size = (ULONG64)read;
    return TRUE;
}

static void FreeRealImage(REAL_IMAGE* image)
{
    if (image->bytes != NULL) {
        HeapFree(GetProcessHeap(), 0, image->bytes);
        image->bytes = NULL;
    }
    image->size = 0;
}

static BOOL ComputeSha256(const BYTE* data, ULONG64 size, char* outHex)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    BOOL ok = FALSE;
    int i;

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
        for (i = 0; i < 32; i++) {
            sprintf_s(outHex + i * 2, 3, "%02x", digest[i]);
        }
        outHex[64] = '\0';
        ok = TRUE;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* 基准镜像 SHA-256（与下面两个驱动样本成套；版本不符则 SKIP，不 FAIL） */
#define REAL_HIDCLASS_SHA   "1b4c6abc0e1077583595823b70185c7638e59164356ece09f7aa1a1efbc0cf90"
#define REAL_MSHIDKMDF_SHA  "760e5e19767e01a1a37d40e7b90cfaafee6a0dc892391f199789ee5f9ef5e535"
#define REAL_MSHIDUMDF_SHA  "4e310617a209a1e7a924674ae3dd2c0a6d06828c7da3d2e6d82cd7070bc0d353"

/* HIDCLASS!HidRegisterMinidriver 写入的 handler RVA（上述 hidclass.sys 版本） */
#define REAL_HID_HANDLER_RVA 0x4B60UL

/* 驱动自身 19 个非 HID 槽的基准（= 修复前 loadModule 关闭时的生产恢复结果） */
typedef struct _REAL_DRIVER_CASE {
    const WCHAR* fileName;
    const char*  sha256;
    ULONG        nonHidSlots[19];
    ULONG        nonHidRva[19];
} REAL_DRIVER_CASE;

static const REAL_DRIVER_CASE g_realDrivers[2] = {
    {
        L"mshidkmdf.sys", REAL_MSHIDKMDF_SHA,
        { 1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 24, 25, 26 },
        { 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070,
          0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070, 0x1070 }
    },
    {
        L"mshidumdf.sys", REAL_MSHIDUMDF_SHA,
        { 1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 24, 25, 26 },
        { 0x1490, 0x1560, 0x1560, 0x1490, 0x1490, 0x1560, 0x1490, 0x1490, 0x1490,
          0x1490, 0x1490, 0x1490, 0x1100, 0x1490, 0x1490, 0x1490, 0x1490, 0x1490, 0x1490 }
    }
};

static BOOL BuildSystemDriverPath(const WCHAR* fileName, WCHAR* out, size_t outCount)
{
    WCHAR dir[MAX_PATH];

    if (GetSystemDirectoryW(dir, MAX_PATH) == 0) {
        return FALSE;
    }
    swprintf_s(out, outCount, L"%ls\\drivers\\%ls", dir, fileName);
    return TRUE;
}

/* 用真实 PE 跑一遍（hidclass 用合成基址），--verify-hid 与 --scan-hid 共用 */
static BOOL RunRealDriver(const REAL_DRIVER_CASE* driver, const REAL_IMAGE* hidclass,
                          HID_RUN* out, char* shaOut, size_t shaCount)
{
    REAL_IMAGE main;
    WCHAR path[MAX_PATH];
    WCHAR mainName[64];
    BOOL ok;

    UNREFERENCED_PARAMETER(shaCount);

    if (!BuildSystemDriverPath(driver->fileName, path, MAX_PATH)) {
        return FALSE;
    }
    if (!ReadWholeFile(path, &main)) {
        return FALSE;
    }
    if (shaOut != NULL) {
        ComputeSha256(main.bytes, main.size, shaOut);
    }

    ModulesReset();
    wcscpy_s(mainName, driver->fileName);
    ModuleAdd(L"hidclass.sys", hidclass->bytes, hidclass->size, REAL_HID_BASE, FALSE);

    ok = RunFixture(main.bytes, main.size, REAL_MAIN_BASE, mainName, FALSE, out);
    FreeRealImage(&main);
    return ok;
}

static void TestRealPe(void)
{
    REAL_IMAGE hidclass;
    WCHAR path[MAX_PATH];
    char sha[65];
    int i;
    int n;

    g_caseName = "real-pe";
    printf("[case] %s\n", g_caseName);

    if (!BuildSystemDriverPath(L"hidclass.sys", path, MAX_PATH) ||
        !ReadWholeFile(path, &hidclass)) {
        printf("  [SKIP] hidclass.sys not readable\n");
        g_skips += 1;
        return;
    }

    ComputeSha256(hidclass.bytes, hidclass.size, sha);
    if (strcmp(sha, REAL_HIDCLASS_SHA) != 0) {
        printf("  [SKIP] hidclass.sys version differs (sha=%s)\n", sha);
        g_skips += 1;
        FreeRealImage(&hidclass);
        return;
    }

    for (n = 0; n < 2; n++) {
        const REAL_DRIVER_CASE* driver = &g_realDrivers[n];
        HID_RUN run;
        char driverSha[65];

        memset(driverSha, 0, sizeof(driverSha));
        if (!RunRealDriver(driver, &hidclass, &run, driverSha, sizeof(driverSha))) {
            printf("  [SKIP] %ls not readable\n", driver->fileName);
            g_skips += 1;
            continue;
        }

        if (strcmp(driverSha, driver->sha256) != 0) {
            printf("  [SKIP] %ls version differs (sha=%s)\n", driver->fileName, driverSha);
            g_skips += 1;
            continue;
        }

        printf("  %ls sha=%s\n", driver->fileName, driverSha);

        for (i = 0; i < 9; i++) {
            ULONG slot = g_hidSlots[i];
            CheckTrue(run.valid[slot] && run.moduleBase[slot] == REAL_HID_BASE &&
                      run.functionRva[slot] == REAL_HID_HANDLER_RVA &&
                      run.source[slot] == SS_SOURCE_IMPORTED_FRAMEWORK,
                      "%ls HID slot %lu: valid=%d base=0x%llX rva=0x%X source=%d "
                      "(expected hidclass base rva=0x%X IMPORTED_FRAMEWORK)",
                      driver->fileName, slot, (int)run.valid[slot],
                      (unsigned long long)run.moduleBase[slot], run.functionRva[slot],
                      run.source[slot], REAL_HID_HANDLER_RVA);
        }

        /* 19/19 既有槽必须保持驱动自身值 */
        for (i = 0; i < 19; i++) {
            ULONG slot = driver->nonHidSlots[i];
            CheckTrue(run.valid[slot] && run.moduleBase[slot] == REAL_MAIN_BASE &&
                      run.functionRva[slot] == driver->nonHidRva[i],
                      "%ls non-HID slot %lu changed: valid=%d base=0x%llX rva=0x%X "
                      "(expected driver base rva=0x%X)",
                      driver->fileName, slot, (int)run.valid[slot],
                      (unsigned long long)run.moduleBase[slot], run.functionRva[slot],
                      driver->nonHidRva[i]);
        }

        CheckTrue(CountSlotsWithBase(&run, REAL_HID_BASE) == 9,
                  "%ls slots attributed to hidclass=%d expected 9", driver->fileName,
                  CountSlotsWithBase(&run, REAL_HID_BASE));
    }

    FreeRealImage(&hidclass);
}

/* ==================================================================
 * 8. 入口
 * ================================================================== */
static int VerifyHid(void)
{
    printf("=== SnowSwordCore HID framework dispatch override verification ===\n\n");

    TestRealShape();
    TestMultiStore();
    TestSlot0Base();
    TestDisplacementEdges();
    TestTwoHandlers();

    TestModuleNameMismatch();
    TestImportNameMismatch();
    TestLoadModuleFailure();
    TestNonExecutableHandler();
    TestLostProvenance();
    TestGenericPathUnaffected();

    TestRealPe();

    printf("\n=== summary: HID PASS=%d FAIL=%d SKIP=%d ===\n",
           g_checks - g_failures, g_failures, g_skips);

    return (g_failures == 0) ? 0 : 1;
}

/* --scan-hid：真实 PE 逐槽打印（无需提权）
 *
 * 任何被导入的模块名都按 %SystemRoot%\System32\drivers\<name> 读磁盘镜像，
 * 基址用确定性合成值（归属判定只需要「同一个模块同一个基址」，
 * 不依赖真实运行时光址，因此无需提权、也不需要枚举内核模块）。
 * 这样 disk.sys -> classpnp.sys 这类跨模块样本也能离线核对。 */
#define SYS_MODULE_POOL_MAX 32

typedef struct _SYS_MODULE_ENTRY {
    WCHAR      name[64];
    REAL_IMAGE image;
    ULONG64    base;
} SYS_MODULE_ENTRY;

static SYS_MODULE_ENTRY g_sysModules[SYS_MODULE_POOL_MAX];
static int g_sysModuleCount = 0;

static void SysModulesReset(void)
{
    int i;
    for (i = 0; i < g_sysModuleCount; i++) {
        FreeRealImage(&g_sysModules[i].image);
        g_sysModules[i].name[0] = L'\0';
    }
    g_sysModuleCount = 0;
}

static const WCHAR* ModuleNameOf(ULONG64 base)
{
    static WCHAR unknown[64];
    int i;

    for (i = 0; i < g_moduleCount; i++) {
        if (g_modules[i].base == base && base != 0) {
            return g_modules[i].name;
        }
    }
    for (i = 0; i < g_sysModuleCount; i++) {
        if (g_sysModules[i].base == base) {
            return g_sysModules[i].name;
        }
    }

    swprintf_s(unknown, 64, L"0x%llX", (unsigned long long)base);
    return unknown;
}

static BOOL WINAPI SystemDiskLoadModule(const WCHAR* moduleName, void* userContext,
                                        SS_MODULE_IMAGE* image)
{
    WCHAR path[MAX_PATH];
    int i;

    UNREFERENCED_PARAMETER(userContext);
    g_loadCalls += 1;

    if (moduleName == NULL || image == NULL) {
        return FALSE;
    }
    if (_wcsicmp(moduleName, L"hidclass.sys") == 0) {
        g_hidclassLoaded = TRUE;
    }

    /* 显式注册的模块（例如固定基址的 hidclass.sys）优先 */
    for (i = 0; i < g_moduleCount; i++) {
        if (_wcsicmp(g_modules[i].name, moduleName) == 0) {
            if (g_modules[i].fail) {
                return FALSE;
            }
            image->buffer = g_modules[i].buffer;
            image->size = g_modules[i].size;
            image->imageBase = g_modules[i].base;
            return TRUE;
        }
    }

    for (i = 0; i < g_sysModuleCount; i++) {
        if (_wcsicmp(g_sysModules[i].name, moduleName) == 0) {
            image->buffer = g_sysModules[i].image.bytes;
            image->size = g_sysModules[i].image.size;
            image->imageBase = g_sysModules[i].base;
            return TRUE;
        }
    }

    if (g_sysModuleCount >= SYS_MODULE_POOL_MAX) {
        return FALSE;
    }
    if (!BuildSystemDriverPath(moduleName, path, MAX_PATH)) {
        return FALSE;
    }
    if (!ReadWholeFile(path, &g_sysModules[g_sysModuleCount].image)) {
        return FALSE;
    }

    wcscpy_s(g_sysModules[g_sysModuleCount].name, moduleName);
    g_sysModules[g_sysModuleCount].base = 0xFFFFF80010000000ULL +
                                          (ULONG64)g_sysModuleCount * 0x100000ULL;

    image->buffer = g_sysModules[g_sysModuleCount].image.bytes;
    image->size = g_sysModules[g_sysModuleCount].image.size;
    image->imageBase = g_sysModules[g_sysModuleCount].base;
    g_sysModuleCount += 1;
    return TRUE;
}

static int ScanHid(const WCHAR* imagePath)
{
    REAL_IMAGE hidclass;
    REAL_IMAGE main;
    WCHAR path[MAX_PATH];
    char sha[65];
    HID_RUN run;
    const WCHAR* leaf;
    ULONG i;
    int hidCount = 0;
    int exitCode;

    if (!BuildSystemDriverPath(L"hidclass.sys", path, MAX_PATH) ||
        !ReadWholeFile(path, &hidclass)) {
        printf("ERROR cannot read hidclass.sys\n");
        return 1;
    }
    if (!ReadWholeFile(imagePath, &main)) {
        printf("ERROR cannot read %ls\n", imagePath);
        FreeRealImage(&hidclass);
        return 1;
    }

    ComputeSha256(hidclass.bytes, hidclass.size, sha);
    printf("HIDCLASS sha256=%s base=0x%llX\n", sha, (unsigned long long)REAL_HID_BASE);

    ModulesReset();
    SysModulesReset();
    ModuleAdd(L"hidclass.sys", hidclass.bytes, hidclass.size, REAL_HID_BASE, FALSE);
    g_activeLoader = SystemDiskLoadModule;

    leaf = wcsrchr(imagePath, L'\\');
    leaf = (leaf == NULL) ? imagePath : (leaf + 1);

    if (!RunFixture(main.bytes, main.size, REAL_MAIN_BASE, leaf, FALSE, &run)) {
        printf("ERROR scan failed\n");
        g_activeLoader = TestLoadModule;
        FreeRealImage(&hidclass);
        FreeRealImage(&main);
        return 1;
    }

    g_activeLoader = TestLoadModule;

    ComputeSha256(main.bytes, main.size, sha);
    printf("IMAGE %ls sha256=%s status=%d hits=%u frameworkKind=%d\n",
           leaf, sha, (int)run.status, run.hitCount, run.frameworkKind);

    printf("MAIN base=0x%llX\n", (unsigned long long)REAL_MAIN_BASE);
    for (i = 0; i < (ULONG)g_sysModuleCount; i++) {
        printf("MODULE %ls base=0x%llX\n", g_sysModules[i].name,
               (unsigned long long)g_sysModules[i].base);
    }

    for (i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        if (run.valid[i] && run.moduleBase[i] == REAL_HID_BASE) {
            hidCount += 1;
        }
        if (run.valid[i]) {
            printf("SLOT %2lu valid=1 module=%-16ls rva=0x%-8X state=%d owner=%d source=%d\n",
                   i, ModuleNameOf(run.moduleBase[i]), run.functionRva[i],
                   run.state[i], run.owner[i], run.source[i]);
        } else {
            printf("SLOT %2lu valid=0\n", i);
        }
    }

    printf("HID-SLOTS-ATTRIBUTED-TO-HIDCLASS %d/9\n", hidCount);

    /*
     * 只有「确实加载 hidclass.sys」的样本才是 HID 样本，才要求 9/9；
     * 其它样本（如 disk.sys -> CLASSPNP.SYS）这里只做逐槽打印，
     * 退出码只反映扫描本身是否成功。
     */
    exitCode = (!g_hidclassLoaded || hidCount == 9) ? 0 : 1;
    FreeRealImage(&hidclass);
    FreeRealImage(&main);
    SysModulesReset();
    return exitCode;
}

int RunHidDispatchTestMain(int argc, char** argv)
{
    if (argc < 2) {
        return 2;
    }

    if (_stricmp(argv[1], "--verify-hid") == 0) {
        return VerifyHid();
    }

    if (_stricmp(argv[1], "--scan-hid") == 0) {
        int result = 0;
        int i;

        for (i = 2; i < argc; i++) {
            WCHAR wide[MAX_PATH];
            if (MultiByteToWideChar(CP_ACP, 0, argv[i], -1, wide, MAX_PATH) == 0) {
                printf("ERROR bad path: %s\n", argv[i]);
                result = 1;
                continue;
            }
            if (ScanHid(wide) != 0) {
                result = 1;
            }
        }
        return result;
    }

    return 2;
}
