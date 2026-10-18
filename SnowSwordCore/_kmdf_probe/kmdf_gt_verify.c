/*
 * kmdf_gt_verify.c -- Phase 3B KMDF baseline Core 侧离线 ground-truth dumper
 *
 * 与 gen_vb_dump.py 产出的 VB 真实函数 dump 做逐字节 diff：
 *   B 段 = BuildKmdfDispatchBaseline：2 个接受 policy + 10 个拒绝场景，逐槽 28 项
 *   P 段 = IsKmdfBaselineExecutable：合成 PE 的 1 接受 + 7 拒绝
 *   O 段 = SS_BuildKmdfDispatchBaseline（build -> PE -> fallback 编排）：5 个处置场景
 *
 * 输入常量与 tests/verify_kmdf_dispatch.py 的 155-check harness 完全一致：
 *   mockBase = 0xFFFFF80000000000, mockSize = 0x5000
 *
 * 直接与 dispatch_kmdf.c 一起编译（调用内部函数），不链接 Core DLL：
 *   cl /I. /D SNOWSWORDCORE_EXPORTS kmdf_gt_verify.c ..\dispatch_kmdf.c
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "dispatch_internal.h"

#define BASE  0xFFFFF80000000000ULL
#define SIZE  0x5000UL

static SS_KMDF_DRIVER_INFO make_info(void)
{
    SS_KMDF_DRIVER_INFO x;
    memset(&x, 0, sizeof(x));
    x.isKmdf = 1;
    x.ownsDispatch = 1;
    x.dispatchPolicyKnown = 1;
    x.dispatch = BASE + 0x1000;
    x.dispatchWithLock = BASE + 0x2000;
    x.dispatchPolicy = SS_KMDF_POLICY_ALL_DISPATCH_WITH_LOCK;
    return x;
}

static void dump_build(int id, int ok, const SS_DRIVER_RECOVERY_OUTPUT* b)
{
    printf("B|%d|%d|%d|%u|%u|%u\n",
           id, ok ? 1 : 0, b->modelKind, b->modelConfidence,
           b->hitCount, b->confidence);
    for (int i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        const SS_FUNCTION_REF* s = &b->majorFunction[i];
        printf("S|%d|%d|%d|%llX|%X|%d|%d|%d|%u\n",
               id, i, s->valid ? 1 : 0,
               (unsigned long long)s->moduleBase, s->functionRva,
               s->state, s->ownerKind, s->source, s->confidence);
    }
}

static void dump_overlay(int id, const SS_KMDF_BASELINE_OUTPUT* o)
{
    printf("O|%d|%d|%d|%u|%u|%u|%X\n",
           id, o->disposition, o->modelKind, o->modelConfidence,
           o->hitCount, o->confidence, o->targetRva);
    for (int i = 0; i < SS_DISPATCH_SLOT_COUNT; i++) {
        const SS_DISPATCH_SLOT* s = &o->slots[i];
        printf("S|%d|%d|%d|%llX|%X|%d|%d|%d|%u\n",
               id, i, s->valid ? 1 : 0,
               (unsigned long long)s->moduleBase, s->functionRva,
               s->state, s->ownerKind, s->source, s->confidence);
    }
}

/* 合成有界 PE，字段与 verify_kmdf_dispatch.py 的 2KB 镜像一致。 */
static void make_synthetic_pe(BYTE* bytes)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)bytes;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(bytes + 0x80);
    IMAGE_SECTION_HEADER* sec =
        (IMAGE_SECTION_HEADER*)(bytes + 0x80 + sizeof(IMAGE_NT_HEADERS64));

    memset(bytes, 0, 0x800);
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x80;
    nt->Signature = 0x4550;
    nt->FileHeader.Machine = 0x8664;
    nt->OptionalHeader.Magic = 0x20B;
    nt->OptionalHeader.SizeOfImage = SIZE;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.NumberOfSections = 1;
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x1000;
    sec->SizeOfRawData = 0x400;
    sec->PointerToRawData = 0x400;
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE;
}

int main(void)
{
    SS_DRIVER_RECOVERY_OUTPUT b;

    /* ============ B 段：BuildKmdfDispatchBaseline ============ */
    /* 接受：policy 1 / 2（与 VB For policy=1..2 对应） */
    for (int policy = 1; policy <= 2; policy++) {
        SS_KMDF_DRIVER_INFO info = make_info();
        info.dispatchPolicy = policy;
        int ok = (int)ss_build_kmdf_dispatch_baseline(&info, BASE, SIZE, &b);
        dump_build(policy - 1, ok, &b);
    }

    /* 拒绝：10 场景（VB scenario 0..9，起始 info 停在 policy=2） */
    for (int scenario = 0; scenario < 10; scenario++) {
        SS_KMDF_DRIVER_INFO invalid = make_info();
        ULONG64 testBase = BASE;
        int id = 2 + scenario;

        switch (scenario) {
        case 0: invalid.isKmdf = 0; break;
        case 1: invalid.ownsDispatch = 0; break;
        case 2: invalid.driverInitFlags = 2; break;
        case 3: invalid.dispatchPolicyKnown = 0; break;
        case 4: invalid.dispatchPolicy = SS_KMDF_POLICY_MIXED; break;
        case 5: invalid.dispatchPolicy = 99; break;
        case 6: invalid.dispatchWithLock = 0; break;
        case 7: invalid.dispatchWithLock = BASE + SIZE; break;
        case 8: testBase = 0x1000; break;
        case 9: testBase = 0xFFFFFFFFFFFFF000ULL; break;
        }

        {
            int ok = (int)ss_build_kmdf_dispatch_baseline(&invalid, testBase,
                                                          SIZE, &b);
            dump_build(id, ok, &b);
        }
    }

    /* ============ P 段：IsKmdfBaselineExecutable ============ */
    {
        BYTE bytes[0x800];
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)bytes;
        IMAGE_SECTION_HEADER* sec =
            (IMAGE_SECTION_HEADER*)(bytes + 0x80 + sizeof(IMAGE_NT_HEADERS64));

        make_synthetic_pe(bytes);
        printf("P|0|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x800, SIZE, 0x1100));
        printf("P|1|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 16, SIZE, 0x1100));
        printf("P|2|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x90, SIZE, 0x1100));
        printf("P|3|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x800, SIZE + 1, 0x1100));
        printf("P|4|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x800, SIZE, 0x1500));
        sec->Characteristics = 0;
        printf("P|5|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x800, SIZE, 0x1100));
        sec->Characteristics = IMAGE_SCN_MEM_EXECUTE;
        sec->PointerToRawData = 0xFFFFFF00;
        printf("P|6|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x800, SIZE, 0x1100));
        dos->e_lfanew = 0x7FFFFFFF;
        printf("P|7|%d\n", (int)ss_is_kmdf_baseline_executable(bytes, 0x800, SIZE, 0x1100));
    }

    /* ============ O 段：SS_BuildKmdfDispatchBaseline 三态编排 ============ */
    {
        BYTE pe[0x800];
        SS_KMDF_BASELINE_OUTPUT out;
        SS_KMDF_DRIVER_INFO info;
        SS_DISPATCH_STATUS st;

        make_synthetic_pe(pe);

        /* O20：policy=1，build RVA=0x1000 命中合成 PE 可执行节 -> BASELINE */
        info = make_info();
        info.dispatchPolicy = SS_KMDF_POLICY_ALL_DISPATCH;
        st = SS_BuildKmdfDispatchBaseline(&info, BASE, SIZE, pe, 0x800, SIZE, &out);
        if (st != SS_DISPATCH_STATUS_RECOVERED) { printf("OERR20\n"); return 1; }
        dump_overlay(20, &out);

        /* O21：DispatchPolicyKnown=0 -> FALLBACK */
        info = make_info();
        info.dispatchPolicyKnown = 0;
        SS_BuildKmdfDispatchBaseline(&info, BASE, SIZE, pe, 0x800, SIZE, &out);
        dump_overlay(21, &out);

        /* O22：NoDispatchOverride -> SKIP */
        info = make_info();
        info.driverInitFlags = 2;
        SS_BuildKmdfDispatchBaseline(&info, BASE, SIZE, pe, 0x800, SIZE, &out);
        dump_overlay(22, &out);

        /* O23：OwnsDispatch=0 -> SKIP */
        info = make_info();
        info.ownsDispatch = 0;
        SS_BuildKmdfDispatchBaseline(&info, BASE, SIZE, pe, 0x800, SIZE, &out);
        dump_overlay(23, &out);

        /* O24：build 接受但镜像不可得（NULL） -> FALLBACK */
        info = make_info();
        info.dispatchPolicy = SS_KMDF_POLICY_ALL_DISPATCH;
        SS_BuildKmdfDispatchBaseline(&info, BASE, SIZE, NULL, 0, SIZE, &out);
        dump_overlay(24, &out);
    }

    return 0;
}
