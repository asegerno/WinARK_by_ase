/*
 * dispatch_static_baseline.h -- 静态扫描基准（离线 oracle）
 *
 * 数据来源：D:\GitHub Project\SnowSword\validation\dispatch-regression.md
 * 产生方式：validation/verify_dispatch_real.py —— 抽取生产 Generic scanner +
 *           PE helpers + udis86 编译成 FreeBASIC harness，stub 掉
 *           ScanImportedDispatchCall（即不跨模块扫描），ImageBase 取 PE
 *           OptionalHeader.ImageBase。
 *
 * 本表用于离线验证 SnowSwordCore 的 DispatchGeneric 移植是否与 VB 生产实现
 * 逐槽一致。这是「扫描器逻辑等价性」的独立于在线 50 样本回归的证据。
 *
 * 注意：镜像随 Windows 更新会变化。测试以 SHA-256 判断镜像是否为同一版本；
 * 不匹配时报告 SKIP 而不是 FAIL。
 */
#pragma once

typedef struct _SS_STATIC_SLOT {
    int      index;   /* IRP_MJ 槽位，-1 表示表尾 */
    unsigned rva;     /* MajorFunction[index] 的原始地址模块内 RVA */
} SS_STATIC_SLOT;

typedef struct _SS_STATIC_BASELINE {
    const wchar_t* imageName;
    const char* sha256;      /* 基准镜像的 SHA-256（小写十六进制） */
    unsigned    hits;        /* 基准 Hits */
    unsigned    fastIoRva;   /* 基准 FastIoDispatch RVA，0 表示未恢复 */
    const SS_STATIC_SLOT* slots;  /* 以 index == -1 结尾 */
} SS_STATIC_BASELINE;

#define SS_SLOT_END { -1, 0 }

static const SS_STATIC_SLOT g_slots_360AntiAttack64[] = {
    {0,0x14D8},{1,0x14D8},{2,0x14D8},{3,0x14D8},{4,0x14D8},{5,0x14D8},{6,0x14D8},
    {7,0x14D8},{8,0x14D8},{9,0x14D8},{10,0x14D8},{11,0x14D8},{12,0x14D8},{13,0x14D8},
    {14,0x14D8},{15,0x14D8},{16,0x14D8},{17,0x14D8},{18,0x14D8},{19,0x14D8},{20,0x14D8},
    {21,0x14D8},{22,0x14D8},{23,0x14D8},{24,0x14D8},{25,0x14D8},{26,0x14D8},{27,0x14D8},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360AntiHacker64[] = {
    {0,0x24A4},{1,0x24A4},{2,0x24A4},{3,0x24A4},{4,0x24A4},{5,0x24A4},{6,0x24A4},
    {7,0x24A4},{8,0x24A4},{9,0x24A4},{10,0x24A4},{11,0x24A4},{12,0x24A4},{13,0x24A4},
    {14,0x24A4},{15,0x24A4},{16,0x24A4},{17,0x24A4},{18,0x24A4},{19,0x24A4},{20,0x24A4},
    {21,0x24A4},{22,0x24A4},{23,0x24A4},{24,0x24A4},{25,0x24A4},{26,0x24A4},{27,0x24A4},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360AntiHijack64[] = {
    {0,0x10DC},{1,0x10DC},{2,0x10DC},{3,0x10DC},{4,0x10DC},{5,0x10DC},{6,0x10DC},
    {7,0x10DC},{8,0x10DC},{9,0x10DC},{10,0x10DC},{11,0x10DC},{12,0x10DC},{13,0x10DC},
    {14,0x10DC},{15,0x10DC},{16,0x1344},{17,0x10DC},{18,0x10DC},{19,0x10DC},{20,0x10DC},
    {21,0x10DC},{22,0x10DC},{23,0x10DC},{24,0x10DC},{25,0x10DC},{26,0x10DC},{27,0x10DC},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360Box64[] = {
    {0,0x12D8},{2,0x12D8},{14,0x132C},{16,0x1234},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360Camera64[] = {
    {0,0x150C},{1,0x1008},{2,0x10E4},{3,0x1008},{4,0x1008},{5,0x1008},{6,0x1008},
    {7,0x1008},{8,0x1008},{9,0x1008},{10,0x1008},{11,0x1008},{12,0x1008},{13,0x1008},
    {14,0x3150},{15,0x1008},{16,0x1008},{17,0x1008},{18,0x10E4},{19,0x1008},{20,0x1008},
    {21,0x1008},{22,0x4118},{23,0x1008},{24,0x1008},{25,0x1008},{26,0x1008},{27,0x1230},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360Hvm64[] = {
    {0,0x22E0},{2,0x22E0},{14,0x23F0},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360Sensor64[] = {
    {0,0x1008},{2,0x1008},{14,0x1008},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360Sensor_DM64[] = {
    {0,0x1008},{2,0x1008},{14,0x1008},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360netmon[] = {
    {0,0x1E2C},{1,0x60FC},{2,0x60FC},{3,0x60FC},{4,0x60FC},{5,0x60FC},{6,0x60FC},
    {7,0x60FC},{8,0x60FC},{9,0x60FC},{10,0x60FC},{11,0x60FC},{12,0x60FC},{13,0x60FC},
    {14,0x236C},{15,0x44BC},{16,0x60FC},{17,0x60FC},{18,0x5F70},{19,0x60FC},{20,0x60FC},
    {21,0x60FC},{22,0x60FC},{23,0x60FC},{24,0x60FC},{25,0x60FC},{26,0x60FC},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_360qpesv64[] = {
    {0,0x18C0},{2,0x18C0},{14,0x1A0C},{16,0x2AC4},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_DsArk64[] = {
    {0,0x13E74},{2,0x13E74},{14,0x13E74},{16,0x13E74},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_mshidumdf[] = {
    {0,0x1100},{1,0x1490},{2,0x1100},{3,0x1490},{4,0x1490},{5,0x1560},{6,0x1560},
    {7,0x1490},{8,0x1490},{9,0x1560},{10,0x1490},{11,0x1490},{12,0x1490},{13,0x1490},
    {14,0x1490},{15,0x1240},{16,0x1490},{17,0x1490},{18,0x1100},{19,0x1490},{20,0x1490},
    {21,0x1490},{22,0x14E0},{23,0x1490},{24,0x1490},{25,0x1490},{26,0x1490},{27,0x71F0},
    SS_SLOT_END
};

static const SS_STATIC_SLOT g_slots_empty[] = { SS_SLOT_END };

static const SS_STATIC_BASELINE g_staticBaseline[] = {
    { L"360AntiAttack64.sys", "0ddcbe69e85ac830e0184cd19456297749235e52f68e1539eb4d47f23d171f4b", 28, 0x0,     g_slots_360AntiAttack64 },
    { L"360AntiHacker64.sys", "5ec905b5c074e55e5d5cffcbab7a7120cbe09f6420053c902fd653791de47beb", 28, 0x2A170, g_slots_360AntiHacker64 },
    { L"360AntiHijack64.sys", "2a25a721e4fe6b766ca0e0a132a6de6933c2fd271353872065e81da1e73d5cca", 28, 0x0,     g_slots_360AntiHijack64 },
    { L"360AntiSteal64.sys",  "63cf4d653e1b85c3d190abd32ba140f1fdd9771f30199ecbe2088ea43c03aa1d", 0,  0x0,     g_slots_empty },
    { L"360Box64.sys",        "6159f26cb0108e858b4935a8a868ebbad1756e389daf51354c28db47cacf0b4d", 4,  0x0,     g_slots_360Box64 },
    { L"360Camera64.sys",     "b004e8e86e2fdf24a94237d9bdb42da1bcbfe3aeecce927c4ef2604a704758f7", 28, 0x0,     g_slots_360Camera64 },
    { L"360FsFlt.sys",        "3e17b69ca2e959231cc08c888c90ec1f16a8493ed3f24b17ee30b7270d32e125", 0,  0x0,     g_slots_empty },
    { L"360Hvm64.sys",        "f89d5d95b8a59e6d5e50a49217f83d080e4eaf4bb77b80d8f38cd915640ba124", 3,  0x0,     g_slots_360Hvm64 },
    { L"360Sensor64.sys",     "1a602738005941f139c996b01e46f6028f5e9ca487c10451a14b3cf0b4fa630e", 3,  0x0,     g_slots_360Sensor64 },
    { L"360Sensor_DM64.sys",  "1f7a77b6331f7d1b24f6823c0f9409fc1ae184a826334d83181d18ea173f66a1", 3,  0x0,     g_slots_360Sensor_DM64 },
    { L"360elam64.sys",       "cfa71ff2e86183b1dfbb093c13deb73ba7cc33153b74dfb1b06839f16ca684ac", 0,  0x0,     g_slots_empty },
    { L"360netmon.sys",       "b9805d4707e9d24e01c37a7fa76e0412b04ef6685a2c31d182706170957065ab", 27, 0x0,     g_slots_360netmon },
    { L"360qpesv64.sys",      "2d86bfb596bb6b25d527b1c6000da645f7c66d9caf108d3959dcf67c1dc06602", 4,  0x0,     g_slots_360qpesv64 },
    { L"DsArk64.sys",         "86127dbc92e2896319d1c9117b85e6db01ff001f3a85614d5ef9088d181b044a", 4,  0x0,     g_slots_DsArk64 },
    { L"acpiex.sys",          "0ea9b48cb8e99d98aec52b1ee2f7a500dec3df60ce3f3e9bda3777d7ff1a0f98", 0,  0x0,     g_slots_empty },
    { L"mshidumdf.sys",       "4e310617a209a1e7a924674ae3dd2c0a6d06828c7da3d2e6d82cd7070bc0d353", 28, 0x0,     g_slots_mshidumdf }
};

#define SS_STATIC_BASELINE_COUNT (sizeof(g_staticBaseline) / sizeof(g_staticBaseline[0]))
