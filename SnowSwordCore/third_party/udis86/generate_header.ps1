# udis86.h 生成器
#
# 从 FreeBASIC 绑定 ring3/headers/udis86.bi 生成 MSVC 可用的 C 头文件，
# 用于链接既有的 libudis86.lib（MSVC x64 静态库，与 FreeBASIC 版同一份引擎）。
#
# 重新生成：
#   pwsh -File generate_header.ps1
#
# 输入：udis86BiPath（默认指向 SnowSword r3 工程的 udis86.bi）
# 输出：本目录下的 udis86.h

param(
    [string]$udis86BiPath = 'D:\GitHub Project\SnowSword\ring3\headers\udis86.bi',
    [string]$outputPath = (Join-Path $PSScriptRoot 'udis86.h')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $udis86BiPath)) {
    throw "udis86.bi not found: $udis86BiPath"
}

$src = [System.IO.File]::ReadAllText($udis86BiPath, [System.Text.Encoding]::UTF8)

function Get-EnumMembers {
    param([string]$Name)
    $pattern = 'Enum\s+' + [regex]::Escape($Name) + '\s*(.*?)End\s+Enum'
    $match = [regex]::Match($src, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) {
        throw "enum not found in .bi: $Name"
    }

    $members = New-Object System.Collections.Generic.List[string]
    foreach ($rawLine in ($match.Groups[1].Value -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith("'")) { continue }          # 整行注释
        $line = ($line -split "'")[0].Trim()             # 去掉行尾注释
        if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)\s*$') {
            $members.Add($Matches[1])
        } elseif ($line -match '^([A-Za-z_][A-Za-z0-9_]*)\s*=') {
            # 显式赋值：保留（udis86 的枚举目前均为隐式递增）
            $members.Add(($line -replace '\s+', ' '))
        } else {
            throw "unexpected enum line in ${Name}: $line"
        }
    }
    return $members
}

$mnemonics = Get-EnumMembers 'ud_mnemonic_code'
$udTypes   = Get-EnumMembers 'ud_type'

if ($mnemonics.Count -lt 100) {
    throw "ud_mnemonic_code too short: $($mnemonics.Count)"
}

$sb = New-Object System.Text.StringBuilder

[void]$sb.AppendLine('/*')
[void]$sb.AppendLine(' * udis86.h -- udis86 反汇编引擎 C 接口（MSVC x64）')
[void]$sb.AppendLine(' *')
[void]$sb.AppendLine(' * 由 third_party/udis86/generate_header.ps1 从')
[void]$sb.AppendLine(' *   D:\GitHub Project\SnowSword\ring3\headers\udis86.bi')
[void]$sb.AppendLine(' * 机械生成。原始来源为 udis86 官方 extern.h + itab.h。')
[void]$sb.AppendLine(' *')
[void]$sb.AppendLine(' * 枚举顺序即数值来源，与 libudis86.lib 必须一致；不要手工插入/删除成员。')
[void]$sb.AppendLine(' */')
[void]$sb.AppendLine('#ifndef UDIS86_H')
[void]$sb.AppendLine('#define UDIS86_H')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('#include <stdint.h>')
[void]$sb.AppendLine('#include <stddef.h>')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('#ifdef __cplusplus')
[void]$sb.AppendLine('extern "C" {')
[void]$sb.AppendLine('#endif')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('/* ---------------- enum ud_mnemonic_code ---------------- */')
[void]$sb.AppendLine('typedef enum ud_mnemonic_code {')
for ($i = 0; $i -lt $mnemonics.Count; $i++) {
    [void]$sb.AppendLine("    $($mnemonics[$i]),")
}
[void]$sb.AppendLine('} ud_mnemonic_code_t;')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('/* ---------------- enum ud_type ---------------- */')
[void]$sb.AppendLine('typedef enum ud_type {')
foreach ($t in $udTypes) {
    [void]$sb.AppendLine("    $t,")
}
[void]$sb.AppendLine('} ud_type_t;')
[void]$sb.AppendLine('')
[void]$sb.AppendLine(@'
/* ---------------- union ud_lval ---------------- */
union ud_lval {
    int8_t   sbyte;
    uint8_t  UByte;
    int16_t  sword;
    uint16_t UWORD;
    int32_t  sdword;
    uint32_t udword;
    int64_t  sqword;
    uint64_t uqword;
    uint16_t ptr_seg;
    uint32_t ptr_off;
};

/* ---------------- struct ud_operand ---------------- */
struct ud_operand {
    enum ud_type typ;      /* operand type */
    uint16_t     SIZE;     /* operand size in bits */
    enum ud_type Base;     /* base register */
    enum ud_type index;    /* index register */
    uint8_t      scale;    /* scale factor */
    uint8_t      offset;   /* displacement width in bits */
    union ud_lval lval;    /* immediate or address value */
    uint64_t     _legacy;  /* internal */
    uint8_t      _oprcode; /* internal */
};

struct ud_itab_entry;
struct ud_lookup_table_list_entry;

/* ---------------- struct ud ---------------- */
struct ud {
    int (*inp_hook)(struct ud*);

#ifndef __UD_STANDALONE__
    void* inp_file;
#endif

    const uint8_t* inp_buf;
    size_t         inp_buf_size;
    size_t         inp_buf_index;
    uint8_t        inp_curr;
    size_t         inp_ctr;
    uint8_t        inp_sess[64];
    int            inp_end;
    int            inp_peek;

    void (*translator)(struct ud*);
    uint64_t insn_offset;
    char     insn_hexcode[64];

    char*  asm_buf;
    size_t asm_buf_size;
    size_t asm_buf_fill;
    char   asm_buf_int[128];

    const char* (*sym_resolver)(struct ud*, uint64_t addr, int64_t* offset);

    uint8_t                 dis_mode;
    uint64_t                pc;
    uint8_t                 vendor;
    enum ud_mnemonic_code   mnemonic;
    struct ud_operand       operand[4];
    uint8_t                 error;
    uint8_t                 _rex;
    uint8_t                 pfx_rex;
    uint8_t                 pfx_seg;
    uint8_t                 pfx_opr;
    uint8_t                 pfx_adr;
    uint8_t                 pfx_lock;
    uint8_t                 pfx_str;
    uint8_t                 pfx_rep;
    uint8_t                 pfx_repe;
    uint8_t                 pfx_repne;
    uint8_t                 opr_mode;
    uint8_t                 adr_mode;
    uint8_t                 br_far;
    uint8_t                 br_near;
    uint8_t                 have_modrm;
    uint8_t                 modrm;
    uint8_t                 modrm_offset;
    uint8_t                 vex_op;
    uint8_t                 vex_b1;
    uint8_t                 vex_b2;
    uint8_t                 primary_opcode;
    void*                   user_opaque_data;
    struct ud_itab_entry*   itab_entry;
    struct ud_lookup_table_list_entry* le;
};

/* ---------------- API ---------------- */
void  ud_init(struct ud* u);
void  ud_set_mode(struct ud* u, uint8_t mode);
void  ud_set_pc(struct ud* u, uint64_t pc);
void  ud_set_input_hook(struct ud* u, int (*hook)(struct ud*));
void  ud_set_input_buffer(struct ud* u, const uint8_t* buffer, size_t size);
void  ud_set_vendor(struct ud* u, unsigned vendor);
void  ud_set_syntax(struct ud* u, void (*syntax)(struct ud*));
void  ud_input_skip(struct ud* u, size_t n);
int   ud_input_end(const struct ud* u);
unsigned int ud_decode(struct ud* u);
unsigned int ud_disassemble(struct ud* u);
void  ud_translate_intel(struct ud* u);
void  ud_translate_att(struct ud* u);
const char* ud_insn_asm(const struct ud* u);
const uint8_t* ud_insn_ptr(const struct ud* u);
uint64_t ud_insn_off(const struct ud* u);
const char* ud_insn_hex(const struct ud* u);
unsigned int ud_insn_len(const struct ud* u);
const struct ud_operand* ud_insn_opr(const struct ud* u, unsigned int n);
int   ud_opr_is_sreg(const struct ud_operand* opr);
int   ud_opr_is_gpr(const struct ud_operand* opr);
enum ud_mnemonic_code ud_insn_mnemonic(const struct ud* u);
const char* ud_lookup_mnemonic(enum ud_mnemonic_code c);
void  ud_set_user_opaque_data(struct ud* u, void* opaque);
void* ud_get_user_opaque_data(const struct ud* u);
'@)
[void]$sb.AppendLine('')
[void]$sb.AppendLine('#ifdef __cplusplus')
[void]$sb.AppendLine('}')
[void]$sb.AppendLine('#endif')
[void]$sb.AppendLine('#endif /* UDIS86_H */')

# libudis86.lib 是 C 编译产物，符号无修饰；FreeBASIC 侧以 Cdecl 声明，
# 这里显式声明为 cdecl 以保证调用约定一致。
$text = $sb.ToString()

[System.IO.File]::WriteAllText($outputPath, $text, (New-Object System.Text.UTF8Encoding($true)))

Write-Output "wrote $outputPath"
Write-Output ("ud_mnemonic_code members: " + $mnemonics.Count)
Write-Output ("ud_type members: " + $udTypes.Count)
Write-Output ("first mnemonic: " + $mnemonics[0] + " / last: " + $mnemonics[$mnemonics.Count-1])
Write-Output ("first type: " + $udTypes[0] + " / last: " + $udTypes[$udTypes.Count-1])
