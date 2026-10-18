"""Phase 2 WDDM baseline 真值对比：gt.json（VB 实测） vs wddm_gt_verify（Core）。

读取：
  _wddm_probe/inv/gt.json           VB 侧面（由 --diag-log 的 [MERGE] 行抽取）
  _wddm_probe/out_<stem>.txt        Core 侧 wddm_gt_verify 的完整输出

比对口径（用户指定的验收项）：
  1. modelKind / modelConfidence
  2. baseline slot 数量
  3. 每槽 RVA（逐槽、按 IRP_MJ 名字）
  4. 槽集合（哪些槽被 baseline 填了）

输出：逐样本 PASS/FAIL + 差异明细 + 汇总。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROBE = Path(__file__).resolve().parent
INV = PROBE / 'inv'
GT = INV / 'gt.json'

SLOT_RE = re.compile(
    r'SLOT\[\s*(\d+)\]\s+(\S+)\s+valid=(\d+)\s+state=(\d+)\s+owner=(\d+)\s+'
    r'src=(\d+)\s+conf=(\d+)\s+moduleBase=0x([0-9A-Fa-f]+)\s+rva=0x([0-9A-Fa-f]+)\s+'
    r'current=0x([0-9A-Fa-f]+)')
MODEL_RE = re.compile(r'MODEL modelKind=(\d+) frameworkKind=(\d+) modelConfidence=(\d+)')
SUMMARY_RE = re.compile(r'SUMMARY recovered=(\d+) frameworkOwned=(\d+) default=(\d+) unresolved=(\d+)')
LOAD_RE = re.compile(r'\[WDDM-BASELINE\] Loaded (\S+) ImageBase=(0x[0-9A-Fa-f]+) '
                     r'ImageSize=(0x[0-9A-Fa-f]+) FileSize=(0x[0-9A-Fa-f]+)')
RFC_RE = re.compile(r'\[WDDM-BASELINE\] RuntimeFunctionCount=(\d+)')

STATE_RECOVERED = 1
STATE_FRAMEWORK_OWNED = 2
# baseline 填出的槽有两种来源：
#   SS_SOURCE_FRAMEWORK_BASELINE (5) —— 结构扫描命中的 exact 槽
#   SS_SOURCE_FRAMEWORK_DEFAULT  (7) —— ApplyWddmUniformDefault 补出的众数默认槽
# 两者都是 RecoverDxgkrnlDispatchBaseline 的产物，属同一 baseline 语义。
SOURCE_FRAMEWORK_BASELINE = 5
SOURCE_FRAMEWORK_DEFAULT = 7

SAMPLE_ORDER = ['igdkmdn64', 'BasicRender', 'IndirectKmd', 'npu_kmd', 'BasicDisplay']


def parse_core(path: Path) -> dict:
    text = path.read_text(encoding='utf-8', errors='replace')

    model = MODEL_RE.search(text)
    summary = SUMMARY_RE.search(text)
    load = LOAD_RE.search(text)
    rfc = RFC_RE.search(text)

    slots = {}
    for m in SLOT_RE.finditer(text):
        index = int(m.group(1))
        slots[index] = {
            'name': m.group(2),
            'valid': int(m.group(3)),
            'state': int(m.group(4)),
            'owner': int(m.group(5)),
            'source': int(m.group(6)),
            'confidence': int(m.group(7)),
            'moduleBase': int(m.group(8), 16),
            'rva': int(m.group(9), 16),
        }

    # baseline 槽 = 由 RecoverDxgkrnlDispatchBaseline 填出的那些：
    # state=Recovered 且 source ∈ {FrameworkBaseline, FrameworkDefault}
    baseline = {i: s for i, s in slots.items()
                if s['state'] == STATE_RECOVERED
                and s['source'] in (SOURCE_FRAMEWORK_BASELINE, SOURCE_FRAMEWORK_DEFAULT)}

    return {
        'modelKind': int(model.group(1)) if model else None,
        'frameworkKind': int(model.group(2)) if model else None,
        'modelConfidence': int(model.group(3)) if model else None,
        'frameworkOwned': int(summary.group(2)) if summary else None,
        'recovered': int(summary.group(1)) if summary else None,
        'unresolved': int(summary.group(4)) if summary else None,
        'baseline_slots': baseline,
        'baseline_slot_count': len(baseline),
        'dxg_load': ({'base': load.group(2), 'imageSize': load.group(3),
                      'fileSize': load.group(4)} if load else None),
        'runtime_function_count': int(rfc.group(1)) if rfc else None,
    }


def main() -> int:
    if not GT.is_file():
        print(f'ground truth not found: {GT}')
        return 2

    gt = json.loads(GT.read_text(encoding='utf-8'))
    gt_by_stem = {}
    for item in gt['samples']:
        gt_by_stem[item['sample'].split('.')[0].lower()] = item

    all_pass = True
    lines = []
    lines.append('=' * 78)
    lines.append('Phase 2 WDDM baseline 真值对比：VB(--diag-log 实测) vs Core(重放 live 快照)')
    lines.append('=' * 78)

    for stem in SAMPLE_ORDER:
        key = stem.lower()
        gt_item = gt_by_stem.get(key)
        out_path = PROBE / f'out_{stem}.txt'

        lines.append('')
        lines.append('-' * 78)
        lines.append(f'{stem}   ({gt_item["sample"] if gt_item else "NO GT"})')
        lines.append('-' * 78)

        if gt_item is None:
            lines.append('  SKIP: no ground truth entry')
            all_pass = False
            continue
        if not out_path.is_file():
            lines.append(f'  SKIP: {out_path.name} not found (run wddm_gt_verify first)')
            all_pass = False
            continue

        core = parse_core(out_path)

        gt_model = gt_item['model']
        gt_conf = gt_item['model_confidence']
        core_model = 'WDDM' if core['modelKind'] == 3 else f'kind{core["modelKind"]}'

        model_ok = (core_model == gt_model and core['modelConfidence'] == gt_conf)
        lines.append(f'  model          VB={gt_model}/{gt_conf}   Core={core_model}/{core["modelConfidence"]}'
                     f'   {"OK" if model_ok else "**MISMATCH**"}')

        gt_slots = gt_item['baseline_slots']
        gt_count = gt_item['baseline_slot_count']
        count_ok = (core['baseline_slot_count'] == gt_count)
        lines.append(f'  slot count     VB={gt_count}   Core={core["baseline_slot_count"]}'
                     f'   {"OK" if count_ok else "**MISMATCH**"}')

        lines.append(f'  dxgkrnl load   Core base={core["dxg_load"]["base"] if core["dxg_load"] else "?"} '
                     f'imageSize={core["dxg_load"]["imageSize"] if core["dxg_load"] else "?"} '
                     f'fileSize={core["dxg_load"]["fileSize"] if core["dxg_load"] else "?"}')
        lines.append(f'  VB     dxgkrnl base={gt_item["dxgkrnl_load"]["image_base"]} '
                     f'fileSize(观测)={gt_item["dxgkrnl_load"]["file_size"]}')
        lines.append(f'  runtimeFns     VB={gt_item["runtime_function_count"]}   '
                     f'Core={core["runtime_function_count"]}')
        lines.append(f'  frameworkOwned VB(=[MERGE] 行数)={gt_count}   Core={core["frameworkOwned"]}')

        # 逐槽
        lines.append('')
        lines.append(f'  {"slot":<34} {"VB rva":>10} {"Core rva":>10}   verdict')
        core_slots = core['baseline_slots']
        all_names = sorted(set(gt_slots.keys()) | {core_slots[i]['name'] for i in core_slots})

        detail_ok = True
        for name in all_names:
            gt_rva = None
            for gname, gslot in gt_slots.items():
                if gname == name:
                    gt_rva = int(gslot['rva'], 16)
                    break
            core_rva = None
            for i, s in core_slots.items():
                if s['name'] == name:
                    core_rva = s['rva']
                    break

            if gt_rva is None:
                verdict = '**EXTRA in Core**'
                detail_ok = False
            elif core_rva is None:
                verdict = '**MISSING in Core**'
                detail_ok = False
            elif gt_rva == core_rva:
                verdict = 'OK'
            else:
                verdict = f'**MISMATCH (diff=0x{abs(gt_rva-core_rva):X})**'
                detail_ok = False

            lines.append(f'  {name:<34} {("-" if gt_rva is None else f"0x{gt_rva:X}"):>10} '
                         f'{("-" if core_rva is None else f"0x{core_rva:X}"):>10}   {verdict}')

        sample_ok = model_ok and count_ok and detail_ok
        all_pass = all_pass and sample_ok
        lines.append('')
        lines.append(f'  ==> {stem}: {"PASS" if sample_ok else "FAIL"}')

    lines.append('')
    lines.append('=' * 78)
    lines.append(f'OVERALL: {"PASS" if all_pass else "FAIL"}')
    lines.append('=' * 78)

    report = '\n'.join(lines)
    print(report)
    (PROBE / 'gt_compare_report.txt').write_text(report, encoding='utf-8')
    return 0 if all_pass else 1


if __name__ == '__main__':
    raise SystemExit(main())
