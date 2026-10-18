"""Extract WDDM per-slot ground truth from the probe logs.

Reads every `D:\\wddm-probe-logs\\*.logdir\\*.log` and pulls the diagnostic
markers the VB WDDM backend emits through the --diag-log file sink:

    [CLASSIFY] Model=WDDM Confidence=... Reason=...
    [LOAD] Module=dxgkrnl.sys ... ImageBase=...
    [WDDM-BASELINE] RuntimeFunctionCount=N
    [WDDM-BASELINE] ...Candidate accepted... / Structural scan found no candidate
    [WDDM-BASELINE-SCORE] ...
    [MERGE] <IRP> FrameworkBaseline fills RVA=0x... VA=0x...
    [APPLY] Result=0x... Recovered=N FrameworkBaseline=N FrameworkOwned=N Unresolved=N

Writes gt.json + gt.txt next to the logs.
"""
from __future__ import annotations

import json
import re
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

LOGS = Path(r'D:\wddm-probe-logs')
# 真值输出目录随脚本自身定位（SnowSwordCore\_wddm_probe\inv），不依赖仓库外的检出路径。
OUT = Path(__file__).resolve().parent / 'inv'

IRP_NAMES = [
    'IRP_MJ_CREATE', 'IRP_MJ_CREATE_NAMED_PIPE', 'IRP_MJ_CLOSE', 'IRP_MJ_READ',
    'IRP_MJ_WRITE', 'IRP_MJ_QUERY_INFORMATION', 'IRP_MJ_SET_INFORMATION',
    'IRP_MJ_QUERY_EA', 'IRP_MJ_SET_EA', 'IRP_MJ_FLUSH_BUFFERS',
    'IRP_MJ_QUERY_VOLUME_INFORMATION', 'IRP_MJ_SET_VOLUME_INFORMATION',
    'IRP_MJ_DIRECTORY_CONTROL', 'IRP_MJ_FILE_SYSTEM_CONTROL',
    'IRP_MJ_DEVICE_CONTROL', 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
    'IRP_MJ_SHUTDOWN', 'IRP_MJ_LOCK_CONTROL', 'IRP_MJ_CLEANUP',
    'IRP_MJ_CREATE_MAILSLOT', 'IRP_MJ_QUERY_SECURITY', 'IRP_MJ_SET_SECURITY',
    'IRP_MJ_POWER', 'IRP_MJ_SYSTEM_CONTROL', 'IRP_MJ_DEVICE_CHANGE',
    'IRP_MJ_QUERY_QUOTA', 'IRP_MJ_SET_QUOTA', 'IRP_MJ_PNP',
]


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ('utf-8-sig', 'gbk', 'latin-1'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return ''


def slot_name(token: str) -> str:
    token = token.strip()
    if token.isdigit():
        index = int(token)
        if 0 <= index < len(IRP_NAMES):
            return IRP_NAMES[index]
        return f'slot{index}'
    return token


def parse(path: Path) -> dict:
    text = read_text(path)
    sample = path.parent.name.split('.')[0]

    classify = re.search(r'\[CLASSIFY\]\s+Module=(\S+)\s+Model=(\w+)\s+'
                         r'Confidence=(\d+)\s+Reason=(.*)', text)
    loads = re.findall(r'\[LOAD\]\s+Module=(\S+)\s+Path=(\S+)\s+'
                       r'ImageBase=(0x[0-9A-Fa-f]+)\s+FileSize=(0x[0-9A-Fa-f]+)', text)
    runtime_count = re.search(r'\[WDDM-BASELINE\]\s+RuntimeFunctionCount=(\d+)', text)
    no_candidate = 'Structural scan found no candidate' in text
    rejected = re.search(r'\[WDDM-BASELINE\]\s+Candidate rejected\s+Hits=(\d+)', text)
    score_rejects = re.findall(r'\[WDDM-BASELINE-SCORE\]\s+(\S+)', text)
    merges = re.findall(r'\[MERGE\]\s+(\S+)\s+FrameworkBaseline fills\s+'
                        r'RVA=(0x[0-9A-Fa-f]+)\s+VA=(0x[0-9A-Fa-f]+)', text)
    outside = re.findall(r'\[WDDM-BASELINE\]\s+Reject outside dxgkrnl\s+Slot=(\S+)', text)
    apply_line = re.search(r'\[APPLY\]\s+Result=(0x[0-9A-Fa-f]+)\s+Recovered=(\d+)\s+'
                           r'FrameworkBaseline=(\d+)\s+FrameworkOwned=(\d+)\s+'
                           r'Unresolved=(\d+)', text)

    slots = OrderedDict()
    for token, rva, va in merges:
        slots[slot_name(token)] = {'rva': rva, 'va': va}

    return {
        'sample': sample,
        'log': str(path),
        'log_bytes': path.stat().st_size,
        'model': classify.group(2) if classify else None,
        'model_confidence': int(classify.group(3)) if classify else None,
        'reason': classify.group(4).strip() if classify else None,
        'dxgkrnl_load': ({'path': loads[0][1], 'image_base': loads[0][2],
                          'file_size': loads[0][3]} if loads else None),
        'runtime_function_count': int(runtime_count.group(1)) if runtime_count else None,
        'no_structural_candidate': no_candidate,
        'candidate_rejected_hits': int(rejected.group(1)) if rejected else None,
        'score_rejects': score_rejects,
        'baseline_slots': slots,
        'baseline_slot_count': len(slots),
        'reject_outside_dxgkrnl': [slot_name(t) for t in outside],
        'apply': (None if not apply_line else {
            'result': apply_line.group(1),
            'recovered': int(apply_line.group(2)),
            'framework_baseline': int(apply_line.group(3)),
            'framework_owned': int(apply_line.group(4)),
            'unresolved': int(apply_line.group(5)),
        }),
    }


def main() -> int:
    dirs = sorted(p for p in LOGS.glob('*.logdir') if p.is_dir())
    if not dirs:
        print(f'no log dirs under {LOGS}')
        return 1

    results = []
    for directory in dirs:
        for log in sorted(directory.glob('*.log')):
            if log.stat().st_size:
                results.append(parse(log))

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'gt.json').write_text(
        json.dumps({'extracted': f'{datetime.now():%Y-%m-%d %H:%M:%S}',
                    'samples': results}, ensure_ascii=False, indent=2),
        encoding='utf-8')

    lines = [f'WDDM ground truth ({len(results)} sample log(s))', '=' * 78, '']
    for item in results:
        lines.append(f"{item['sample']}")
        lines.append(f"  model={item['model']} confidence={item['model_confidence']} "
                     f"reason={item['reason']}")
        load = item['dxgkrnl_load']
        lines.append(f"  dxgkrnl: base={load['image_base']} size={load['file_size']}"
                     if load else '  dxgkrnl: NOT LOADED')
        lines.append(f"  runtime functions scanned={item['runtime_function_count']} "
                     f"no_candidate={item['no_structural_candidate']} "
                     f"candidate_rejected_hits={item['candidate_rejected_hits']}")
        if item['score_rejects']:
            lines.append(f"  score rejects={item['score_rejects']}")
        apply_ = item['apply']
        if apply_:
            lines.append(f"  APPLY result={apply_['result']} recovered={apply_['recovered']} "
                         f"framework_baseline={apply_['framework_baseline']} "
                         f"framework_owned={apply_['framework_owned']} "
                         f"unresolved={apply_['unresolved']}")
        lines.append(f"  BASELINE SLOTS ({item['baseline_slot_count']}):")
        for name, slot in item['baseline_slots'].items():
            lines.append(f"    {name:34s} rva={slot['rva']:>10s}  va={slot['va']}")
        if item['reject_outside_dxgkrnl']:
            lines.append(f"  rejected outside dxgkrnl: {item['reject_outside_dxgkrnl']}")
        lines.append('')

    total = sum(item['baseline_slot_count'] for item in results)
    lines.append(f'TOTAL baseline slots across samples: {total}')
    (OUT / 'gt.txt').write_text('\n'.join(lines), encoding='utf-8')
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
