# Phase 2 — WDDM coverage probe runbook

Purpose: obtain the **real** WDDM baseline per-slot ground truth for the five
dxgkrnl samples, plus proof that the instrumented build is the one being run.
Everything here is read-mostly; the only source edits are already applied and
are listed in §5 for removal.

## 0. Why a probe is needed (verified facts)

- `DetectWddmDriver` **does** classify all 5 dxgkrnl samples as WDDM
  (confidence 80–100 vs threshold 70). Proven by the static oracle
  `_wddm_probe/verify_wddm_detect.py`, which compiles and runs the real VB code.
- `RecoverDxgkrnlDispatchBaseline` **cannot** be validated statically:
  `ScoreWddmBaselineCandidate` requires
  `expectedCount >= 6` (`DispatchSlotFrameworkOwned` slots produced by
  `MergeWddmDispatchResult`) and `exactCount >= 4`
  (live `Context.CurrentMajorFunction[i]` vs the candidate RVA). A static
  harness has no live snapshot, so its "no structural candidate" result is an
  artifact, **not** a real failure. Ground truth must come from a live run.
- CLI diagnostics are invisible because `Logger.OutputToUI` only appends to the
  in-memory `strLog` (consumed by the GUI RichEdit). The logger *is* started on
  the `--cli` / `--agent-pipe` path (`FrmMain.frm:1522` calls `InitLog`).

## 1. Prerequisites

- **An elevated (Administrator) shell.** The driver `SnowSword` is installed but
  STOPPED; `dispatch-function list` needs it loaded and needs
  `SE_LOAD_DRIVER_NAME` / `SE_DEBUG_NAME`.
- `D:\Programs\VisualFreeBasic6.0` (the VFB install) present — used by
  `validation/build_snowsword.py`.
- Python on PATH (the repo scripts use it).

## 2. Build the instrumented CLI executable

Run from the repository root, **with the work dir left at its default** so that
the compiler's `-i ../headers` resolves (the script assumes the work dir sits
next to `ring3/headers`; do not point `--work` at an arbitrary location).

```powershell
cd "D:\GitHub Project\SnowSword"
python validation\build_snowsword.py
```

Expected: a line per patched module, and in particular

```
  CODEGEN_SnowSword_DispatchWddm_MODULE.inc: ClearWddmBaselineCandidate, ... , MergeWddmDispatchResult
  CODEGEN_SnowSword_ModLog_MODULE.inc: InitLog
...
BUILD: PASS  ...\ring3\dsh_build\SnowSword.exe (NNNNNNN bytes)
```

The `DispatchWddm.inc` line is the whole point: before this session that module
was **absent** from `PATCHES`, so any edit to the WDDM source was silently
ignored by the build and would have produced a false regression.

## 3. Run the 5 WDDM samples with the diagnostic log enabled

Create the log directory first (`MkDir` in the probe block does not create
parents):

```powershell
New-Item -ItemType Directory -Force -Path "D:\wddm-probe-logs" | Out-Null
```

Then for each sample. **The `--addr` values below were refreshed on
2026-10-03 14:22 (post-boot) and come from `validation/cli-results-core/manifest.json`,
group `dxgkrnl`** — not from `validation/cli-results/manifest.json`, which is
stale (11:18, pre-boot):

```powershell
$exe = "D:\GitHub Project\SnowSword\ring3\dsh_build\SnowSword.exe"
& $exe -c "dispatch-function list --path \"C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_715821f1c885b416\igdkmdn64.sys\" --addr 0xFFFF9A89A7D37E10 --diag-log D:\wddm-probe-logs"
& $exe -c "dispatch-function list --path \"C:\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_505dbfb03b1f39fa\BasicRender.sys\" --addr 0xFFFF9A89A54CBC80 --diag-log D:\wddm-probe-logs"
& $exe -c "dispatch-function list --path C:\Windows\System32\drivers\IndirectKmd.sys --addr 0xFFFF9A89A9F14E00 --diag-log D:\wddm-probe-logs"
& $exe -c "dispatch-function list --path \"C:\Windows\System32\DriverStore\FileRepository\npu.inf_amd64_c174cd41587112dd\npu_kmd.sys\" --addr 0xFFFF9A89A80A9A00 --diag-log D:\wddm-probe-logs"
& $exe -c "dispatch-function list --path \"C:\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_2753efdbb0d9a226\BasicDisplay.sys\" --addr 0xFFFF9A89A54CDC80 --diag-log D:\wddm-probe-logs"
```

**Important:** `--addr` is the runtime `DRIVER_OBJECT` captured when the
manifest was generated. Any reboot invalidates them and `IOCTL_GetDriverInfo`
will reject the run. To refresh: collect a fresh inventory into a new
`--out` directory first (`kernel-modules.txt` + `system-drivers.json`), then run

```powershell
cd "D:\GitHub Project\SnowSword"
python validation\prepare_cli_regression.py --out validation\<new-dir>
```

## 4. What to send back

`D:\wddm-probe-logs\` — the logger writes one file per day
(`Logger.GetDailyLogName`, `YYYYMMDD.log`), appended.

The lines that answer the question (all emitted by real backend code):

| Marker | Meaning |
|---|---|
| `[CLASSIFY] Module=... Model=WDDM Confidence=... Reason=...` | `DetectWddmDriver` returned true |
| `[LOAD] Module=dxgkrnl.sys ... ImageBase=...` | dxgkrnl was loaded for the baseline scan |
| `[WDDM-BASELINE] RuntimeFunctionCount=N` | the structural scan actually ran |
| `[WDDM-BASELINE] Structural scan found no candidate` | scan ran, no candidate survived |
| `[WDDM-BASELINE] Candidate rejected Hits=N` | candidate found but `HitCount < 4` |
| `[WDDM-BASELINE-SCORE] REJECT(...)` | which hard gate rejected it, with counts |
| `[MERGE] <IRP> FrameworkBaseline fills RVA=0x... VA=0x...` | **a slot was actually recovered from the baseline** |
| `[WDDM-BASELINE] Reject outside dxgkrnl Slot=...` | baseline slot rejected by `IsAddressInModule` |
| `[APPLY] Result=0x... Recovered=N FrameworkBaseline=N FrameworkOwned=N Unresolved=N` | final per-run tallies |

Also send the normal stdout of each run (the 32-row table). Slot-level ground
truth is the `[MERGE]` set plus the `[APPLY]` counts.

## 5. Removing the probe afterwards

Everything added for the probe is removable in one step:

```powershell
python _wddm_probe\apply_probe_edits.py --revert
```

That restores `ModLog.Inc` and `build_snowsword.py` from their
`.pre-diagprobe` backups. If you prefer the probe to stay through Phase 2, the
`--diag-log` branch is inert unless the marker appears on the command line, so
it cannot affect any A/B run.

## 6. Scope discipline

The probe changes **only** where log lines go. It touches no recovery
algorithm, no constant, and no WDDM logic. The `build_snowsword.py` change adds
build propagation for `DispatchWddm.inc` and `ModLog.Inc` and nothing else.
