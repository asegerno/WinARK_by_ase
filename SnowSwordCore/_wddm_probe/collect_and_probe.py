"""Phase 2 WDDM probe: re-collect inventory, then capture the 5 dxgkrnl samples.

Why a dedicated script:
  `validation/cli_inventory.ps1` obtains `kernel-modules.txt` through
  `run_snowsword_cli.py`, which needs an ALREADY-RUNNING `--agent-pipe`
  SnowSword server.  No such process exists after a reboot, so the inventory
  cannot be re-collected by that script alone.  This wrapper starts the pipe
  server, re-collects the inventory through it, and then runs the 5 WDDM
  samples in one-shots.

Run elevated (the driver must load, and `dispatch-function list` needs
SE_LOAD_DRIVER_NAME).  All writes stay under the workspace.

Outputs (workspace):
  inv/kernel-modules.txt        kernel-module list through the pipe
  inv/system-drivers.json       Win32_SystemDriver snapshot
  inv/manifest.json             fresh --addr values (reboot invalidates old ones)
  inv/<stem>.cli.txt            stdout of each sample
  inv/<stem>.probe.log          the --diag-log file sink for that run
  inv/summary.json              per-sample result
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# 本仓库根：SnowSwordCore\_wddm_probe\collect_and_probe.py -> parents[2] == <repo>\
REPO = Path(__file__).resolve().parents[2]
WORK = Path(__file__).resolve().parent / 'inv'
RUNNER = REPO / 'validation' / 'run_snowsword_cli.py'
SERVER = REPO / 'ring3' / 'Release64' / 'SnowSword.exe'
# The freshly built instrumented exe (carries DispatchWddm.inc + --diag-log).
CANDIDATE_EXES = [
    REPO / 'ring3' / 'dsh_build' / 'SnowSword.exe',
    REPO / 'ring3' / 'Release64' / 'SnowSword.exe',
]
PIPE = 'snowsword_wddm_probe_20261003'
PYTHON = sys.executable
PIPE_BUSY = (231, 121)
CREATE_NEW_CONSOLE = 0x00000010

DXGKRNL = ['igdkmdn64.sys', 'BasicRender.sys', 'IndirectKmd.sys',
           'npu_kmd.sys', 'BasicDisplay.sys']

# The --diag-log directory must contain NO SPACES and needs no quoting.
# `ParseArgv`'s strip logic takes the token after `--diag-log` up to the first
# space, so a quoted path would be cut at its first space and keep the leading
# quote; `InitLog` then feeds that to MkDir (which cannot create parents) and
# the file sink never opens.  A space-free path avoids the whole issue.
LOG_ROOT = Path(r'D:\wddm-probe-logs')

LOG = WORK / 'run.log'


def log(message: str) -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    line = f'[{datetime.now():%H:%M:%S}] {message}'
    print(line, flush=True)
    with LOG.open('a', encoding='utf-8') as stream:
        stream.write(line + '\n')


def wait_pipe(present: bool, seconds: float) -> bool:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ok = kernel32.WaitNamedPipeW(f'\\\\.\\pipe\\{PIPE}', 0)
        if (bool(ok) or ctypes.get_last_error() in PIPE_BUSY) == present:
            return True
        time.sleep(0.5)
    return False


def exe_of_choice() -> Path:
    for candidate in CANDIDATE_EXES:
        if candidate.is_file():
            return candidate
    raise SystemExit('no SnowSword.exe found')


def start_server(exe: Path) -> subprocess.Popen:
    log(f'starting pipe server: {exe} --cli --agent-pipe {PIPE}')
    handle = subprocess.Popen([str(exe), '--cli', '--agent-pipe', PIPE],
                              cwd=str(exe.parent),
                              creationflags=CREATE_NEW_CONSOLE, close_fds=True)
    if not wait_pipe(True, 180):
        raise SystemExit('pipe server did not come up')
    log(f'pipe up (pid={handle.pid})')
    return handle


def pipe_command(command: str, output: Path, timeout: float = 180) -> int:
    """Send one command to the pipe server, tolerating a missing final prompt.

    The agent-pipe server does not re-print the `ANTIROOTKIT> ` prompt after
    every reply, and `run_snowsword_cli.py` raises TimeoutError when it never
    sees one.  The bytes already captured (and written by its `finally`) are
    what we want, so a timeout after data arrived is not an error.
    """
    result = subprocess.run([PYTHON, str(RUNNER), '--pipe', PIPE,
                             '--command', command, '--output', str(output),
                             '--timeout', str(timeout)],
                            cwd=str(REPO), capture_output=True, timeout=timeout + 90,
                            encoding='utf-8', errors='replace')
    size = output.stat().st_size if output.is_file() else 0
    log(f'  pipe cmd {command!r} -> rc={result.returncode} '
        f'{output.name} ({size} bytes)')
    return result.returncode


def load_driver_in_server(exe: Path) -> bool:
    """Load the driver *in the long-lived pipe server* so it stays loaded.

    A `-c load-driver` one-shot cannot serve here: `RunSingleCommand` ends with
    `UninitDriver(True)`, which unloads the driver the same process loaded, so
    the service is STOPPED again by the time the one-shot exits.  The pipe
    server outlives the command, so it must own the load.
    """
    scratch = WORK / 'load-driver.txt'
    pipe_command('load-driver', scratch, timeout=120)
    text = scratch.read_text(encoding='utf-8', errors='replace') if scratch.is_file() else ''
    ok = 'SUCCESS' in text.upper()
    log(f'load-driver in server: {"SUCCESS" if ok else "NOT CONFIRMED"}')
    return ok


def system_drivers() -> None:
    script = ("Get-CimInstance Win32_SystemDriver | "
              "Select-Object Name,State,ServiceType,PathName | "
              "ConvertTo-Json -Depth 4")
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive',
                             '-Command', script],
                            capture_output=True, text=True, encoding='utf-8',
                            errors='replace')
    (WORK / 'system-drivers.json').write_text(result.stdout, encoding='utf-8-sig')
    log(f'system-drivers.json {len(result.stdout)} bytes')


def build_manifest() -> dict:
    modules = {}
    for line in (WORK / 'kernel-modules.txt').read_text(
            encoding='utf-8', errors='replace').splitlines():
        fields = line.split('|')
        if len(fields) == 6 and fields[0].isdigit():
            modules[fields[1].lower()] = dict(name=fields[1], base=fields[2],
                                              size=fields[3], path=fields[4],
                                              driver_object=fields[5])
    jobs, missing = [], []
    for name in DXGKRNL:
        module = modules.get(name.lower())
        if not module or module['driver_object'] in ('0x0', '', None):
            missing.append({'name': name,
                            'reason': 'not in inventory' if not module else 'no DRIVER_OBJECT'})
            continue
        job = dict(module, group='dxgkrnl')
        path = Path(module['path'])
        job['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ''
        job['command'] = (f'dispatch-function list --path "{module["path"]}" '
                          f'--addr {module["driver_object"]}')
        jobs.append(job)
    manifest = {'jobs': jobs, 'missing': missing,
                'collected': f'{datetime.now():%Y-%m-%d %H:%M:%S}'}
    (WORK / 'manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    log(f'manifest: jobs={len(jobs)} missing={missing}')
    return manifest


def run_samples(exe: Path, manifest: dict) -> list:
    summary = []
    for job in manifest['jobs']:
        stem = Path(job['name']).stem
        # One directory PER SAMPLE: several processes (the pipe server and each
        # one-shot) share `Logger.GetDailyLogName()`, so a single directory
        # interleaves and truncates concurrent appends.  A distinct directory
        # per run keeps each process's output readable.
        probe_dir = LOG_ROOT / f'{stem}.{os.getpid()}.logdir'
        if probe_dir.exists():
            shutil.rmtree(probe_dir, ignore_errors=True)
        probe_dir.mkdir(parents=True, exist_ok=True)
        command = f'{job["command"]} --diag-log {probe_dir}'
        out_file = WORK / f'{stem}.cli.txt'
        result = subprocess.run([str(exe), '-c', command], cwd=str(exe.parent),
                                capture_output=True, timeout=300,
                                encoding='utf-8', errors='replace')
        text = (result.stdout or '') + ('\n--stderr--\n' + result.stderr
                                        if result.stderr else '')
        out_file.write_text(text, encoding='utf-8')

        rows = resolved = 0
        for line in text.splitlines():
            if line.startswith('ROWCOUNT:'):
                rows = int(line.split(':', 1)[1])
            if line.count('|') == 4 and line.split('|')[3] not in ('-', ''):
                resolved += 1

        # The file sink is opened lazily by the logger; collect whatever exists.
        probe_text = ''
        for candidate in sorted(probe_dir.glob('*')):
            if candidate.is_file():
                raw = candidate.read_bytes()
                for enc in ('utf-8-sig', 'gbk', 'latin-1'):
                    try:
                        probe_text += raw.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                shutil.copy2(candidate, WORK / f'{stem}.probe.log')

        markers = sorted({m for m in re.findall(
            r'\[(CLASSIFY|WDDM-BASELINE[^\]]*|WDDM-BASELINE-SCORE|MERGE|APPLY|'
            r'WDDM-EVIDENCE|LOAD|REJECT|ORCH)[^\]]*\]', probe_text)})
        merges = len(re.findall(r'\[MERGE\]', probe_text))
        entry = {'name': job['name'], 'group': 'dxgkrnl', 'rc': result.returncode,
                 'rows': rows, 'resolved': resolved,
                 'probe_bytes': len(probe_text), 'merge_lines': merges,
                 'markers': markers,
                 'addr': job['driver_object'], 'path': job['path']}
        summary.append(entry)
        log(f'{job["name"]}: rc={result.returncode} rows={rows} resolved={resolved} '
            f'probe={len(probe_text)}B merges={merges}')
        for marker in markers:
            log(f'    {marker}')
    (WORK / 'summary.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    return summary


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    exe = exe_of_choice()
    log('=' * 70)
    log(f'probe start; exe={exe} '
        f'({exe.stat().st_size} bytes, {datetime.fromtimestamp(exe.stat().st_mtime):%Y-%m-%d %H:%M})')

    server = None
    try:
        server = start_server(exe)
        if not load_driver_in_server(exe):
            log('WARNING: driver load not confirmed in the pipe server')
        pipe_command('kernel-module list', WORK / 'kernel-modules.txt', timeout=240)
        system_drivers()
        manifest = build_manifest()
        if not manifest['jobs']:
            log('FATAL: no dxgkrnl jobs resolved from the fresh inventory')
            return 2
        run_samples(exe, manifest)
    finally:
        if server is not None:
            subprocess.run(['taskkill', '/F', '/PID', str(server.pid)],
                           capture_output=True)
            log(f'pipe server {server.pid} stopped')
    log('probe done')
    return 0


if __name__ == '__main__':
    sys.exit(main())
