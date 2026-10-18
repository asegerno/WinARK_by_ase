"""Shared assembly helpers for the Phase 2 WDDM static probes.

Both probe harnesses (verify_wddm_detect.py, verify_wddm_baseline.py) build a
FreeBASIC program out of the repository's real source and need the same two
transformations, so they live here.

Note on `String` vs `StringW`: in FreeBASIC 64-bit both are 4-byte string
descriptors, so a procedure whose real signature says `As StringW` may be
declared (and called) with `As String` without an ABI difference.  The harness
therefore normalises the Unicode spelling away before emitting `Declare` lines.
"""
from pathlib import Path
import re
import subprocess

ROOT = Path(r'D:\GitHub Project\SnowSword')
DEFAULT_FBC = Path('D:/Programs/VisualFreeBasic6.0/Compile/'
                   'FreeBASIC-1.10.0-winlibs-gcc-9.3.0/fbc64.exe')


def read(path):
    return (ROOT / path).read_text(encoding='utf-8-sig')


def procedures(text):
    """Top-level Sub/Function bodies by line map.

    Deliberately NOT regex-driven for the body extent: a regex cannot reliably
    tell a procedure's terminator from the following blank lines, and pulling a
    declaration line into a body desynchronises the Declare list from the body
    list.  A procedure starts at a line whose trimmed form begins with
    Sub/Function and ends at its matching `End Sub` / `End Function`.
    """
    lines = text.split('\n')
    starts = [i for i, ln in enumerate(lines)
              if re.match(r'^\s*(?:Private |Public )?(?:Sub|Function)\s+\w+', ln)]
    ends = [i for i, ln in enumerate(lines)
            if re.match(r'^\s*End (?:Sub|Function)\s*$', ln)]
    assert len(starts) == len(ends), (len(starts), len(ends))
    bodies = []
    for begin, stop in zip(starts, ends):
        assert begin < stop, (begin, stop)
        bodies.append('\n'.join(lines[begin:stop + 1]).rstrip())
    return bodies


def _strip_comment(line):
    """Remove a trailing FreeBASIC `'` comment that sits outside a string.

    Necessary because some edited signatures carry a trailing remark *after*
    the line-continuation underscore (e.g. `ByRef Context As ..., _  ' <- new`),
    which would otherwise look like the end of the signature.
    """
    out = []
    in_string = False
    for ch in line:
        if ch == '"':
            in_string = not in_string
        elif ch == "'" and not in_string:
            break
        out.append(ch)
    return ''.join(out).rstrip()


def _header(body):
    """The procedure's signature, keeping FreeBASIC line continuations.

    The continuation form is preserved deliberately: collapsing a long
    multi-parameter signature onto one line exceeds FreeBASIC's line-length
    limit (error 147: "Default types or suffixes are only valid in ...").
    """
    lines = []
    for line in body.split('\n'):
        stripped = _strip_comment(line)
        lines.append(stripped)
        if not stripped.endswith(' _'):
            break
    return '\n'.join(lines)


def declarations(bodies):
    """`Declare` lines, in the same order as `bodies`."""
    out = []
    for body in bodies:
        text = re.sub(r'^(?:Private |Public )', '', _header(body))
        text = re.sub(r'\bStringW\b', 'String', text)
        out.append('Declare ' + text)
    return '\n'.join(out)


def names(bodies):
    return [re.search(r'(?:Sub|Function)\s+(\w+)', b).group(1) for b in bodies]


def compile_program(fbc, out_dir, bas_name, program):
    """Write the program and run fbc; return (exe, log), exe None on failure."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / bas_name
    path.write_text(program, encoding='utf-8')
    exe = out_dir / (Path(bas_name).stem + '.exe')
    proc = subprocess.run(
        [str(fbc), '-i', str(out_dir), '-i', str(ROOT / 'ring3/headers'),
         '-p', str(ROOT / 'ring3/Release64'), '-x', str(exe), str(path)],
        capture_output=True, text=True, encoding='utf-8', errors='replace')
    log = (proc.stdout or '') + (proc.stderr or '')
    (out_dir / (Path(bas_name).stem + '.build.log')).write_text(log, encoding='utf-8')
    if proc.returncode == 0 and exe.is_file():
        return exe, log
    return None, log
