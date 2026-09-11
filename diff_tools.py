"""Apply an agent-produced patch to an ARVO container, recompile, re-run the POC.

    python diff_tools.py --patch-run-id arvo-42540891-vul-1784232900-patch

Every stage is persisted to patch_verification as it completes, so a run that
dies in the compile still leaves its baseline and patch-application evidence.
See PATCH_VERIFICATION_PROPOSAL.md for the design and the reasoning behind the
field set.
"""
import argparse
import getpass
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from arvo_tools import run_command, standby_container, cleanup_container
from queries import (get_vuln_id, get_result_json, get_context,
                     get_original_crash_log, update_patch_crash_results,
                     start_patch_verification, update_patch_verification)

logger = logging.getLogger(__name__)

# No call in the previous implementation passed a timeout, which is why a slow
# ffmpeg rebuild read as a hang. A full arvo compile links every decoder fuzzer
# in the project (435 for ffmpeg), measured at ~30 min.
PULL_TIMEOUT = 1800
COMPILE_TIMEOUT = 3600
POC_TIMEOUT = 120

# Bounds on what goes into the database. The full compile log is teed to disk;
# see stream_compile.
EXTRACT_HEAD_LINES = 200
EXTRACT_TAIL_LINES = 2000
EXTRACT_MAX_BYTES = 256 * 1024
ERROR_PATTERNS = re.compile(
    r'error:|Error \d|undefined reference|No space left|fatal|'
    r'cannot find|Permission denied|Segmentation fault', re.I)

RUNS_DIR = Path('runs')


def setup_logger(log_path: str = 'diff_tools.log') -> None:
    """File plus stdout. The previous implementation configured a file-only
    handler, so nothing reached the terminal until after the compile."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_path), logging.StreamHandler(sys.stdout)],
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def run_and_report(cmd, label=None, **kwargs):
    """Run a command and log the outcome. Applier output is logged at INFO, not
    DEBUG -- 'Hunk #1 succeeded at 388 with fuzz 2' is the line you need when
    reading back a verdict, and it was being discarded."""
    kwargs.setdefault('check', False)
    kwargs.setdefault('stdout', subprocess.PIPE)
    kwargs.setdefault('stderr', subprocess.PIPE)

    result = run_command(cmd, **kwargs)
    tag = label or cmd[0]

    logger.info(f'{tag} (rc={result.returncode})')
    if result.stdout:
        logger.info(f'{tag} stdout: {result.stdout.rstrip()}')
    if result.stderr:
        logger.info(f'{tag} stderr: {result.stderr.rstrip()}')

    return result


# --- diff repair ------------------------------------------------------------

HUNK_RE = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$')
NO_NEWLINE = '\\'


def _is_file_header(lines, i: int) -> bool:
    """True if lines[i] starts a ---/+++ file header pair.

    A body line removing text that happens to begin with '--- ' is ambiguous
    with the next entry's header, so require the '+++ ' partner. Every stored
    diff has the pair; none has a removal line that looks like one.
    """
    l = lines[i]
    if l.startswith('--- '):
        return i + 1 < len(lines) and lines[i + 1].startswith('+++ ')
    if l.startswith('+++ '):
        return i > 0 and lines[i - 1].startswith('--- ')
    return False


def _split_lines(diff_text: str):
    """Split without inventing a trailing blank context line."""
    lines = diff_text.split('\n')
    trailing_newline = bool(lines) and lines[-1] == ''
    if trailing_newline:
        lines.pop()
    return lines, trailing_newline


def recount_hunks(diff_text: str):
    """Rewrite every @@ header whose counts disagree with its body.

    Returns (corrected_text, headers_rewritten). Headers that are already
    correct are preserved byte-for-byte, so a well-formed diff is untouched.

    39% of stored agent diffs carry at least one bad count. Left alone, a
    shortfall makes GNU patch over-read into the following hunk or entry and
    fail with 'malformed patch'.
    """
    if not diff_text:
        return diff_text, 0

    lines, trailing_newline = _split_lines(diff_text)
    out = []
    rewritten = 0
    i = 0

    while i < len(lines):
        m = HUNK_RE.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue

        old_start = int(m.group(1))
        declared_old = int(m.group(2)) if m.group(2) is not None else 1
        new_start = int(m.group(3))
        declared_new = int(m.group(4)) if m.group(4) is not None else 1
        heading = m.group(5)

        header_index = i
        i += 1
        body_start = i
        count_old = count_new = 0

        while i < len(lines):
            if HUNK_RE.match(lines[i]) or _is_file_header(lines, i):
                break
            ch = lines[i][:1]
            if ch == ' ':
                count_old += 1
                count_new += 1
            elif ch == '-':
                count_old += 1
            elif ch == '+':
                count_new += 1
            elif ch == NO_NEWLINE:
                pass            # '\ No newline at end of file'
            elif lines[i] == '':
                # A bare empty line is a context line with its space stripped.
                # Both appliers accept it, so it is counted, not rewritten.
                count_old += 1
                count_new += 1
            else:
                break           # junk between entries; not part of this hunk
            i += 1

        if (count_old, count_new) == (declared_old, declared_new):
            out.append(lines[header_index])
        else:
            old_part = f'{old_start}' if count_old == 1 else f'{old_start},{count_old}'
            new_part = f'{new_start}' if count_new == 1 else f'{new_start},{count_new}'
            out.append(f'@@ -{old_part} +{new_part} @@{heading}')
            rewritten += 1
            logger.info(f'recount: @@ -{old_start},{declared_old} +{new_start},'
                        f'{declared_new} @@ -> -{old_part} +{new_part} '
                        f'(body has -{count_old}/+{count_new})')

        out.extend(lines[body_start:i])

    text = '\n'.join(out)
    if trailing_newline or not text.endswith('\n'):
        text += '\n'
    return text, rewritten


def derive_strip_level(diff_text: str) -> int:
    """-p1 if every header path carries an a/ or b/ prefix, else -p0.

    The stored diffs are mixed style: 'libavcodec/mpegaudio_parser.c' needs -p0,
    'a/libavcodec/mjpegdec.c' needs -p1. Deciding from the headers replaces the
    old try-p0-then-p1 retry, which ran the second attempt against a tree the
    first may already have mutated. Prefix set matches
    analysis/loc_eval.norm_path.
    """
    paths = []
    for line in diff_text.split('\n'):
        if line.startswith('--- ') or line.startswith('+++ '):
            p = line[4:].strip().split('\t')[0]
            if p and p != '/dev/null':
                paths.append(p)

    if not paths:
        logger.warning('no file headers found in diff; defaulting to -p0')
        return 0

    if all(p.startswith(('a/', 'b/')) for p in paths):
        return 1
    return 0


FUZZ_RE = re.compile(r'with fuzz (\d+)')
HUNK_OK_RE = re.compile(r'^Hunk #\d+ succeeded', re.M)
HUNK_FAIL_RE = re.compile(r'^Hunk #\d+ FAILED', re.M)


def parse_patch_output(text: str) -> dict:
    """Pull the per-hunk outcome out of GNU patch's own reporting.

    Fuzz is recorded rather than forbidden: a hunk applied at fuzz 3 has had all
    its context discarded, and analysis needs to be able to filter on that.
    """
    text = text or ''
    fuzzes = [int(x) for x in FUZZ_RE.findall(text)]
    return {
        'hunks_ok': len(HUNK_OK_RE.findall(text)),
        'hunks_failed': len(HUNK_FAIL_RE.findall(text)),
        'max_fuzz': max(fuzzes) if fuzzes else 0,
        'malformed': 'malformed patch' in text.lower(),
    }


# --- stages -----------------------------------------------------------------

def build_patch_argv(project: str, workdir: str, strip: int, dry_run: bool):
    """GNU patch argv. Fuzz is left at the default of 2; the -F 3 an earlier
    revision used raised the ceiling to the maximum the context allows, which
    for these diffs (median 3 context lines) means applying unverified."""
    argv = ['patch']
    if workdir == '/src':
        argv += ['--directory', project]
    argv += [f'-p{strip}', '--force', '--no-backup-if-mismatch', '--ignore-whitespace']
    if dry_run:
        argv.append('--dry-run')
    return argv


def apply_patches(patches, container_name, project, workdir):
    """Recount, then dry-run and apply each entry separately.

    Entries are never concatenated: a miscounted hunk in one entry reaches into
    the next entry's header and takes the whole patch down with it. Results are
    aggregated into one record -- hunks fail, not entries, so the per-hunk
    counters plus patch's own narrative are the useful granularity.
    """
    combined_text, total_recounted = [], 0
    stdout_parts, stderr_parts = [], []
    worst_rc = 0
    hunks_ok = hunks_failed = max_fuzz = 0
    strip_levels = set()

    for idx, patch in enumerate(patches, start=1):
        raw = patch.get('diff') or ''
        target = patch.get('file') or f'entry {idx}'
        if not raw.strip():
            logger.warning(f'entry {idx} ({target}) has an empty diff; skipping')
            continue

        fixed, recounted = recount_hunks(raw)
        total_recounted += recounted
        strip = derive_strip_level(fixed)
        strip_levels.add(strip)
        combined_text.append(fixed)

        marker = f'=== entry {idx}: {target} (-p{strip}, {recounted} header(s) recounted) ==='
        stdout_parts.append(marker)
        logger.info(marker)

        dry = run_and_report(build_patch_argv(project, workdir, strip, dry_run=True),
                             label=f'patch --dry-run (entry {idx})',
                             container_name=container_name, input=fixed)
        stdout_parts.append(f'--- dry run (rc={dry.returncode}) ---')
        stdout_parts.append(dry.stdout or '')
        if dry.stderr:
            stderr_parts.append(f'[entry {idx} dry-run] {dry.stderr}')

        if dry.returncode != 0:
            # Nothing was written. Record and move on rather than mutating the
            # tree with a patch known not to apply.
            logger.error(f'entry {idx} ({target}) failed the dry run '
                         f'(rc={dry.returncode}); not applying')
            stats = parse_patch_output((dry.stdout or '') + (dry.stderr or ''))
            hunks_failed += stats['hunks_failed']
            worst_rc = max(worst_rc, dry.returncode)
            continue

        real = run_and_report(build_patch_argv(project, workdir, strip, dry_run=False),
                              label=f'patch (entry {idx})',
                              container_name=container_name, input=fixed)
        stdout_parts.append(f'--- apply (rc={real.returncode}) ---')
        stdout_parts.append(real.stdout or '')
        if real.stderr:
            stderr_parts.append(f'[entry {idx}] {real.stderr}')

        stats = parse_patch_output((real.stdout or '') + (real.stderr or ''))
        hunks_ok += stats['hunks_ok']
        hunks_failed += stats['hunks_failed']
        max_fuzz = max(max_fuzz, stats['max_fuzz'])
        worst_rc = max(worst_rc, real.returncode)

    patch_text = '\n'.join(combined_text)
    return {
        'patch_text': patch_text,
        'patch_sha256': hashlib.sha256(patch_text.encode('utf-8')).hexdigest(),
        'patch_recounted': total_recounted,
        'patch_strip': sorted(strip_levels)[0] if len(strip_levels) == 1
                       else (min(strip_levels) if strip_levels else None),
        'patch_argv': json.dumps(
            build_patch_argv(project, workdir,
                             sorted(strip_levels)[0] if strip_levels else 0,
                             dry_run=False)),
        'patch_rc': worst_rc,
        'patch_stdout': '\n'.join(p for p in stdout_parts if p is not None),
        'patch_stderr': '\n'.join(stderr_parts) or None,
        'patch_hunks_ok': hunks_ok,
        'patch_hunks_failed': hunks_failed,
        'patch_max_fuzz': max_fuzz,
    }


def _build_extract(head, tail, errors, total_lines, total_bytes):
    parts = [f'[capture] {total_lines} lines, {total_bytes} bytes total']
    if head:
        parts.append(f'--- first {len(head)} lines ---')
        parts.extend(head)
    if errors:
        parts.append(f'--- {len(errors)} matched line(s) ---')
        parts.extend(errors)
    if tail:
        parts.append(f'--- last {len(tail)} lines ---')
        parts.extend(tail)
    text = '\n'.join(parts)
    if len(text.encode('utf-8')) > EXTRACT_MAX_BYTES:
        clipped = text.encode('utf-8')[:EXTRACT_MAX_BYTES].decode('utf-8', 'ignore')
        text = clipped + f'\n[truncated at {EXTRACT_MAX_BYTES} bytes]'
    return text


def stream_compile(container_name: str, log_path: Path, timeout: int = COMPILE_TIMEOUT):
    """Run `arvo compile`, teeing the full output to disk and keeping a bounded
    extract for the database.

    Streams rather than buffering into a pipe: the previous implementation gave
    no sign of progress for the whole rebuild. stdout and stderr are merged --
    build.sh runs under `bash -eux`, so its trace and the compiler diagnostics
    interleave, and chronological order is what makes the log readable.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['docker', 'exec', container_name, 'arvo', 'compile']
    logger.info(f'arvo compile (timeout {timeout}s), teeing to {log_path}')

    head, tail, errors = [], deque(maxlen=EXTRACT_TAIL_LINES), []
    total_lines = total_bytes = 0
    timed_out = False
    started = time.monotonic()
    last_progress = started

    with open(log_path, 'w', encoding='utf-8', errors='replace') as sink:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                errors='replace', bufsize=1)
        try:
            for line in proc.stdout:
                sink.write(line)
                total_lines += 1
                total_bytes += len(line.encode('utf-8'))
                stripped = line.rstrip('\n')
                if len(head) < EXTRACT_HEAD_LINES:
                    head.append(stripped)
                tail.append(stripped)
                if ERROR_PATTERNS.search(stripped) and len(errors) < 500:
                    errors.append(stripped)

                now = time.monotonic()
                if now - last_progress >= 60:
                    logger.info(f'arvo compile: {total_lines} lines, '
                                f'{total_bytes // 1024} KiB, '
                                f'{int(now - started)}s elapsed')
                    last_progress = now

                if now - started > timeout:
                    timed_out = True
                    logger.error(f'arvo compile exceeded {timeout}s; killing')
                    proc.kill()
                    break
            proc.wait(timeout=30)
        except Exception:
            proc.kill()
            raise

    duration = time.monotonic() - started
    rc = proc.returncode
    logger.info(f'arvo compile finished rc={rc} in {duration:.0f}s '
                f'({total_lines} lines, {total_bytes // 1024} KiB)'
                + (' [TIMED OUT]' if timed_out else ''))

    return {
        'compile_rc': rc,
        'compile_output_extract': _build_extract(head, list(tail), errors,
                                                 total_lines, total_bytes),
        'compile_log_path': str(log_path),
        'compile_log_bytes': total_bytes,
        'compile_duration_s': round(duration, 1),
        'compile_timed_out': 1 if timed_out else 0,
    }


def run_poc(container_name: str, timeout: int = POC_TIMEOUT):
    """Re-run the POC against the patched build. Small enough to capture with a
    plain run(), so stdout and stderr stay separate -- the fuzzer banner goes to
    stdout and the ASAN report to stderr."""
    started = time.monotonic()
    timed_out = False
    try:
        result = run_command(['arvo'], container_name=container_name, check=False,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=timeout)
        rc, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc = None
        out = e.stdout.decode('utf-8', 'replace') if isinstance(e.stdout, bytes) else (e.stdout or '')
        err = e.stderr.decode('utf-8', 'replace') if isinstance(e.stderr, bytes) else (e.stderr or '')
        logger.error(f'POC re-run exceeded {timeout}s')

    duration = time.monotonic() - started
    logger.info(f'POC re-run rc={rc} in {duration:.1f}s'
                + (' [TIMED OUT]' if timed_out else ''))
    return {
        'poc_rc': rc,
        'poc_stdout': out,
        'poc_stderr': err,
        'poc_duration_s': round(duration, 1),
        'poc_timed_out': 1 if timed_out else 0,
    }


def handle_fuzzer_result(poc: dict, container_name: str):
    """Human adjudication. Returns (is_crash_resolved, note, poc) -- poc is
    replaced if the operator re-runs, so what gets stored is what was judged."""
    is_crash_resolved = None
    note = None

    while True:
        output = (poc.get('poc_stdout') or '') + (poc.get('poc_stderr') or '')
        print('\n--- Patched Fuzzer Output ---')
        print(output)
        print(f"Exit code: {poc.get('poc_rc')}"
              + ('  [TIMED OUT]' if poc.get('poc_timed_out') else ''))
        print('-----------------------------')
        choice = input('[r]e-run  |  [c]lassify  |  [q]uit: ').strip().lower()

        if choice == 'r':
            poc = run_poc(container_name)

        elif choice == 'c':
            class_choice = input(
                'Classify result: [s]uccess (Patch fixed vulnerability) | '
                '[u]nsuccessful (Crash persists) | [b]ack: ').strip().lower()

            if class_choice in ('s', 'u'):
                is_crash_resolved = (class_choice == 's')
                note = input('Note (optional, Enter to skip): ').strip() or None
                logger.info('User classified crash as '
                            + ('RESOLVED' if is_crash_resolved else 'UNRESOLVED')
                            + (f' -- {note}' if note else ''))
                break
            elif class_choice == 'b':
                continue
            else:
                print('Invalid choice. Returning to main menu.')

        elif choice == 'q':
            logger.info('User quit without classifying')
            break
        else:
            print('Invalid choice.')

    return is_crash_resolved, note, poc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Apply, recompile and re-test a patch run.')
    parser.add_argument('--patch-run-id', type=str, required=True,
                        help='Unique identifier for the specific patch run to write and test.')
    parser.add_argument('--compile-timeout', type=int, default=COMPILE_TIMEOUT)
    parser.add_argument('--poc-timeout', type=int, default=POC_TIMEOUT)
    args = parser.parse_args(argv)

    patch_run_id = args.patch_run_id
    container_name = patch_run_id

    vuln_row = get_vuln_id(patch_run_id)
    if not vuln_row:
        logger.error(f'No run found for {patch_run_id}')
        return 1
    vuln_id = vuln_row[0]

    project, crash_type, _ = get_context(vuln_id)
    baseline_log = get_original_crash_log(vuln_id)
    image_tag = f'n132/arvo:{vuln_id}-vul'

    applier_sha = hashlib.sha256(
        Path(__file__).read_bytes()).hexdigest()[:16]

    logger.info(f'Starting patch verification for {patch_run_id}')
    logger.info(f'  vuln {vuln_id}  project={project}  crash_type={crash_type}')
    logger.info(f'  image {image_tag}  applier {applier_sha}')
    logger.info(f'  timeouts: pull {PULL_TIMEOUT}s  compile {args.compile_timeout}s  '
                f'poc {args.poc_timeout}s')

    verification_id = None
    try:
        result_json = json.loads(get_result_json(patch_run_id)[0])
        patches = result_json.get('patches', [])
        if not patches:
            logger.error(f'{patch_run_id} has no patches in result_json; nothing to apply')
            return 1

        logger.info(f'Starting standby container {container_name}')
        standby_container(container_name, vuln_id)
        workdir = run_command(['pwd'], container_name=container_name,
                              stdout=subprocess.PIPE).stdout.strip()
        logger.info(f'arvo container working directory: {workdir}')

        verification_id = start_patch_verification(
            patch_run_id,
            started_at=_now(),
            applier_sha256=applier_sha,
            image_tag=image_tag,
            container_workdir=workdir,
            baseline_source='arvo.crash_output',
            baseline_log=baseline_log,
        )
        if verification_id is None:
            logger.error('Could not open a verification row; aborting')
            return 1

        logger.info(f'Baseline POC output ({len(baseline_log or "")} chars):\n{baseline_log}')

        # stage 2
        applied = apply_patches(patches, container_name, project, workdir)
        update_patch_verification(verification_id, applied)

        if applied['patch_rc'] != 0:
            logger.error(f"Patch did not apply cleanly (rc={applied['patch_rc']}, "
                         f"{applied['patch_hunks_failed']} hunk(s) failed). "
                         f'Stopping before compile; the attempt is recorded.')
            update_patch_verification(verification_id, {'finished_at': _now()})
            print('\n--- Patch Failed ---')
            print(applied['patch_stdout'])
            print('--------------------')
            return 1

        if applied['patch_max_fuzz']:
            logger.warning(f"Applied with fuzz up to {applied['patch_max_fuzz']} -- "
                           f'that much context was discarded. Recorded in '
                           f'patch_max_fuzz.')

        # stage 3
        log_path = RUNS_DIR / patch_run_id / f'compile_{verification_id}.log'
        compiled = stream_compile(container_name, log_path, args.compile_timeout)
        update_patch_verification(verification_id, compiled)

        if compiled['compile_rc'] != 0 or compiled['compile_timed_out']:
            logger.error(f"Compile did not succeed (rc={compiled['compile_rc']}"
                         + (', timed out' if compiled['compile_timed_out'] else '')
                         + f"). Full log: {log_path}")
            logger.error('A POC result after a failed compile does not reflect the '
                         'patched code. Stopping; the attempt is recorded.')
            update_patch_verification(verification_id, {'finished_at': _now()})
            return 1

        # stage 4
        poc = run_poc(container_name, args.poc_timeout)
        update_patch_verification(verification_id, poc)

        print('\n--- Baseline Fuzzer Output ---')
        print(baseline_log)
        print('------------------------------')

        is_crash_resolved, note, poc = handle_fuzzer_result(poc, container_name)
        update_patch_verification(verification_id, poc)

        if is_crash_resolved is not None:
            update_patch_verification(verification_id, {
                'is_crash_resolved': is_crash_resolved,
                'adjudicated_by': getpass.getuser(),
                'adjudicated_at': _now(),
                'adjudication_note': note,
            })
            # patch_data stays a denormalised view of the newest attempt so the
            # analysis/ scripts that read it keep working unchanged.
            update_patch_crash_results(
                run_id=patch_run_id,
                is_crash_resolved=is_crash_resolved,
                patch_crash_log=(poc.get('poc_stdout') or '') + (poc.get('poc_stderr') or ''),
                compile_errors=compiled['compile_output_extract'],
            )

        update_patch_verification(verification_id, {'finished_at': _now()})
        return 0

    except Exception as e:
        logger.exception(f'Verification failed for {patch_run_id}: {e}')
        if verification_id is not None:
            update_patch_verification(verification_id, {'finished_at': _now()})
        return 1

    finally:
        cleanup_container(container_name)


if __name__ == '__main__':
    setup_logger()
    sys.exit(main())
