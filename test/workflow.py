#!/usr/bin/env python3
"""Workflow smoke checks with fake gh, AI and editor commands; no network access.

Usage: python3 test/workflow.py /path/to/ghav
"""

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


ORIGINAL = '# GHSA-test draft\nsummary: Original\nseverity: high\n---\nBefore\n'
REPLY = 'Review notes\nsummary: Revised\nseverity: high\n---\nAfter\n'
MANUAL = 'summary: Manual\nseverity: low\n---\nResolved by hand\n'
STUB = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
name = Path(sys.argv[0]).name
if name == 'gh':
    args = sys.argv[1:]
    with (root / 'gh.calls').open('a') as f:
        f.write(json.dumps(args) + '\\n')
    if '--input' in args:
        payload = Path(args[args.index('--input') + 1]).read_text()
        (root / 'payload.json').write_text(payload)
        if (root / 'fail-api').exists():
            (root / 'fail-api').unlink()
            print('HTTP 422: rejected advisory', file=sys.stderr)
            sys.exit(1)
        print('GHSA-test')
    else:
        print((root / 'original').read_text(), end='')
elif name == 'ai':
    with (root / 'ai.calls').open('a') as f:
        f.write('run\\n')
    print((root / 'reply').read_text(), end='', flush=True)
    if os.environ.get('AI_WAIT'):
        (root / 'ai.ready').touch()
        time.sleep(30)
    sys.exit(int(os.environ.get('AI_EXIT', '0')))
else:
    path = Path(sys.argv[1])
    mode = os.environ.get('EDITOR_MODE', '')
    if mode == 'fail':
        sys.exit(2)
    if mode == 'empty':
        path.write_text('')
    if path.suffix == '.diff':
        if mode in ('broken', 'manual', 'retry'):
            if mode == 'retry' and (root / 'clean.diff').exists():
                path.write_text((root / 'clean.diff').read_text())
            else:
                (root / 'clean.diff').write_text(path.read_text())
                path.write_text(path.read_text() + 'broken line\\n')
        elif mode == 'invalid':
            path.write_text(path.read_text().replace('+summary: Revised', '+unknown: Revised'))
    elif mode in ('manual', 'api-edit'):
        path.write_text((root / 'manual').read_text())
'''


def saved_dir(output):
    match = re.search(r'Recovery files: (.+)', output)
    assert match, output
    return Path(match[1])


def run(binary, root, mode='', answer='', args=None, **extra):
    env = os.environ | {
        'PATH': str(root) + os.pathsep + os.environ['PATH'],
        'TEST_ROOT': str(root), 'TMPDIR': str(root),
        'GHAV_AI': 'ai', 'EDITOR': 'editor', 'EDITOR_MODE': mode,
    } | extra
    result = subprocess.run(
        [binary, *(args or ['-r', 'owner/repo', 'review', 'GHSA-test'])],
        env=env, input=answer, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=10,
    )
    return result, env


def setup(root):
    for name in ('gh', 'ai', 'editor'):
        (root / name).write_text(STUB)
        (root / name).chmod(0o700)
    for name, text in [('original', ORIGINAL), ('reply', REPLY), ('manual', MANUAL)]:
        (root / name).write_text(text)


def payload(root):
    return json.loads((root / 'payload.json').read_text())


def checks(binary, root):
    setup(root)
    for mode, choice, expected in [('broken', 'n', 'Revised'),
                                   ('invalid', 'n', 'Revised'),
                                   ('manual', 'm', 'Manual'),
                                   ('retry', 'd', 'Revised')]:
        (root / 'clean.diff').unlink(missing_ok=True)
        result, _ = run(binary, root, mode, choice + '\n')
        assert result.returncode == 0, result.stdout
        assert payload(root)['summary'] == expected, result.stdout
        assert not saved_dir(result.stdout).exists()

    result, _ = run(binary, root, 'broken', 'q\n')
    directory = saved_dir(result.stdout)
    assert 'Cannot apply review diff: line ' in result.stdout
    assert (directory / 'reply.txt').read_text() == REPLY
    assert (directory / 'original.md').read_text() == ORIGINAL
    assert (directory / 'review.diff').read_text().endswith('broken line\n')
    assert directory.stat().st_mode & 0o777 == 0o700
    ai_calls = (root / 'ai.calls').read_text()
    result, _ = run(binary, root, answer='n\n', args=['resume', str(directory)])
    assert result.returncode == 0, result.stdout
    assert (root / 'ai.calls').read_text() == ai_calls
    assert not directory.exists()

    (root / 'fail-api').touch()
    result, _ = run(binary, root, answer='q\n')
    assert result.returncode != 0, result.stdout
    directory = saved_dir(result.stdout)
    assert 'HTTP 422' in result.stdout
    assert (directory / 'result.md').read_text().endswith('After\n')
    (directory / 'user-notes').write_text('keep this')
    result, _ = run(binary, root, args=['resume', str(directory)])
    assert result.returncode == 0, result.stdout
    assert (directory / 'user-notes').read_text() == 'keep this'
    assert not (directory / 'reply.txt').exists()

    (root / 'fail-api').touch()
    result, _ = run(binary, root, 'api-edit', 'e\n')
    assert result.returncode == 0, result.stdout
    assert payload(root)['summary'] == 'Manual'

    for mode in ('empty', 'fail'):
        before = (root / 'payload.json').read_text()
        result, _ = run(binary, root, mode)
        assert saved_dir(result.stdout).exists()
        assert (root / 'payload.json').read_text() == before

    # Ordinary edit/new share the recovery path and must retain their save behavior.
    before = (root / 'payload.json').read_text()
    result, _ = run(binary, root, args=['-r', 'owner/repo', 'edit', 'GHSA-test'])
    assert saved_dir(result.stdout).exists()
    assert (root / 'payload.json').read_text() == before
    result, _ = run(binary, root, 'manual', args=['-r', 'owner/repo', 'edit', 'GHSA-test'])
    assert result.returncode == 0, result.stdout
    assert payload(root)['summary'] == 'Manual'
    result, _ = run(binary, root, args=['-r', 'owner/repo', 'new', 'abcdef1234'])
    assert result.returncode == 0, result.stdout
    assert payload(root)['summary'] == 'Revised'
    assert not saved_dir(result.stdout).exists()

    # EOF at either recovery prompt aborts without spinning or submitting changes.
    before = (root / 'payload.json').read_text()
    result, _ = run(binary, root, 'broken')
    assert saved_dir(result.stdout).exists()
    result, _ = run(binary, root, 'invalid', 'm\n')
    assert 'Edit again? [Y/n]' in result.stdout
    assert saved_dir(result.stdout).exists()
    assert (root / 'payload.json').read_text() == before

    # A nonzero AI exit must keep even a complete reply for a later resume.
    result, _ = run(binary, root, AI_EXIT='1')
    assert result.returncode != 0
    directory = saved_dir(result.stdout)
    assert (directory / 'reply.txt').read_text() == REPLY
    result, env = run(binary, root, args=['resume', str(directory)])
    assert result.returncode == 0, result.stdout

    # Ctrl+C while generating leaves partial output and gives a clean exit status.
    (root / 'reply').write_text('partial expensive analysis\n')
    with (root / 'interrupt.log').open('w+') as output:
        process = subprocess.Popen(
            [binary, '-r', 'owner/repo', 'review', 'GHSA-test'],
            env=env | {'AI_WAIT': '1'}, stdin=subprocess.PIPE,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not (root / 'ai.ready').exists():
                assert process.poll() is None
                assert time.monotonic() < deadline
                time.sleep(0.02)
            os.killpg(process.pid, signal.SIGINT)
            assert process.wait(timeout=5) == 130
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        output.seek(0)
        log = output.read()
        assert 'Interrupted. Saved work' in log, log
        directory = saved_dir(log)
        assert (directory / 'reply.txt').read_text() == 'partial expensive analysis\n'
        result, _ = run(binary, root, args=['resume', str(directory)])
        assert result.returncode != 0
        assert 'no advisory in saved reply.txt' in result.stdout
        assert (directory / 'reply.txt').exists()

    # Ctrl+C at the recovery prompt must also leave the edited diff intact.
    (root / 'reply').write_text(REPLY)
    with (root / 'prompt-interrupt.log').open('w+') as output:
        process = subprocess.Popen(
            [binary, '-r', 'owner/repo', 'review', 'GHSA-test'],
            env=env | {'EDITOR_MODE': 'broken'}, stdin=subprocess.PIPE,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                output.seek(0)
                if '[q]uit and keep files [q]:' in output.read():
                    break
                assert process.poll() is None
                assert time.monotonic() < deadline
                time.sleep(0.02)
            os.killpg(process.pid, signal.SIGINT)
            assert process.wait(timeout=5) == 130
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        output.seek(0)
        log = output.read()
        assert 'Interrupted. Saved work' in log, log
        directory = saved_dir(log)
        assert (directory / 'reply.txt').read_text() == REPLY
        assert (directory / 'review.diff').read_text().endswith('broken line\n')


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghav-workflow-test-') as tmp:
        checks(binary, Path(tmp))
    print('Workflow recovery checks passed')
