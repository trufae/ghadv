#!/usr/bin/env python3
"""Offline agent progress, output isolation, failure and interruption checks."""
import json
from contextlib import ExitStack
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def stub():
    root = Path(os.environ['TEST_ROOT'])
    name = Path(sys.argv[0]).name
    mode = os.environ.get('AGENT_MODE', '')
    streaming_claude = name == 'claude' and '--model' not in sys.argv
    if name == 'pmai':
        assert sys.argv[1] == '--progress' and len(sys.argv) == 3, sys.argv
        prompt = sys.argv[2]
    else:
        prompt = sys.stdin.read()
        expected = (['-p', '--output-format', 'stream-json', '--verbose'] if streaming_claude else
                    ['-p', '--model', 'fixture'] if name == 'claude' else ['exec', '-'])
        assert sys.argv[1:] == expected, sys.argv
    (root / 'agent-prompt').write_text(prompt)
    if streaming_claude:
        events = [
            {'type': 'system', 'subtype': 'init'},
            {'type': 'assistant', 'parent_tool_use_id': None, 'message': {'content': [
                {'type': 'text', 'text': 'Checking the café fixture'},
                {'type': 'tool_use', 'name': 'Read', 'input': {'file_path': 'fixture.c'}},
            ]}},
        ]
        for event in events:
            print(json.dumps(event, ensure_ascii=False), flush=True)
    elif mode != 'quiet':
        print('Checking the fixture live', file=sys.stderr, flush=True)
    # The test releases the agent only after it has observed live feedback.
    deadline = time.monotonic() + 30
    while not (root / 'agent-release').exists():
        assert time.monotonic() < deadline, 'No live feedback reached the parent'
        time.sleep(.02)
    reply = (root / 'reply').read_text()
    if streaming_claude:
        if mode == 'missing':
            return
        if mode == 'malformed':
            print('not JSON', flush=True)
            return
        if mode == 'error':
            print(json.dumps({'type': 'result', 'is_error': True, 'errors': ['fixture failure']}), flush=True)
            return
        print(json.dumps({'type': 'result', 'is_error': False, 'result': reply}), end='', flush=True)
    else:
        print(reply, end='', flush=True)
    if mode == 'nonzero':
        sys.exit(7)


def main():
    from workflow import REPLY, setup, saved_dir

    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghadv-progress-test-') as tmp, ExitStack() as cleanup:
        root = Path(tmp)
        setup(root)
        for name in ('claude', 'codex', 'pmai'):
            path = root / name
            path.write_text(f'#!{sys.executable}\n' + Path(__file__).read_text().split('\n', 1)[1])
            path.chmod(0o700)
        base = {k: v for k, v in os.environ.items() if not k.startswith('GHADV_') and k not in ('GH_HOST', 'GITLAB_HOST')}
        base.update(PATH=str(root) + os.pathsep + base['PATH'], TEST_ROOT=str(root), TMPDIR=str(root),
                    GHADV_PROVIDER='github', EDITOR='editor', EDITOR_MODE='fail')

        def check(agent=None, mode='', save=False):
            for name in ('agent-release', 'editor-buffer', 'payload.json', 'saved.json'):
                (root / name).unlink(missing_ok=True)
            env = base | {'AGENT_MODE': mode, 'EDITOR_MODE': '' if save else 'fail'}
            if agent is not None:
                env['GHADV_AI'] = agent
            claude = agent in (None, 'claude -p')
            marker = (b'agent still running (' if mode == 'quiet' else
                      b'[claude] tool: Read' if claude else b'Checking the fixture live')
            with (root / 'stdout').open('w+') as output:
                process = subprocess.Popen([binary, '-r', 'owner/repo', 'review', 'GHSA-test'],
                    cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.PIPE, start_new_session=True)
                log = bytearray()
                try:
                    deadline = time.monotonic() + 25
                    while marker not in log:
                        remaining = deadline - time.monotonic()
                        assert remaining > 0 and select.select([process.stderr], [], [], remaining)[0], log
                        chunk = os.read(process.stderr.fileno(), 65536)
                        assert chunk, (process.poll(), log.decode(errors='replace'))
                        log.extend(chunk)
                    output.seek(0)
                    directory = saved_dir(output.read())
                    cleanup.callback(shutil.rmtree, directory, ignore_errors=True)
                    prompt = (directory / 'prompt.txt').read_text()
                    # Shell command substitution strips only trailing newlines for pmai.
                    assert (root / 'agent-prompt').read_text() == (prompt.rstrip('\n') if agent and agent.startswith('pmai') else prompt)
                    if mode == 'interrupt':
                        os.killpg(process.pid, signal.SIGINT)
                    else:
                        (root / 'agent-release').touch()
                    _, rest = process.communicate(timeout=10)
                    log.extend(rest)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    process.stderr.close()
                output.seek(0)
                stdout = output.read()
                stderr = log.decode(errors='replace')
                if mode in ('missing', 'malformed', 'error', 'nonzero', 'interrupt'):
                    assert process.returncode != 0, stderr
                    assert not (root / 'editor-buffer').exists()
                    assert not (root / 'payload.json').exists()
                    assert (directory / 'reply.txt').read_text() == (REPLY if mode == 'nonzero' else 'Checking the café fixture\n')
                    assert (directory / 'claude.jsonl').exists()
                    if mode == 'error':
                        assert 'fixture failure' in stderr
                    if mode == 'interrupt':
                        assert process.returncode == 130 and 'Interrupted.' in stderr
                        (directory / 'reply.txt').write_text(REPLY)
                        resumed = subprocess.run([binary, 'resume', str(directory)], cwd=root,
                            env=base | {'EDITOR_MODE': '', 'GHADV_AI': 'false'}, capture_output=True, timeout=10)
                        assert resumed.returncode == 0, resumed.stderr
                        assert not directory.exists()
                else:
                    assert process.returncode == 0, stderr
                    assert 'Checking the café fixture' not in stdout and 'Checking the fixture live' not in stdout
                    assert '+summary: Revised' in (root / 'editor-buffer').read_text()
                    assert '"type"' not in (root / 'editor-buffer').read_text()
                    if save:
                        assert not directory.exists()
                        assert json.loads((root / 'payload.json').read_text())['summary'] == 'Revised'
                    else:
                        assert (directory / 'reply.txt').read_text() == REPLY

        check(save=True)  # Unset GHADV_AI uses Claude streaming and cleans up the raw log.
        check('claude -p')
        for mode in ('missing', 'malformed', 'error', 'nonzero', 'interrupt'):
            check('claude -p', mode)
        check('codex exec -')
        check('pmai --progress "$(cat)"')
        check('claude -p --model fixture')  # A custom command keeps its flags and plain stdout.
        check('pmai --progress "$(cat)"', 'quiet')
    print('Agent progress and recovery checks passed')


if __name__ == '__main__':
    if Path(sys.argv[0]).name in ('claude', 'codex', 'pmai'):
        stub()
    else:
        main()
