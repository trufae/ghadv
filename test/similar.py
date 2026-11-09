#!/usr/bin/env python3
"""Similar-bug CLI/TUI checks with stub commands; no network or real AI calls.

Usage: python3 test/similar.py /path/to/ghav
"""

import json
from pathlib import Path
import sys
import tempfile
import time

from credits import Terminal
from workflow import run, saved_dir, setup


COMMIT = 'abcdef1234567890abcdef1234567890abcdef1234'
UNLINKED = '1234567890abcdef1234567890abcdef1234567890'
REPORT = '# Similar bugs\n\nNo additional bugs confirmed. Checked sibling parsers.\n'
PATCH = 'diff --git a/parser.c b/parser.c\n+if (size > remaining) return false;\n'
STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
if Path(sys.argv[0]).name == 'git':
    assert args[0] == 'log', args
    print((root / 'commits').read_text(), end='')
    sys.exit(0)
with (root / 'gh.calls').open('a') as f:
    f.write(json.dumps(args) + '\\n')
assert args[0] == 'api' and '--method' not in args and '--input' not in args, args
endpoint = next(a for a in args if a.startswith('repos/'))
assert endpoint.startswith('repos/owner/repo/'), args
if (root / 'fail-source').exists():
    print('HTTP 503: unavailable', file=sys.stderr)
    sys.exit(1)
if endpoint == 'repos/owner/repo/security-advisories':
    print((root / 'advisories').read_text(), end='')
elif endpoint == 'repos/owner/repo/security-advisories/GHSA-test':
    print((root / 'original').read_text(), end='')
elif '/commits/' in endpoint or ('/pulls/' in endpoint and '-H' in args):
    print((root / 'patch').read_text(), end='')
elif '/comments?' in endpoint:
    print('Discussion: examine sibling readers')
elif '/issues/' in endpoint or '/pulls/' in endpoint:
    print('Source report: missing bounds check')
else:
    raise AssertionError(args)
'''


def last_prompt(root):
    return json.loads((root / 'ai.prompts').read_text().splitlines()[-1])


def cli_checks(binary, root):
    context = 'Check sibling parsers; $(touch should-not-exist) `false`'
    args = ['-r', 'owner/repo', 'similar', 'GHSA-test', context]
    result, _ = run(binary, root, args=args)
    assert result.returncode == 0, result.stdout
    directory = saved_dir(result.stdout)
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / 'reply.txt').read_text() == REPORT
    assert (directory / 'original.md').read_text() == (root / 'original').read_text()
    assert (root / 'viewed.md').read_text() == REPORT
    prompt = last_prompt(root)
    assert 'CVE-2026-12345' in prompt and 'Template bounds bug' in prompt
    assert f'Extra context: {context}' in prompt
    assert 'Markdown findings report' in prompt and 'high-confidence' in prompt
    assert 'summary: <one line title' not in prompt
    assert not (Path.cwd() / 'should-not-exist').exists()
    calls = (root / 'ai.calls').read_text(), (root / 'gh.calls').read_text()
    result, _ = run(binary, root, args=['resume', str(directory)])
    assert result.returncode == 0, result.stdout
    assert calls == ((root / 'ai.calls').read_text(), (root / 'gh.calls').read_text())
    assert directory.exists() and (root / 'viewed.md').read_text() == REPORT

    for selection in [COMMIT, UNLINKED, f'https://github.com/owner/repo/commit/{COMMIT}',
                      'https://github.com/owner/repo/issues/123',
                      'https://github.com/owner/repo/pull/456']:
        # URL forms must infer the repository without consulting the current checkout.
        prefix = [] if selection.startswith('https://') else ['-r', 'owner/repo']
        result, _ = run(binary, root, args=[*prefix, 'similar', selection], GHAV_REPO='')
        assert result.returncode == 0, result.stdout
        prompt = last_prompt(root)
        if selection == UNLINKED:
            assert 'Linked advisory:' not in prompt
        elif 'issues/' not in selection and 'pull/' not in selection:
            assert 'Linked advisory:' in prompt and 'CVE-2026-12345' in prompt
        if 'issues/' in selection or 'pull/' in selection:
            assert 'Source report: missing bounds check' in prompt
            assert 'Discussion: examine sibling readers' in prompt
        if 'issues/' not in selection:
            assert PATCH in prompt
        assert 'Source: https://github.com/owner/repo/' in prompt

    # Failures keep output for recovery and never open the editor or submit an advisory.
    for reply, extra, error in [('', {}, 'empty findings report'),
                                ('Partial search\n', {'AI_EXIT': '1'}, 'agent exited with status 1')]:
        (root / 'reply').write_text(reply)
        (root / 'viewed.md').unlink(missing_ok=True)
        result, _ = run(binary, root, args=args, **extra)
        assert result.returncode != 0 and error in result.stdout, result.stdout
        directory = saved_dir(result.stdout)
        assert (directory / 'reply.txt').read_text() == reply
        assert not (root / 'viewed.md').exists()
        if reply:
            before = (root / 'ai.calls').read_text()
            result, _ = run(binary, root, args=['resume', str(directory)])
            assert result.returncode == 0, result.stdout
            assert (root / 'viewed.md').read_text() == reply
            assert (root / 'ai.calls').read_text() == before

    before = (root / 'ai.calls').read_text()
    result, _ = run(binary, root, args=['-r', 'other/repo', 'similar',
                                      f'https://github.com/owner/repo/commit/{COMMIT}'])
    assert result.returncode != 0 and 'does not match' in result.stdout
    (root / 'fail-source').touch()
    result, _ = run(binary, root, args=args)
    assert result.returncode != 0 and 'HTTP 503' in result.stdout
    (root / 'fail-source').unlink()
    assert (root / 'ai.calls').read_text() == before
    (root / 'reply').write_text(REPORT)


def tui_checks(binary, root):
    env = {'GHAV_AI': 'ai', 'EDITOR': 'editor'}
    with Terminal(binary, root, 'tui', env, controlling=True) as ui:
        ui.expect('b similar bugs')
        # Both the actions menu and the post-view advisory prompt expose the action.
        ui.send('m')
        ui.expect('b Find similar bugs')
        ui.send('b')
        ui.expect('extra context (optional):')
        ui.send('Check parser callers\n')
        screen = ui.expect('Press Enter to return')
        assert REPORT.strip() in screen.replace('\r', '')
        assert 'Extra context: Check parser callers' in last_prompt(root)
        ui.send('v\n')
        ui.expect('[b] similar bugs')
        ui.send('b\n')
        ui.expect('extra context (optional):')
        ui.send('\n')
        ui.expect('Findings report saved')
        ui.expect('Press Enter to return')
        ui.send('\n')
        ui.expect('b similar bugs')

        before = (root / 'ai.calls').read_text()
        for cancel in ['\x1b', '\x03', '\x04']:
            ui.send('b')
            ui.expect('extra context (optional):')
            ui.send('unfinished' + cancel)
            ui.expect('b similar bugs')
        assert (root / 'ai.calls').read_text() == before

        ui.send('\t')
        ui.expect('COMMIT')
        for commit in [COMMIT, UNLINKED]:
            ui.send('b')
            screen = ui.expect('extra context (optional):')
            assert commit in screen
            ui.send('\n')
            ui.expect('Press Enter to return')
            prompt = last_prompt(root)
            assert f'Source: https://github.com/owner/repo/commit/{commit}' in prompt
            assert PATCH in prompt
            assert ('Linked advisory:' in prompt) == (commit == COMMIT)
            ui.send('\n')
            ui.expect('b similar bugs')
            ui.send('j')
        ui.send('q')
        ui.finish()

    # Empty lists reject the action; a cancelled context does not start the AI.
    before = (root / 'ai.calls').read_text()
    advisories = (root / 'advisories').read_text()
    (root / 'advisories').write_text('')
    with Terminal(binary, root, 'tui', env) as ui:
        ui.expect('No entries.')
        ui.send('b')
        ui.expect('no advisory selected')
        ui.send('q')
        ui.finish()
    (root / 'advisories').write_text(advisories)
    assert (root / 'ai.calls').read_text() == before

    # Ctrl+C during the search returns to the list and preserves a resumable partial report.
    with Terminal(binary, root, 'tui', env | {'AI_WAIT': '1'}, controlling=True) as ui:
        ui.expect('b similar bugs')
        ui.send('b')
        ui.expect('extra context (optional):')
        ui.send('\n')
        screen = ui.expect('running ai ...')
        directory = saved_dir(screen.replace('\r', ''))
        deadline = time.monotonic() + 5
        while not (root / 'ai.ready').exists():
            assert time.monotonic() < deadline
            time.sleep(0.02)
        ui.send('\x03')
        ui.expect('cancelled; recovery files')
        ui.expect('b similar bugs')
        assert (directory / 'reply.txt').read_text() == REPORT
        ui.send('q')
        ui.finish()


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghav-similar-test-') as tmp:
        root = Path(tmp)
        setup(root)
        for name in ['gh', 'git']:
            (root / name).write_text(STUB)
            (root / name).chmod(0o700)
        (root / 'original').write_text(
            f'# GHSA-test published CVE-2026-12345\nsummary: Template bounds bug\n'
            f'severity: high\n---\nMissing bounds check; fixed by {COMMIT}\n')
        (root / 'advisories').write_text(
            f'GHSA-test\tpublished\tCVE-2026-12345\thigh\tTemplate bounds bug\t{COMMIT}\t\n')
        (root / 'commits').write_text(
            f'{COMMIT}\t2026-01-01\tLinked fix\n{UNLINKED}\t2026-01-02\tUnlinked fix\n')
        (root / 'patch').write_text(PATCH)
        (root / 'reply').write_text(REPORT)
        cli_checks(binary, root)
        tui_checks(binary, root)
        assert not (root / 'editor-buffer').exists()
        calls = [json.loads(line) for line in (root / 'gh.calls').read_text().splitlines()]
        assert all('--method' not in args and '--input' not in args for args in calls)
    print('Similar-bug search checks passed')
