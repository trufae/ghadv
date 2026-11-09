#!/usr/bin/env python3
"""Exercise background loading and measure commit navigation, using stub gh/git.

Usage: python3 test/performance.py /path/to/ghadv [--benchmark-only]
"""

import json
import os
from pathlib import Path
import re
import statistics
import sys
import tempfile
import time

from credits import Terminal


STUB = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
if Path(sys.argv[0]).name == 'git':
    kind = 'commits' if args[:1] == ['log'] and '-n' in args else 'git-status'
elif args[:1] == ['repo']:
    kind = 'repository'
elif '--method' in args:
    kind = 'action'
elif any('/issues?' in a for a in args):
    kind = 'issues'
elif '--paginate' in args:
    kind = 'advisories'
else:
    kind = 'status'
# Capture before waiting, to exercise stale responses crossing a workflow update.
data = (root / kind).read_text() if (root / kind).exists() else ''
if kind == 'git-status' and args[0] == 'log':
    data = 'abcdef0\\ttest head\\n'
fd = os.open(root / 'calls', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, (json.dumps(kind) + '\\n').encode())
os.close(fd)
deadline = time.monotonic() + 15
while (root / ('hold-' + kind)).exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if (root / ('fail-' + kind)).exists():
    sys.exit('deliberate ' + kind + ' failure')
print(data, end='')
'''


def setup(root):
    for name in ('gh', 'git'):
        (root / name).write_text(STUB)
        (root / name).chmod(0o700)
    (root / 'repository').write_text('owner/repo\n')
    (root / 'git-status').write_text('')
    (root / 'status').write_text('advisory status loaded\n')
    (root / 'advisories').write_text(''.join(
        f'GHSA-{i:04}\tdraft\tCVE-2026-{i:04}\thigh\tAdvisory {i}\t{i+3000:040x}\t\n'
        for i in range(500)))
    (root / 'commits').write_text(''.join(
        f'{i:040x}\t2026-11-09\tcommit-{i:04} Fix bounds check 界 é ##security\n'
        for i in range(2000)))
    (root / 'issues').write_text('https://github.com/owner/repo/issues/1\t1\tissue\topen\tIssue one\n')


def wait_for(ui, predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert ui.process.poll() is None, ui.buffer
        assert time.monotonic() < deadline, ui.buffer
        ui.read(0.01)


def calls(root, kind):
    path = root / 'calls'
    return sum(json.loads(line) == kind for line in path.read_text().splitlines()) if path.exists() else 0


def selected(ui, index):
    wait_for(ui, lambda: re.search(r'\x1b\[7m[^\x1b]*commit-' + f'{index:04}', ui.buffer))


def navigation(binary, root):
    with Terminal(binary, root, 'tui', size=(160, 30)) as ui:
        ui.expect('advisories 500 (all)')
        ui.expect('commits 2000')
        ui.send('\t')
        ui.expect('[commits 2000]')
        before = (root / 'calls').read_text()
        durations = []
        for i in range(40):
            start = time.monotonic()
            ui.send('j' if i % 2 == 0 else 'k')
            selected(ui, 1 if i % 2 == 0 else 0)
            durations.append(time.monotonic() - start)
        assert (root / 'calls').read_text() == before, 'navigation spawned commands'
        print(f'2000 commits / 500 advisories: median {statistics.median(durations)*1000:.2f} ms/key, '
              f'max {max(durations)*1000:.2f} ms/key')
        durations = []
        for i in range(1, 65):
            start = time.monotonic()
            ui.send('j')
            selected(ui, i)
            if i > 30:
                durations.append(time.monotonic() - start)
        print(f'Scrolling past the viewport: median {statistics.median(durations)*1000:.2f} ms/key')
        assert (root / 'calls').read_text() == before, 'scrolling spawned commands'
        ui.send('q')
        ui.finish()


def background(binary, root):
    for kind in ('repository', 'advisories', 'issues', 'git-status'):
        (root / ('hold-' + kind)).touch()
    start = time.monotonic()
    with Terminal(binary, root, 'tui', size=(160, 30), repo=None, extra_env={'GHADV_REPO': ''}) as ui:
        wait_for(ui, lambda: 'Loading...' in ui.buffer, timeout=1)
        print(f'First screen with blocked repository/GitHub/Git: {(time.monotonic()-start)*1000:.2f} ms')
        ui.send('\t')
        ui.expect('[commits 2000]')
        ui.send('j')
        selected(ui, 1)
        (root / 'hold-repository').unlink()
        wait_for(ui, lambda: calls(root, 'advisories') > 0 and calls(root, 'issues') > 0)
        # Repeated reload requests must not start overlapping copies of a blocked job.
        ui.send('ggggg')
        ui.send('k')
        selected(ui, 0)
        assert calls(root, 'advisories') == 1 and calls(root, 'issues') == 1
        (root / 'hold-advisories').unlink()
        ui.expect('advisories 500 (all)')
        (root / 'hold-issues').unlink()
        ui.expect('issues/PRs 1 (cve)')
        (root / 'hold-git-status').unlink()
        ui.expect('test head')
        # A failed background reload preserves the working list and its selection.
        (root / 'fail-commits').touch()
        ui.send('g')
        ui.expect('deliberate commits failure')
        ui.send('j')
        selected(ui, 1)
        (root / 'fail-commits').unlink()
        # Status loading remains cancellable; returning must repaint the list.
        ui.send('\x1b[Z')
        ui.expect('[advisories 500 (all)]')
        (root / 'hold-status').touch()
        ui.send('s')
        ui.expect('Loading status for GHSA-0000')
        ui.send('\x1b')
        ui.expect('[advisories 500 (all)]')
        (root / 'hold-status').unlink()
        # Keep navigating while a confirmed mutation waits, and discard an older
        # list response when the mutation requires a fresh snapshot.
        (root / 'hold-advisories').touch()
        before = calls(root, 'advisories')
        ui.send('g')
        wait_for(ui, lambda: calls(root, 'advisories') > before)
        (root / 'hold-action').touch()
        ui.send('p')
        ui.expect('PUBLISH GHSA-0000?')
        ui.send('y')
        ui.expect('Updating GHSA-0000...')
        ui.send('j')
        wait_for(ui, lambda: re.search(r'\x1b\[7m[^\x1b]*GHSA-0001', ui.buffer))
        (root / 'advisories').write_text((root / 'advisories').read_text()
                                       .replace('Advisory 0\t', 'Fresh advisory\t')
                                       .replace('GHSA-0000\tdraft', 'GHSA-0000\tpublished'))
        (root / 'hold-action').unlink()
        ui.expect('advisory updated')
        ui.send('k')
        ui.expect('GHSA-0000 | published')
        ui.send('p')
        ui.expect('action unavailable for published')
        assert calls(root, 'action') == 1
        (root / 'hold-advisories').unlink()
        ui.expect('Fresh advisory')
        assert 'GHSA-0000 | draft' not in ui.buffer
        # Quitting does not wait for outstanding read-only requests.
        (root / 'hold-issues').touch()
        before = calls(root, 'issues')
        ui.send('g')
        wait_for(ui, lambda: calls(root, 'issues') > before)
        start = time.monotonic()
        ui.send('q')
        ui.finish()
        assert time.monotonic() - start < 1, 'quit waited for a background load'
        (root / 'hold-issues').unlink()


def repository_failure(binary, root):
    (root / 'fail-repository').touch()
    with Terminal(binary, root, 'tui', size=(160, 30), repo=None, extra_env={'GHADV_REPO': ''}) as ui:
        ui.expect('Cannot find repository.')
        ui.send('\t')
        ui.expect('[commits 2000]')
        ui.send('j')
        selected(ui, 1)
        (root / 'fail-repository').unlink()
        ui.send('g')
        ui.expect('advisories 500 (all)')
        ui.send('q')
        ui.finish()


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghadv-performance-') as tmp:
        root = Path(tmp)
        setup(root)
        navigation(binary, root)
    if '--benchmark-only' not in sys.argv:
        with tempfile.TemporaryDirectory(prefix='ghadv-background-') as tmp:
            root = Path(tmp)
            setup(root)
            background(binary, root)
            repository_failure(binary, root)
        print('Background loading, reload, status, action and quit checks passed')
