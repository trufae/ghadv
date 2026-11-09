#!/usr/bin/env python3
"""Exercise TUI filtering and selection with stub gh/git commands.

Usage: python3 test/filters.py /path/to/ghadv
"""

import json
from pathlib import Path
import sys
import tempfile

from credits import Terminal
from workflow import setup


STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
name = Path(sys.argv[0]).name
with (root / 'calls').open('a') as f:
    f.write(json.dumps([name, *args]) + '\\n')
if name == 'git':
    if args[0] == 'log':
        print((root / 'commits').read_text(), end='')
    else:
        assert args[0] == 'show', args
        print('Selected commit: ' + args[1])
else:
    assert args[0] == 'api' and '--method' not in args and '--input' not in args, args
    endpoint = next(a for a in args if a.startswith('repos/'))
    if endpoint == 'repos/owner/repo/security-advisories?per_page=100':
        print((root / 'advisories').read_text(), end='')
    elif endpoint.startswith('repos/owner/repo/issues?'):
        print((root / 'issues').read_text(), end='')
    else:
        print('Selected source: ' + endpoint)
'''


def filter_text(ui, text):
    ui.send('/')
    ui.expect('Filter text:')
    ui.send(text + '\n')
    return ui.expect('/ text')


def selected_advisory(ui, identifier):
    ui.send('m')
    ui.expect('Actions for ' + identifier)
    ui.send('\x1b')
    ui.expect('/ text')


def checks(binary, root):
    setup(root)
    for name in ['gh', 'git']:
        (root / name).write_text(STUB)
        (root / name).chmod(0o700)
    rows = [('one', 'triage', 'Alpha'), ('two', 'draft', 'Beta'),
            ('three', 'published', 'Gamma'), ('four', 'closed', 'Delta')]
    (root / 'advisories').write_text(''.join(
        f'GHSA-{name}\t{state}\tCVE-2026-100{i}\thigh\t{title} parser\t{str(i) * 40}'
        f'\thttps://github.com/owner/repo/issues/{i}\n'
        for i, (name, state, title) in enumerate(rows, 1)))
    (root / 'commits').write_text(''.join(
        f'{str(i) * 40}\t2026-01-01\t{title} fix\n'
        for i, (_, _, title) in enumerate(rows, 1)))
    (root / 'issues').write_text(''.join(
        f'https://github.com/owner/repo/issues/{i}\t{i}\tissue\topen\t{title} report\n'
        for i, (_, _, title) in enumerate(rows, 1)))
    with Terminal(binary, root, 'tui', {'GHADV_LABEL': 'security'}) as ui:
        ui.expect('advisories 4 (all)')
        for key, states in [('F', ['closed', 'published', 'draft', 'triage', 'all']),
                            ('f', ['triage', 'draft', 'published', 'closed', 'all'])]:
            for state in states:
                ui.send(key)
                ui.expect(f'advisories {4 if state == "all" else 1} ({state})')

        # Filtering resets the selected row, combines with state, and ignores case.
        ui.send('J')
        ui.expect('GHSA-four | closed')
        screen = filter_text(ui, 'bEtA')
        assert 'advisories 1 (all)' in screen and '/bEtA |' in screen
        selected_advisory(ui, 'GHSA-two')
        ui.send('f')
        ui.expect('No matches.')
        ui.send('m')
        ui.expect('no advisory selected')
        ui.send('F')
        ui.expect('advisories 1 (all)')
        for cancel in ['\x1b', '\x03', '\x04']:
            ui.send('/')
            ui.expect('Filter text:')
            ui.send('different' + cancel)
            ui.expect('/bEtA |')
        ui.send('g')
        # An unchanged reload emits no redraw; verify the retained selection instead.
        selected_advisory(ui, 'GHSA-two')
        assert 'No matches.' in filter_text(ui, '[literal.*]')
        assert 'advisories 4 (all)' in filter_text(ui, '')
        selected_advisory(ui, 'GHSA-one')
        filter_text(ui, 'CVE-2026-1003')
        selected_advisory(ui, 'GHSA-three')

        # Source selections must use the filtered row's underlying index.
        filter_text(ui, 'bEtA')
        ui.send('\t')
        ui.expect('[commits 4]')
        selected_advisory(ui, 'GHSA-two')
        screen = filter_text(ui, 'gamma')
        assert '[commits 1]' in screen
        ui.send('\n')
        ui.expect('Selected commit: ' + '3' * 40)
        ui.expect('/ text')
        selected_advisory(ui, 'GHSA-three')
        filter_text(ui, 'ghsa-two')
        selected_advisory(ui, 'GHSA-two')
        ui.send('\n')
        ui.expect('Selected commit: ' + '2' * 40)
        ui.expect('/ text')
        ui.send('\t')
        ui.expect('[issues/PRs 4 (security)]')
        selected_advisory(ui, 'GHSA-two')
        screen = filter_text(ui, 'gamma')
        assert '[issues/PRs 1 (security)]' in screen
        ui.send('\n')
        ui.expect('/ text')
        assert 'repos/owner/repo/issues/3' in (root / 'viewed.md').read_text()
        selected_advisory(ui, 'GHSA-three')

        # Each tab retains its query; linking cannot select a hidden destination row.
        ui.send('\t')
        ui.expect('/bEtA |')
        selected_advisory(ui, 'GHSA-two')
        ui.send('f')
        ui.expect('advisories 0 (triage)')
        ui.send('\t')
        ui.expect('/ghsa-two |')
        ui.send('\t')
        ui.expect('/gamma |')
        ui.send('\t')
        ui.expect('advisories 0 (triage)')
        ui.send('\t')
        ui.expect('/ghsa-two |')
        ui.send('\t')
        ui.expect('/gamma |')
        filter_text(ui, 'beta')
        ui.send('\t')
        ui.expect('advisories 1 (all)')
        selected_advisory(ui, 'GHSA-two')
        ui.send('q')
        ui.finish()
    calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
    assert ['git', 'show', '2' * 40] in calls and ['git', 'show', '3' * 40] in calls


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghadv-filter-test-') as tmp:
        checks(binary, Path(tmp))
    print('TUI filter checks passed')
