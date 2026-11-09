#!/usr/bin/env python3
"""Check CVE request receipts across CLI/TUI restarts using stub gh/git commands.

Usage: python3 test/cve.py /path/to/ghav
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from credits import Terminal


STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
assert args[0] == 'api', args
endpoint = next(a for a in args if a.startswith('repos/'))
assert '/security-advisories' in endpoint or '/issues?' in endpoint, args
if '/issues?' in endpoint:
    sys.exit(0)
if '--method' in args:
    assert args[args.index('--method') + 1] == 'POST' and endpoint.endswith('/cve'), args
    with (root / 'requests').open('a') as f:
        f.write(json.dumps(args) + '\\n')
    if (root / 'reject').exists():
        print('HTTP 422: request rejected', file=sys.stderr)
        sys.exit(1)
    if (root / 'fail-refresh').exists():
        (root / 'offline').touch()
    sys.exit(0)
if (root / 'offline').exists():
    print('HTTP 503: unavailable', file=sys.stderr)
    sys.exit(1)
cve = (root / 'assigned').read_text() if (root / 'assigned').exists() else ''
query = args[args.index('--jq') + 1]
if '--paginate' in args:
    print('GHSA-test\\tpublished\\t' + (cve or '-') + '\\thigh\\tTest advisory\\t\\t')
    print('GHSA-other\\tdraft\\t-\\tlow\\tOther advisory\\t\\t')
elif query == '.cve_id // ""':
    print(cve)
else:
    assert query.startswith('"advisory: ') and '.cve_id // "unassigned"' in query, query
    print('advisory: ' + endpoint.split('/')[-1] + '\\nstate: published\\ncve: '
          + (cve or 'unassigned') + '\\nprivate report: no\\nurl: https://github.com/' + endpoint)
'''


def checks(binary, root):
    (root / 'gh').write_text(STUB)
    (root / 'gh').chmod(0o700)
    (root / 'git').write_text('#!/bin/sh\nexit 0\n')
    (root / 'git').chmod(0o700)
    state = root / 'state'
    env = {'XDG_STATE_HOME': str(state), 'GH_HOST': 'github.com'}

    def run(command, identifier='GHSA-test', repo='owner/repo', ok=True, **extra):
        args = [binary, '-r', repo, command]
        if command != 'ls':
            args.append(identifier)
        result = subprocess.run(
            args, capture_output=True, text=True, cwd=root, timeout=5,
            env=os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'],
                              'TEST_ROOT': str(root)} | env | extra,
        )
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result.stdout + result.stderr

    def requests():
        path = root / 'requests'
        return path.read_text().splitlines() if path.exists() else []

    assert 'request status unknown' in run('status')
    assert 'requested*' not in run('ls')
    assert not state.exists(), 'reads must not create state directories'

    # A cancelled TUI action creates no receipt; a successful one survives exit.
    with Terminal(binary, root, 'tui', env) as ui:
        ui.expect('c request CVE')
        ui.send('c')
        ui.expect('request a CVE for GHSA-test?')
        ui.send('n')
        ui.expect('/ text')
        assert not requests() and not state.exists()
        ui.send('c')
        ui.expect('request a CVE for GHSA-test?')
        # Losing connectivity after acceptance must not hide the receipt.
        (root / 'fail-refresh').touch()
        ui.send('y')
        ui.expect('requested*')
        ui.send('q')
        ui.finish()

    (root / 'offline').unlink()
    (root / 'fail-refresh').unlink()
    assert len(requests()) == 1
    receipts = list((state / 'ghav' / 'cve-requests').iterdir())
    assert len(receipts) == 1
    stamp = receipts[0].read_text().strip()
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z', stamp), stamp
    status = run('status')
    assert stamp in status and 'recorded locally' in status and 'no CVE assigned' in status
    listing = run('ls')
    assert 'requested*' in listing.splitlines()[0]
    assert 'requested*' not in listing.splitlines()[1]
    assert 'request status unknown' in run('status', 'GHSA-other')

    with Terminal(binary, root, 'tui', env) as ui:
        screen = ui.expect('/ text')
        assert 'requested*' in screen and 'c request CVE' not in screen
        ui.send('c')
        ui.expect('CVE request already recorded locally')
        assert len(requests()) == 1
        ui.send('g')
        ui.expect('requested*')
        # A newly assigned ID replaces the receipt, including action hints.
        (root / 'assigned').write_text('CVE-2026-12345')
        ui.send('g')
        screen = ui.expect('/ text')
        assert 'CVE-2026-12345' in screen and 'requested*' not in screen
        ui.send('c')
        ui.expect('CVE already assigned: CVE-2026-12345')
        ui.send('q')
        ui.finish()

    assert 'cve: CVE-2026-12345' in run('status')
    assert 'requested*' not in run('status')
    assert 'requested*' not in run('ls')
    assert 'CVE already assigned' in run('cve') and len(requests()) == 1
    (root / 'assigned').unlink()

    # Host, repository and advisory scope are independent; casing is insignificant.
    assert 'requested*' not in run('ls', repo='owner/another')
    assert 'requested*' not in run('ls', GH_HOST='enterprise.example')
    assert 'requested*' in run('ls', repo='OWNER/REPO', GH_HOST='GITHUB.COM')
    assert 'requested*' in run('ls', GH_HOST='')
    assert 'requested*' in run('status', 'ghsa-TEST')

    # CLI and its alias record receipts too, and explicit retries remain possible.
    assert 'CVE request accepted' in run('approve', 'GHSA-other')
    assert run('ls').count('requested*') == 2
    assert 'CVE request accepted' in run('cve', 'GHSA-other')
    assert len(requests()) == 3

    # Neither failed POSTs nor failed preflight GETs create successful receipts.
    (root / 'reject').touch()
    assert 'HTTP 422' in run('cve', 'GHSA-failed', ok=False)
    assert 'request status unknown' in run('status', 'GHSA-failed')
    (root / 'reject').unlink()
    (root / 'offline').touch()
    before = len(requests())
    assert 'HTTP 503' in run('cve', 'GHSA-offline', ok=False)
    assert len(requests()) == before
    (root / 'offline').unlink()
    assert 'request status unknown' in run('status', 'GHSA-offline')

    # A disk error must not report that GitHub rejected an accepted request.
    blocked = root / 'not-a-directory'
    blocked.write_text('blocked')
    message = run('cve', 'GHSA-unsaved', XDG_STATE_HOME=str(blocked))
    assert 'CVE request accepted, but could not save' in message
    assert len(requests()) == before + 1
    assert 'request status unknown' in run('status', 'GHSA-unsaved')

    # Invalid/truncated receipts must not look like accepted requests.
    receipts[0].write_text('broken')
    assert 'request status unknown' in run('status')
    assert 'requested*' not in run('ls').splitlines()[0]


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghav-cve-test-') as tmp:
        checks(binary, Path(tmp))
    print('CVE request persistence checks passed')
