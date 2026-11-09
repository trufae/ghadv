#!/usr/bin/env python3
"""Exercise the credits TUI in a pseudo-terminal with a stub gh; no GitHub writes.

Usage: python3 test/credits.py /path/to/ghadv
"""

import codecs
import fcntl
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time


ROLES = ['finder', 'reporter', 'analyst', 'coordinator', 'remediation_developer',
         'remediation_reviewer', 'remediation_verifier', 'tool', 'sponsor', 'other']
INITIAL = [{'login': 'alice', 'type': 'finder'}]
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
with (root / 'calls').open('a') as f:
    f.write(json.dumps(args) + '\\n')
if any('/issues?' in a for a in args):
    sys.exit(0)
assert 'repos/owner/repo/security-advisories' in ' '.join(args)
if '--input' in args:
    assert args[args.index('--method') + 1] == 'PATCH'
    assert 'repos/owner/repo/security-advisories/GHSA-test' in args
    payload = json.loads(Path(args[args.index('--input') + 1]).read_text())
    assert list(payload) == ['credits'], payload
    with (root / 'writes').open('a') as f:
        f.write(json.dumps(payload) + '\\n')
    if (root / 'fail').exists():
        (root / 'fail').unlink()
        print('HTTP 422: invalid credit', file=sys.stderr)
        sys.exit(1)
    (root / 'credits.json').write_text(json.dumps(payload['credits']))
    print('GHSA-test')
elif '--paginate' in args:
    print('GHSA-test\\tdraft\\t-\\thigh\\tTest advisory\\t\\t')
else:
    assert args[args.index('--jq') + 1] == '.credits // []'
    print((root / 'credits.json').read_text())
'''


class Terminal:
    def __init__(self, binary, root, command='credits', extra_env=None, controlling=False,
                 size=(100, 24), repo='owner/repo'):
        self.controlling = controlling
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', size[1], size[0], 0, 0))
        self.attributes = termios.tcgetattr(self.slave)
        self.buffer = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')()
        args = [binary] + (['-r', repo] if repo else []) + [command]
        if command == 'credits':
            args.append('GHSA-test')
        self.process = subprocess.Popen(
            args, stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env=os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'],
                              'TEST_ROOT': str(root), 'TMPDIR': str(root),
                              'GHADV_LABEL': '', 'TERM': 'xterm-256color'} | (extra_env or {}),
            cwd=root, start_new_session=True,
            # Make typed Ctrl+C reach the foreground process group, as in a real terminal.
            preexec_fn=(lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0)) if controlling else None,
        )

    def read(self, timeout=0.1):
        if select.select([self.master], [], [], timeout)[0]:
            data = os.read(self.master, 65536)
            self.buffer += self.decoder.decode(data)
            return bool(data)
        return False

    def send(self, keys):
        while self.read(0):
            pass
        self.buffer = ''
        os.write(self.master, keys.encode())

    def expect(self, text):
        deadline = time.monotonic() + 5
        while text not in ANSI.sub('', self.buffer):
            assert self.process.poll() is None, self.buffer
            assert time.monotonic() < deadline, (text, self.buffer)
            self.read()
        return ANSI.sub('', self.buffer)

    def finish(self):
        deadline = time.monotonic() + 5
        while self.process.poll() is None:
            assert time.monotonic() < deadline, self.buffer
            self.read()
        assert self.process.returncode == 0, self.buffer
        while self.read(0):
            pass
        try:
            restored = termios.tcgetattr(self.slave)
        except termios.error:
            # macOS revokes the controlling PTY when its session leader exits.
            if self.controlling and sys.platform == 'darwin':
                return
            raise
        # macOS sets the transient PENDIN flag when canonical input is restored.
        restored[3] &= ~getattr(termios, 'PENDIN', 0)
        self.attributes[3] &= ~getattr(termios, 'PENDIN', 0)
        assert restored == self.attributes, ('terminal settings were not restored', self.attributes,
                                              restored, self.buffer)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.kill()
            deadline = time.monotonic() + 5
            while self.process.poll() is None and time.monotonic() < deadline:
                self.read()
            self.process.wait(timeout=1)
        os.close(self.master)
        os.close(self.slave)


def checks(binary, root):
    (root / 'gh').write_text(STUB)
    (root / 'gh').chmod(0o700)
    (root / 'credits.json').write_text(json.dumps(INITIAL))

    with Terminal(binary, root) as ui:
        ui.expect('1 entries | saved')
        ui.send('?')
        screen = ui.expect('Enter/1-9/0')
        assert all(role in screen for role in ROLES), screen
        ui.send('\x1b')
        ui.expect('1 entries | saved')
        ui.send('a@alice\n2')
        ui.expect('2 entries | unsaved changes')
        ui.send('aALICE\n1')
        ui.expect('already has the finder credit')
        ui.send('abob\n5')
        ui.expect('3 entries | unsaved changes')
        ui.send('e\x15bobby\n6')
        ui.expect('Credit staged')
        ui.send('s')
        ui.expect('Credits saved.')
        expected = INITIAL + [{'login': 'alice', 'type': 'reporter'},
                              {'login': 'bobby', 'type': 'remediation_reviewer'}]
        assert json.loads((root / 'credits.json').read_text()) == expected
        ui.send('d')
        ui.expect('2 entries | unsaved changes')
        ui.send('u')
        ui.expect('3 entries | saved')
        ui.send('ddd')
        ui.expect('0 entries | unsaved changes')
        (root / 'fail').touch()
        ui.send('s')
        ui.expect('Save failed; edits kept: HTTP 422')
        assert json.loads((root / 'credits.json').read_text()) == expected
        ui.send('s')
        ui.expect('Credits saved.')
        assert json.loads((root / 'credits.json').read_text()) == []
        ui.send('q')
        ui.finish()

    writes = (root / 'writes').read_text()
    with Terminal(binary, root) as ui:
        ui.expect('No credits yet.')
        ui.send('acarol\n1')
        ui.expect('1 entries | unsaved changes')
        ui.send('a\x7f\x7f\x03')
        ui.expect('1 entries | unsaved changes')
        ui.send('acancelled\n\x03')
        ui.expect('1 entries | unsaved changes')
        ui.send('\x03')
        ui.expect('Unsaved credits:')
        ui.send('c')
        ui.expect('1 entries | unsaved changes')
        ui.send('q')
        ui.expect('Unsaved credits:')
        ui.send('d')
        ui.finish()
    assert (root / 'writes').read_text() == writes

    # Keyboard navigation, save-on-exit, and the role numbered 0 (other).
    with Terminal(binary, root) as ui:
        ui.expect('No credits yet.')
        ui.send('adave\n\x1b[B\n')
        ui.expect('Credit staged')
        ui.send('adave\n0')
        ui.expect('2 entries | unsaved changes')
        ui.send('q')
        ui.expect('Unsaved credits:')
        ui.send('s')
        ui.finish()
    assert json.loads((root / 'credits.json').read_text()) == [
        {'login': 'dave', 'type': 'reporter'}, {'login': 'dave', 'type': 'other'}]

    # Scrolling and resizing keep the selected credit, including on short terminals.
    many = [{'login': 'user' + str(i), 'type': 'finder'} for i in range(25)]
    (root / 'credits.json').write_text(json.dumps(many))
    with Terminal(binary, root) as ui:
        ui.expect('25 entries | saved')
        fcntl.ioctl(ui.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 12, 60, 0, 0))
        ui.send('JJ')
        ui.expect('@user20')
        ui.send('e\n')
        ui.expect('Available credit roles')
        ui.send('kkkkkkkkkkjjjjjjjjj\n')
        ui.expect('Credit staged')
        ui.send('s')
        ui.expect('Credits saved.')
        ui.send('q')
        ui.finish()
    many[20]['type'] = 'other'
    assert json.loads((root / 'credits.json').read_text()) == many

    # Both the main list shortcut and actions menu reach the dedicated screen.
    (root / 'git').write_text('#!/bin/sh\nexit 0\n')
    (root / 'git').chmod(0o700)
    with Terminal(binary, root, 'tui') as ui:
        ui.expect('GHSA-test')
        ui.expect('C credits')
        ui.send('C')
        ui.expect('Credits | owner/repo | GHSA-test')
        ui.send('q')
        ui.expect('C credits')
        ui.send('m')
        ui.expect('C manage credits')
        ui.send('C')
        ui.expect('Credits | owner/repo | GHSA-test')
        ui.send('q')
        ui.expect('C credits')
        ui.send('q')
        ui.finish()


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ghadv-credits-test-') as tmp:
        checks(binary, Path(tmp))
    print('Credits TUI and API checks passed')
