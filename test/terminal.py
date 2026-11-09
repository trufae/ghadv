#!/usr/bin/env python3
"""Check bounded TUI output, resizes, scrolling and redraws using a PTY and stub gh/git.

Usage: python3 test/terminal.py /path/to/ghadv
"""

import fcntl
from pathlib import Path
import re
import struct
import sys
import tempfile
import termios
import time
import unicodedata

from credits import Terminal


STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
assert '--method' not in args and '--input' not in args, args
if Path(sys.argv[0]).name == 'git':
    for i in range(30):
        print(f'{i:040x}\\t2026-11-09\\t{i:02} Fix 界 é ' + 'long subject ' * 30)
elif '.credits // []' in args:
    print(json.dumps([dict(login=f'user{i:02}', type='finder') for i in range(30)]))
elif any('/issues?' in a for a in args):
    for i in range(30):
        print(f'https://github.com/owner/repo/issues/{i+1}\\t{i+1}\\tissue\\topen\\t{i:02} Issue 界 ' + 'title ' * 30)
else:
    for i in range(30):
        print(f'GHSA-test-{i:02}\\tdraft\\t-\\thigh\\t{i:02} Vulnerability 界 é ' + 'summary ' * 30 + '\\t\\t')
with (root / 'calls').open('a') as f:
    f.write('done\\n')
'''

CSI = re.compile(r'\x1b\[([0-?]*)([ -/]*)([@-~])')


class Screen:
    """Track the subset of terminal output used by ghadv and reject implicit scrolling."""
    def __init__(self, size):
        self.resize(size)
        self.alt = False

    def resize(self, size):
        self.width, self.height = size
        self.rows = [''] * self.height
        self.x = self.y = 0

    def feed(self, data):
        i = 0
        while i < len(data):
            if data[i] == '\x1b':
                match = CSI.match(data, i)
                assert match, repr(data[i:])
                params, _, command = match.groups()
                i = match.end()
                if command == 'H':
                    row, column = map(int, params.split(';'))
                    assert 1 <= row <= self.height and 1 <= column <= self.width, (self.width, self.height, match[0])
                    self.x, self.y = column - 1, row - 1
                    if column == 1:
                        self.rows[self.y] = ''
                elif command in ('h', 'l'):
                    assert params in ('?7', '?25', '?1000', '?1006', '?1049'), match[0]
                    if params == '?1049':
                        self.alt = command == 'h'
                else:
                    assert command in ('m', 'K'), ('unexpected clear or movement', match[0])
                continue
            char = data[i]
            assert char >= ' ' and char != '\x7f', ('scrolling/control character', repr(data))
            cells = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1)
            self.x += cells
            assert self.x <= max(1, self.width - 1), (self.width, self.height, repr(data))
            self.rows[self.y] += char
            i += 1


def frame(ui, screen):
    deadline = time.monotonic() + 5
    while not ui.buffer:
        assert time.monotonic() < deadline, 'no frame after resize or input'
        assert ui.process.poll() is None
        ui.read()
    while ui.read(0.25):
        pass
    data = ui.buffer
    screen.feed(data)
    ui.buffer = ''
    return data


def resize(ui, screen, size):
    screen.resize(size)
    fcntl.ioctl(ui.slave, termios.TIOCSWINSZ, struct.pack('HHHH', size[1], size[0], 0, 0))
    frame(ui, screen)


def checks(binary, root):
    for name in ('gh', 'git'):
        (root / name).write_text(STUB)
        (root / name).chmod(0o700)
    sizes = [(1, 1), (2, 2), (5, 1), (10, 3), (19, 5), (20, 6), (39, 8),
             (40, 5), (60, 4), (79, 10), (80, 6), (120, 24)]
    with Terminal(binary, root, 'tui', size=(1, 1)) as ui:
        screen = Screen((1, 1))
        frame(ui, screen)
        assert screen.alt and screen.rows == ['0']
        ui.send('JJ')
        frame(ui, screen)
        assert screen.rows == ['2']
        for size in sizes[1:]:
            resize(ui, screen, size)
        assert any('20 Vulnerability' in row for row in screen.rows)

        # A reload of unchanged data does not clear or repaint the screen.
        calls = len((root / 'calls').read_text().splitlines())
        ui.send('g')
        deadline = time.monotonic() + 5
        while len((root / 'calls').read_text().splitlines()) < calls + 3:
            assert time.monotonic() < deadline
            ui.read(0.1)
        ui.read(0.3)
        assert ui.buffer == '', repr(ui.buffer)

        # Scrolling beyond either end stops at the first/last entry.
        ui.send('JJJJ')
        ui.expect('GHSA-test-29 | draft')
        frame(ui, screen)
        assert any('29 Vulnerability' in row for row in screen.rows)
        ui.send('j')
        assert not ui.read(0.3)
        ui.send('KKKK')
        ui.expect('GHSA-test-00 | draft')
        frame(ui, screen)
        assert any('00 Vulnerability' in row for row in screen.rows), screen.rows
        ui.send('k')
        assert not ui.read(0.3)

        # Every tab remains bounded through narrow and short resizes.
        for key in ('\t', '\t', '\t'):
            ui.send(key)
            frame(ui, screen)
            for size in ((7, 2), (30, 4), (120, 24)):
                resize(ui, screen, size)

        # Dialogs, confirmation cancellation, help and the filter form also resize.
        for key in ('m', 'p', '?', 's', '/'):
            ui.send(key)
            if key == 's':
                ui.expect('j/k: scroll; choose key; Enter/Esc: cancel')
            frame(ui, screen)
            for size in ((1, 1), (15, 3), (120, 24)):
                resize(ui, screen, size)
                if size == (1, 1) and key != '/':
                    ui.send('J')
                    frame(ui, screen)
            ui.send('\x1b')
            frame(ui, screen)

        ui.send('/')
        frame(ui, screen)
        ui.send('nomatch\n')
        frame(ui, screen)
        assert any('No matches.' in row for row in screen.rows)
        for size in ((1, 1), (10, 2), (120, 24)):
            resize(ui, screen, size)
        ui.send('q')
        ui.finish()
        screen.feed(ui.buffer)
        assert not screen.alt

    # The standalone credits UI and both nested forms obey the same bounds.
    with Terminal(binary, root, size=(1, 1)) as ui:
        screen = Screen((1, 1))
        frame(ui, screen)
        for size in sizes[1:]:
            resize(ui, screen, size)
        for key in ('?', 'a'):
            ui.send(key)
            frame(ui, screen)
            for size in ((1, 1), (8, 2), (120, 24)):
                resize(ui, screen, size)
            ui.send('\x1b')
            frame(ui, screen)
        ui.send('d')
        frame(ui, screen)
        ui.send('q')
        frame(ui, screen)
        resize(ui, screen, (1, 1))
        ui.send('d')
        ui.finish()
        screen.feed(ui.buffer)
        assert not screen.alt


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='ghadv-terminal-test-') as tmp:
        checks(str(Path(sys.argv[1]).resolve()), Path(tmp))
    print('Terminal size, resize, scrolling and redraw checks passed')
