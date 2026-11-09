module main

import encoding.utf8
import term

fn test_clip_terminal_cells_and_styles() {
	assert clip_line('ab界cd', 4) == 'ab界'
	assert clip_line('ab界cd', 3) == 'ab'
	assert clip_line('🟠 fix', 2) == '🟠'
	assert clip_line('🟠 fix', 1) == ''
	assert clip_line('e\u0301x', 1) == 'e\u0301'
	assert clip_line('👩🏽‍💻x', 2) == '👩🏽‍💻'
	assert clip_line('🇯🇵x', 2) == '🇯🇵'
	assert clip_line('❤️x', 2) == '❤️'
	assert clip_line('text', 0) == ''
	assert clip_line('text', -1) == ''
	assert clip_line('\x1b[31m界xx\x1b[0m', 3) == '\x1b[31m界x\x1b[0m'
	assert clip_line('one\n\t\rtwo\x1b[2J\x1b[H!', 40) == 'one   two!'
	assert clip_line('a\x1b]0;title\x07b\x1b]8;;url\x1b\\c', 20) == 'abc'
	assert clip_line('a\x1b[', 20) == 'a'
}

fn test_rows_fit_every_width() {
	title := 'Fix 界 e\u0301 👩🏽‍💻 🟠 '.repeat(20)
	a := ['GHSA-abcd-efgh-ijkl', 'published', 'CVE-2026-123456789', 'critical', title, 'abcdef0123']
	for w in 1 .. 201 {
		for line in [row(a, w), crow(['abcdef0123456789', '2026-11-09', title], [a], w),
			irow(['url', '123456789', 'issue', 'closed', title], [a], w),
			row(['error:', title], w), crow(['error:', title], [a], w),
			irow(['error:', title], [a], w)] {
			plain := term.strip_ansi(line)
			assert utf8.validate_str(plain)
			mut width := 0
			for g in plain.graphemes() { width += cell_width(g) }
			assert width <= line_width(w), '${w}: ${plain}'
			assert !plain.contains('\n')
		}
	}
	assert row(a, 30).starts_with('Fix')
	assert crow(['short', 'date', title], [a], 80).contains('short')
}

fn test_small_layouts_and_scroll_limits() {
	for h in 1 .. 60 {
		for headers, footers in {2: 3, 3: 4, 1: 1} {
			layout := tui_layout(h, headers, footers)
			assert layout.page >= 1
			assert layout.head + layout.page + layout.foot == h
			frame := list_frame(layout, []string{len: headers, init: 'header'}, ['selected'],
				[]string{len: footers, init: 'footer'})
			assert frame.len == h
			assert frame[layout.head] == 'selected'
			for count in [0, 1, 4, 100] {
				for sel in 0 .. int_max(1, count) {
					for old in [-20, 0, 50, 1000] {
						top := list_top(old, sel, count, layout.page)
						assert top >= 0 && top <= int_max(0, count - layout.page)
						assert top <= sel && sel < top + layout.page
					}
				}
			}
		}
	}
	assert list_top(99, 99, 100, 10) == 90
	assert list_top(90, 0, 100, 10) == 0
	assert list_top(90, 99, 100, 200) == 0
}

fn test_render_updates_only_changed_rows_without_scrolling() {
	mut screen := TuiScreen{}
	first := screen.render(['one', 'two'], 10, 3)
	assert !first.contains('\n') && !first.contains('\r') && !first.contains('\x1b[2J')
	assert screen.render(['one', 'two'], 10, 3) == ''
	changed := screen.render(['one', 'short'], 10, 3)
	assert changed.contains('\x1b[2;1H') && changed.contains('short\x1b[0m\x1b[K')
	assert !changed.contains('\x1b[1;1H') && !changed.contains('\x1b[3;1H')
	shrunk := screen.render(['界', 'hidden'], 1, 1)
	assert screen.lines == ['']
	assert shrunk.contains('\x1b[1;1H') && !shrunk.contains('\x1b[2;1H')
	assert shrunk.starts_with('\x1b[?7l') && shrunk.ends_with('\x1b[?7h')
	screen.width = 0
	assert screen.render([''], 1, 1) != ''
}

fn test_wrapped_dialogs_and_input_tails() {
	assert wrap_text('abcd\n界x\n', 2) == ['ab', 'cd', '界', 'x', '']
	assert wrap_text('界x', 1) == ['?', 'x']
	assert input_line('Username: ', 'abcdefghijkl', 8) == 'Userijkl'
	assert input_line('Filter: ', 'abc界', 1) == ''
	assert input_line('Filter: ', 'abc界', 4) == 'Fi界'
}
