module main

import os
import term
import encoding.utf8.east_asian

// Count terminal cells, keeping combining characters and emoji sequences together.
fn cell_width(grapheme string) int {
	if grapheme.len == 1 && grapheme[0] < 0x80 { return 1 }
	mut width := 0
	for r in grapheme.runes() {
		rune_width := term.printable_len(r.str())
		if rune_width > 0 {
			width = int_max(width, int_max(rune_width, east_asian.display_width(r.str(), 1)))
		}
		if r == 0xfe0f || (r >= 0x1f1e6 && r <= 0x1f1ff) { width = 2 }
	}
	return width
}

// Keep only SGR styling, flatten control characters, and never split a grapheme.
// Every list entry occupies exactly one physical row, even with Unicode text.
fn clip_line(text string, width int) string {
	if width <= 0 { return '' }
	mut out := ''
	mut used := 0
	mut styled := false
	mut i := 0
	for i < text.len {
		if text[i] == 0x1b {
			start := i
			i++
			if i < text.len && text[i] == `[` {
				i++
				for i < text.len && (text[i] < 0x40 || text[i] > 0x7e) { i++ }
				if i < text.len {
					if text[i] == `m` && text[start + 2..i].bytes().all(it.is_digit() || it in [`;`, `:`]) {
						out += text[start..i + 1]
						styled = true
					}
					i++
				}
			} else if i < text.len && text[i] in [`]`, `P`, `X`, `^`, `_`] {
				i++
				for i < text.len && text[i] != 7 && text[i] != 0x1b { i++ }
				if i < text.len {
					i += if text[i] == 0x1b && i + 1 < text.len && text[i + 1] == `\\` { 2 } else { 1 }
				}
			} else {
				for i < text.len && text[i] >= 0x20 && text[i] <= 0x2f { i++ }
				if i < text.len { i++ }
			}
			continue
		}
		start := i
		for i < text.len && text[i] != 0x1b { i++ }
		for g in text[start..i].graphemes() {
			part := if g.runes().any(it < 0x20 || (it >= 0x7f && it < 0xa0)) { ' ' } else { g }
			cells := cell_width(part)
			if used + cells > width {
				return out + if styled { '\x1b[0m' } else { '' }
			}
			out += part
			used += cells
		}
	}
	return out + if styled { '\x1b[0m' } else { '' }
}

fn terminal_size() (int, int) {
	w, h := term.get_terminal_size()
	return int_max(1, w), int_max(1, h)
}

fn line_width(w int) int {
	return int_max(1, w - 1)
}

struct TuiLayout {
	head int
	page int
	foot int
}

// Sacrifice chrome before list space; even a one-row terminal has a selection.
fn tui_layout(height int, headers int, footers int) TuiLayout {
	h := int_max(1, height)
	head := if h >= headers + footers + 1 { headers } else if h >= 3 { int_min(1, headers) } else { 0 }
	foot := int_min(footers, h - head - 1)
	return TuiLayout{head, h - head - foot, foot}
}

fn list_top(top int, sel int, count int, page int) int {
	return int_min(int_max(0, count - page), int_max(0, int_min(int_max(top, sel - page + 1), sel)))
}

fn list_frame(layout TuiLayout, headers []string, body []string, footers []string) []string {
	mut lines := headers[..layout.head].clone()
	for i in 0 .. layout.page { lines << if i < body.len { body[i] } else { '' } }
	lines << footers[footers.len - layout.foot..]
	return lines
}

fn tui_tabs(tabs []string, view int, width int) string {
	for labels in [tabs, tabs.map(it.all_before(' '))] {
		line := labels.map(if it == labels[view] { term.inverse('[${it}]') } else { it }).join(' | ')
		plain := term.strip_ansi(line)
		if clip_line(plain, width) == plain { return line }
	}
	return term.inverse(clip_line('[${tabs[view]}]', width))
}

struct TuiScreen {
mut:
	lines []string
	width int
}

// Address rows explicitly: no newlines, terminal wrapping, or full-screen clears.
// Updating only changed rows also makes a no-op reload produce no screen traffic.
fn (mut screen TuiScreen) render(lines []string, width int, height int) string {
	w, h := int_max(1, width), int_max(1, height)
	mut next := []string{len: h}
	mut out := ''
	for i in 0 .. h {
		next[i] = clip_line(if i < lines.len { lines[i] } else { '' }, line_width(w))
		if screen.width != w || screen.lines.len != h || next[i] != screen.lines[i] {
			out += '\x1b[${i + 1};1H\x1b[0m${next[i]}\x1b[0m\x1b[K'
		}
	}
	screen.lines = next
	screen.width = w
	// Disable autowrap during painting, including when a resize races this frame.
	return if out == '' { '' } else { '\x1b[?7l${out}\x1b[?7h' }
}

fn (mut screen TuiScreen) draw(lines []string, w int, h int) {
	print(screen.render(lines, w, h))
	os.flush()
}

const tui_enter = '\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h'
const tui_leave = '\x1b[0m\x1b[?7h\x1b[?1000l\x1b[?1006l\x1b[?25h\x1b[?1049l'

fn wrap_text(text string, width int) []string {
	mut lines := []string{}
	for line in text.split('\n') {
		mut part := ''
		mut used := 0
		for g in term.strip_ansi(clip_line(line, line.len)).graphemes() {
			cells := cell_width(g)
			if used + cells > width && part != '' {
				lines << part
				part, used = '', 0
			}
			part += if cells > width { '?' } else { g }
			used += int_min(cells, width)
		}
		lines << part
	}
	return lines
}

// Menus and confirmations can be read a page at a time at any terminal size.
fn tui_dialog(text string) string {
	mut screen := TuiScreen{}
	mut top := 0
	for {
		w, h := terminal_size()
		lines := wrap_text(text, line_width(w))
		page := int_max(1, h - 1)
		top = int_min(int_max(0, top), int_max(0, lines.len - page))
		mut frame := lines[top..int_min(lines.len, top + page)].clone()
		if h > 1 {
			for frame.len < page { frame << '' }
			frame << 'j/k: scroll; choose key; Enter/Esc: cancel'
		}
		screen.draw(frame, w, h)
		k := key(w, h)
		match k {
			'' {}
			'j', '\x1b[B' { top++ }
			'k', '\x1b[A' { top-- }
			'J', '\x1b[6~', ' ' { top += page }
			'K', '\x1b[5~' { top -= page }
			else { return k }
		}
	}
	return ''
}

fn input_line(prompt string, text string, width int) string {
	mut text_width := 0
	for g in text.graphemes() { text_width += cell_width(g) }
	reserved := int_min(text_width, int_max(1, width / 2))
	label := clip_line(prompt, int_max(0, width - reserved))
	available := int_max(0, width - term.printable_len(label))
	mut tail := ''
	mut used := 0
	for g in text.graphemes().reverse() {
		cells := cell_width(g)
		if used + cells > available { break }
		tail = g + tail
		used += cells
	}
	return label + tail
}

const tui_help = 'tab/shift-tab: next/previous view (advisories/commits/issues)
j/k or mouse wheel: move; J/K: move ten rows
enter: view advisory/commit/issue/PR; e: edit; r: AI review; n: new draft
b: find similar bugs using the selected advisory or source as a template
C: manage advisory credits (finder, reporter, fix developer and other roles)
c (or a): request CVE; d: accept/reopen as draft; p: publish; x: close
s: advisory status; m: actions menu; f/F: next/previous advisory state filter
/: filter the current list by text (Enter applies; empty clears; Esc cancels)
g: reload; A: cycle AI agent
?: this help; q or Ctrl+C: quit

Severity: 🔴 critical, 🟠 high, 🟡 medium, 🟢 low, ⚪ unknown.
Commit circles use linked advisory severity or a keyword estimate from the subject.
States: triage (private report), draft, published, closed.
CVE assignment is separate from the advisory state and happens asynchronously.
Use s to check the assigned CVE; GitHub REST does not expose pending requests.
requested* means ghadv recorded an accepted request locally, across restarts.
It is not a live queue status; s shows when the request was accepted.'

fn color(state string, s string) string {
	return if !term.can_show_color_on_stdout() {
		s
	} else {
		match state {
			'draft' { term.yellow(s) }
			'triage' { term.cyan(s) }
			'published' { term.green(s) }
			else { term.dim(s) }
		}
	}
}

fn severity_icon(severity string) string {
	return match severity.to_lower() {
		'critical' { '🔴' }
		'high' { '🟠' }
		'medium', 'moderate' { '🟡' }
		'low' { '🟢' }
		else { '⚪' }
	}
}

fn crow(c []string, advs [][]string, w int) string {
	if c.len < 3 {
		return clip_line(c.join(' '), line_width(w))
	}
	i := adv_of(advs, c[0])
	mark := if i < 0 { term.dim('${'-':-20}') } else { color(advs[i][1], '${advs[i][0]:-20}') }
	severity := if i >= 0 && severity_icon(advs[i][3]) != '⚪' {
		advs[i][3]
	} else {
		commit_severity(c[2])
	}
	line := if w < 40 { c[2] } else if w < 80 {
		'${severity_icon(severity)} ${c[0]#[..10]} ${c[2]}'
	} else { '${severity_icon(severity)} ${c[0]#[..10]} ${c[1]} ${mark} ${c[2]}' }
	return clip_line(line, line_width(w))
}

fn irow(item []string, advs [][]string, w int) string {
	if item.len < 5 {
		return clip_line(item.join(' '), line_width(w))
	}
	i := adv_of(advs, item[0])
	mark := if i < 0 { term.dim('${'-':-20}') } else { color(advs[i][1], '${advs[i][0]:-20}') }
	line := if w < 40 { '#${item[1]} ${item[4]}' } else if w < 80 {
		'#${item[1]} ${item[2]} ${item[3]} ${item[4]}'
	} else { '${'#' + item[1]:-8} ${item[2]:-5} ${item[3]:-7} ${mark} ${item[4]}' }
	return clip_line(line, line_width(w))
}

fn row(r []string, w int) string {
	if r.len < 5 {
		return clip_line(r.join(' '), line_width(w))
	}
	line := if w < 40 { r[4] } else if w < 80 {
		'${severity_icon(r[3])} ${r[0]} ${color(r[1], r[1])} ${r[4]}'
	} else { '${severity_icon(r[3])} ${r[0]:-20} ${color(r[1], '${r[1]:-10}')} ${r[2]:-15} ${r[3]:-9} ${r[4]}' }
	return clip_line(line, line_width(w))
}

// Suggested actions depend on the advisory lifecycle, independently of CVE assignment.
fn advisory_actions(a []string) []string {
	if a.len < 5 {
		return []string{}
	}
	mut actions := []string{}
	if a[1] in ['draft', 'published'] && a[2] == '-' {
		actions << 'c request CVE'
	}
	if a[1] == 'triage' {
		actions << 'd accept as draft'
	} else if a[1] == 'closed' {
		actions << 'd reopen as draft'
	}
	if a[1] == 'draft' {
		actions << 'p publish'
	}
	if a[1] in ['triage', 'draft'] {
		actions << 'x close'
	}
	return actions
}

fn key_hints(items []string, width int) string {
	mut out := ''
	mut used := 0
	for item in items {
		space := if used == 0 { '' } else { ' ' }
		if used + space.len + term.printable_len(item) > width {
			break
		}
		out += space + term.bold(term.cyan(item.all_before(' '))) + ' ' +
			term.dim(item.all_after_first(' '))
		used += space.len + term.printable_len(item)
	}
	return out
}

// Catch SIGINT while the CLI child handles the operation. Unlike SIG_IGN, a caught
// handler resets on exec, so the child and its AI/editor still receive Ctrl+C.
fn wait_for_workflow(_ os.Signal) {}

fn tui_workflow(api GitHub, args ...string) ! {
	terminal := os.exec(['stty', '-g'])
	if terminal.exit_code != 0 { return error('workflow requires an interactive terminal') }
	previous := os.signal_opt(.int, wait_for_workflow)!
	defer { os.signal_opt(.int, previous) or {} }
	code := os.system_args([os.executable(), '-r', api.repo, ...args])
	// An interrupted editor may leave echo/canonical input disabled.
	os.system_args(['stty', terminal.output.trim_space()])
	if code == 130 {
		return error_with_code('cancelled; recovery files, if created, are at the path printed above', 130)
	}
	if code != 0 { eprintln('Workflow exited with status ${code}') }
}

// A cancellable line prompt, with the same key handling as the TUI forms.
fn action_input(prompt string) ?string {
	terminal := os.exec(['stty', '-g'])
	if terminal.exit_code != 0 { return none }
	os.system_args(['stty', '-icanon', '-echo', '-isig', 'min', '0', 'time', '2'])
	defer {
		os.system_args(['stty', terminal.output.trim_space()])
		println('')
	}
	mut text := ''
	for {
		w, h := terminal_size()
		runes := text.runes()
		line := input_line(prompt, text, line_width(w))
		print('\x1b[?7l\r${line}\x1b[K\x1b[?7h')
		os.flush()
		k := key(w, h)
		match k {
			'\x1b', '\x03', '\x04' { return none }
			'\n', '\r' { return text }
			'\x15' { text = '' }
			'\x7f', '\x08' {
				text = runes#[..runes.len - 1].string()
			}
			else {
				if k != '' && k[0] >= 0x20 && k[0] != 0x7f { text += k }
			}
		}
	}
	return none
}

// Interactive actions start in cooked mode; input is a commit or URL.
fn run(k string, api GitHub, id string, input string) ! {
	match k {
		'C' {
			credits_tui(api, id)!
		}
		'e', 'r' {
			advisory_tui(api, id, k)!
		}
		'b' {
			if input == '' {
				advisory_tui(api, id, k)!
			} else {
				if !similar_tui(api, input)! { return }
				action_input('Press Enter to return (Ctrl+C/Esc also returns): ') or {}
			}
		}
		'n' {
			args := if input != '' {
				input
			} else {
				action_input('commit or issue/PR URL [context] (Ctrl+C/Esc cancels): ') or { return }
			}
			trimmed := args.trim_space()
			if trimmed != '' {
				ctx := if trimmed.contains(' ') { trimmed.all_after_first(' ') } else { '' }
				tui_workflow(api, 'new', trimmed.all_before(' '), ctx)!
				action_input('Press Enter to return (Ctrl+C/Esc also returns): ') or {}
			}
		}
		else {
			if input == '' {
				advisory_tui(api, id, 'v')!
				return
			}
			if input != '' && !input.starts_with('https://') {
				os.system_args(['git', 'show', input])
				return
			}
			view_text(api.source_text(source(api.repo, input)!, false)!)!
		}
	}
}

fn similar_tui(api GitHub, input string) !bool {
	println('Find similar bugs with AI using ${input} as a template; results open as a saved report.')
	println('Example: Look for the same missing bounds check in related parsers and callers.')
	println('Enter to search; Ctrl+C or Esc to cancel. Ctrl+C also cancels the running AI.')
	ctx := action_input('extra context (optional): ') or { return false }
	tui_workflow(api, 'similar', input, ctx)!
	return true
}

// Stay on the same advisory while viewing, editing, reviewing and finding related bugs.
fn advisory_tui(api GitHub, id string, first string) ! {
	mut action := first
	for {
		match action {
			'v' { view_text(api.advisory(id)!)! }
			'e' { tui_workflow(api, 'edit', id)! }
			'b' { if !similar_tui(api, id)! { return } }
			'r' {
				println('Review ${id} with AI, then inspect its proposed changes in \$EDITOR.')
				println('Example: Check the affected versions and whether the fix addresses the root cause.')
				println('Enter to review; Ctrl+C or Esc to cancel. Ctrl+C also cancels the running AI.')
				ctx := action_input('extra context (optional): ') or { return }
				tui_workflow(api, 'review', id, ctx)!
			}
			else {}
		}
		action = action_input('[v]iew advisory, [r] AI review, [b] similar bugs, [e]dit. Press Enter to return: ') or { return }
		if action !in ['v', 'r', 'b', 'e'] { return }
	}
}

fn view_text(text string) ! {
	path := os.join_path(os.temp_dir(), 'ghadv-view-${os.getpid()}.md')
	os.write_file(path, text)!
	defer { os.rm(path) or {} }
	if os.exists_in_system_path('r2') {
		os.system_args(['r2', '-q', '-c', "cat -m ${path}~..", '--'])
	} else {
		sh('${os.getenv_opt('PAGER') or { 'less' }} "\$1"', path)
	}
}

fn act(k string, api GitHub, id string) !string {
	match k {
		'a', 'c' { return api.request_cve(id) }
		'd' { api.set_state(id, 'draft')! }
		'p' { api.set_state(id, 'published')! }
		'x' { api.set_state(id, 'closed')! }
		else { return error('unknown action: ${k}') }
	}
	return 'advisory updated; press s for status'
}

// Poll one event against the painted size, including resizes during rendering.
fn key(w int, h int) string {
	for {
		mut s, _ := os.fd_read(0, 1)
		if s == '\x1b' {
			// Read one complete escape sequence, leaving queued events for the next call.
			for s.len < 64 {
				c, _ := os.fd_read(0, 1)
				if c == '' {
					break
				}
				s += c
				if s in ['\x1b[', '\x1bO'] {
					continue
				}
				if s.starts_with('\x1b[M') {
					// Legacy mouse reports have three bytes after CSI M.
					if s.len < 6 {
						continue
					}
				} else if s.starts_with('\x1b[') && (c[0] < 0x40 || c[0] > 0x7e) {
					continue
				}
				break
			}
		}
		if s.starts_with('\x1b[<') || s.starts_with('\x1b[M') {
			mut button := -1
			if s.starts_with('\x1b[M') && s.len == 6 {
				button = int(s[3]) - 32
			} else if s.starts_with('\x1b[<') && s.ends_with('M') {
				fields := s[3..s.len - 1].split(';')
				if fields.len == 3 {
					button = fields[0].int()
				}
			}
			// Ignore clicks, releases and horizontal scrolling; strip Shift/Alt/Ctrl.
			match button & ~28 {
				64 { return 'k' }
				65 { return 'j' }
				else { continue }
			}
		}
		if s != '' {
			if s.len == 1 && s[0] >= 0xc2 && s[0] <= 0xf4 {
				length := if s[0] < 0xe0 { 2 } else if s[0] < 0xf0 { 3 } else { 4 }
				for s.len < length {
					c, _ := os.fd_read(0, 1)
					if c == '' { break }
					s += c
				}
			}
			return s
		}
		nw, nh := terminal_size()
		if nw != w || nh != h {
			return ''
		}
	}
	return ''
}

// These forms stay in raw mode: Escape/Ctrl+C cancels a form, preserving staged edits.
fn tui_input(title string, prompt string, current string, ascii_only bool) ?string {
	print('\x1b[?25h\x1b[?1000l\x1b[?1006l')
	defer { print('\x1b[?25l\x1b[?1000h\x1b[?1006h') }
	mut screen := TuiScreen{}
	mut text := current
	for {
		w, h := terminal_size()
		layout := tui_layout(h, 1, 1)
		line := input_line(prompt, text, line_width(w))
		screen.draw(list_frame(layout, [title], [line],
			['Enter: next   Esc/Ctrl+C: cancel   Ctrl+U: clear']), w, h)
		print('\x1b[${layout.head + 1};${int_min(w, term.printable_len(line) + 1)}H')
		os.flush()
		k := key(w, h)
		match k {
			'\x1b', '\x03', '\x04' { return none }
			'\n', '\r' { return text }
			'\x15' { text = '' }
			'\x7f', '\x08' {
				graphemes := text.graphemes()
				text = graphemes#[..graphemes.len - 1].join('')
			}
			else {
				if k != '' && k[0] >= 0x20 && k[0] != 0x7f {
					if !ascii_only || (k.len == 1 && k[0] < 0x7f && text.len < 80) { text += k }
				}
			}
		}
	}
	return none
}

fn credit_login(current string) ?string {
	login := tui_input('Credit a GitHub user', 'Username: ', current, true)?
	if login.trim_space() == '' { return none }
	return login
}

fn credit_role_picker(current string) ?string {
	mut sel := int_max(0, credit_roles.map(it.typ).index(current))
	mut top := 0
	mut screen := TuiScreen{}
	for {
		w, h := terminal_size()
		layout := tui_layout(h, 2, 2)
		page := layout.page
		top = list_top(top, sel, credit_roles.len, page)
		mut body := []string{}
		for i in top .. int_min(credit_roles.len, top + page) {
			role := credit_roles[i]
			number := if i == 9 { 0 } else { i + 1 }
			line := '${number} ${role.typ:-23} ${role.description}'
			body << if i == sel { term.inverse(line) } else { line }
		}
		screen.draw(list_frame(layout, [term.bold('Available credit roles'), ''], body,
			[credit_roles[sel].description, 'j/k or arrows: move; Enter/1-9/0: select; Esc/Ctrl+C: cancel']), w, h)
		k := key(w, h)
		match k {
			'\x1b', '\x03', 'q' { return none }
			'\n', '\r' { return credit_roles[sel].typ }
			'j', '\x1b[B' { sel = int_min(sel + 1, credit_roles.len - 1) }
			'k', '\x1b[A' { sel = int_max(sel - 1, 0) }
			else {
				if k.len == 1 && k[0].is_digit() {
					i := if k == '0' { 9 } else { k.int() - 1 }
					return credit_roles[i].typ
				}
			}
		}
	}
	return none
}

fn credits_tui(api GitHub, id string) ! {
	terminal := os.exec(['stty', '-g'])
	if terminal.exit_code != 0 { return error('credits screen requires an interactive terminal') }
	mut credits := api.credits(id)!
	mut saved := credits.clone()
	// Read Ctrl+C as a key so exiting with unsaved changes offers save/discard/cancel.
	os.system_args(['stty', '-icanon', '-echo', '-isig', 'min', '0', 'time', '2'])
	print(tui_enter)
	defer {
		print(tui_leave)
		os.flush()
		os.system_args(['stty', terminal.output.trim_space()])
	}
	mut sel := 0
	mut top := 0
	mut status := ''
	mut screen := TuiScreen{}
	for {
		w, h := terminal_size()
		width := line_width(w)
		layout := tui_layout(h, 3, 4)
		page := layout.page
		sel = int_min(int_max(0, sel), int_max(0, credits.len - 1))
		top = list_top(top, sel, credits.len, page)
		dirty := credits != saved
		headers := [term.bold('Credits | ${api.repo} | ${id}'),
			'${credits.len} entries' + if dirty { ' | unsaved changes' } else { ' | saved' },
			'${'GITHUB USER':-24} ROLE']
		mut body := []string{}
		for i in top .. int_min(credits.len, top + page) {
			line := if w < 50 { '@${credits[i].login} ${credits[i].typ}' } else {
				'${'@' + credits[i].login:-24} ${credits[i].typ}'
			}
			body << if i == sel { term.inverse(line) } else { line }
		}
		if credits.len == 0 { body << 'No credits yet. Press a to add a person.' }
		description := if credits.len > 0 {
			credit_description(credits[sel].typ)
		} else {
			'One person can have several roles.'
		}
		screen.draw(list_frame(layout, headers, body, [description, status,
			key_hints(['a add', 'e edit', 'd delete', 's save', '? roles', 'q back'], width),
			key_hints(['q back', 'j/k move', 'enter edit', 'u undo all', 'Esc back'], width)]), w, h)
		mut k := key(w, h)
		mut leave := false
		if k == '' { continue }
		status = ''
		if k in ['q', '\x1b', '\x03'] {
			if !dirty { return }
			screen.width = 0
			match tui_dialog('Unsaved credits: [s]ave and exit, [d]iscard, [c]ancel: ') {
				'd' { return }
				's' {
					k = 's'
					leave = true
				}
				else { continue }
			}
		}
		match k {
			'j', '\x1b[B' { sel++ }
			'k', '\x1b[A' { sel-- }
			'J' { sel += 10 }
			'K' { sel -= 10 }
			'?' {
				screen.width = 0
				credit_role_picker('') or {}
			}
			'a', 'e', '\n', '\r' {
				if k != 'a' && credits.len == 0 { continue }
				index := if k == 'a' { -1 } else { sel }
				old := if index < 0 { Credit{} } else { credits[index] }
				screen.width = 0
				login := credit_login(old.login) or { continue }
				typ := credit_role_picker(old.typ) or { continue }
				credits = change_credit(credits, index, Credit{login, typ}) or {
					status = err.msg()
					continue
				}
				if index < 0 { sel = credits.len - 1 }
				status = 'Credit staged; press s to save to GitHub.'
			}
			'd', 'x' {
				if credits.len > 0 {
					credits.delete(sel)
					status = 'Credit removed locally; s saves, u undoes all changes.'
				}
			}
			'u' {
				credits = saved.clone()
				status = 'Unsaved changes undone.'
			}
			's' {
				if !dirty {
					status = 'No changes to save.'
					continue
				}
				api.update_credits(id, credits) or {
					status = 'Save failed; edits kept: ' + err.msg().replace('\n', ' ')
					continue
				}
				saved = credits.clone()
				status = 'Credits saved.'
				if leave { return }
			}
			else {}
		}
	}
}

fn tui(api GitHub, label string) {
	saved := os.exec(['stty', '-g']).output.trim_space()
	raw := fn () {
		os.system_args(['stty', '-icanon', '-echo', '-isig', 'min', '0', 'time', '2'])
		print(tui_enter)
	}
	cooked := fn [saved] () {
		print(tui_leave)
		os.flush()
		os.system_args(['stty', saved])
	}
	defer { cooked() }
	mut advs := api.advisories('') or { [['error:', err.msg()]] }
	mut cms := commits() or { [['error:', err.msg()]] }
	mut items := api.issues(label) or { [['error:', err.msg()]] }
	mut git_status := local_git_status()
	mut view := 0 // 0 advisories, 1 git, 2 labeled issues/PRs
	mut sel := [0, 0, 0]
	mut top := [0, 0, 0]
	mut status := ''
	mut filter := 0
	mut queries := ['', '', '']
	mut screen := TuiScreen{}
	raw()
	for {
		w, h := terminal_size()
		width := line_width(w)
		layout := tui_layout(h, 3, 3)
		mut visible := [][]int{len: 3}
		for v, entries in [advs, cms, items] {
			query := queries[v].to_lower()
			for i, entry in entries {
				mut text := entry.join(' ')
				if v != 0 && query != '' && entry.len > 0 {
					linked := adv_of(advs, entry[0])
					if linked >= 0 { text += ' ' + advs[linked][0] }
				}
				if text.to_lower().contains(query) { visible[v] << i }
			}
		}
		advisory_matches := visible[0].clone()
		if filter != 0 {
			visible[0] = visible[0].filter(advs[it].len > 1 && advs[it][1] == states[filter])
		}
		page := layout.page
		n := visible[view].len
		sel[view] = if n == 0 { 0 } else { int_min(int_max(sel[view], 0), n - 1) }
		top[view] = list_top(top[view], sel[view], n, page)
		selected := if n > 0 { visible[view][sel[view]] } else { -1 }
		input := if view == 1 && selected >= 0 && cms[selected].len > 2 {
			cms[selected][0]
		} else if view == 2 && selected >= 0 && items[selected].len >= 5 {
			items[selected][0]
		} else {
			''
		}
		ai := if view == 0 {
			selected
		} else {
			adv_of(advs, input)
		}
		id := if ai >= 0 && ai < advs.len && advs[ai].len >= 5 { advs[ai][0] } else { '' }
		actions := if id != '' {
			advisory_actions(advs[ai])
		} else {
			[]string{}
		}
		tabs := ['advisories ${visible[0].len} (${states[filter]})', 'commits ${visible[1].len}',
			'issues/PRs ${visible[2].len} (${label})']
		header := 'ghadv ${api.repo} | local git: ${git_status}'
		tab_line := tui_tabs(tabs, view, width)
		columns := if w < 40 {
			if view == 0 { 'SUMMARY' } else if view == 1 { 'SUBJECT' } else { 'NUMBER TITLE' }
		} else if w < 80 {
			if view == 0 { '   ADVISORY STATE SUMMARY' } else if view == 1 { '   COMMIT     SUBJECT' } else { 'NUMBER TYPE STATE TITLE' }
		} else if view == 0 {
			'   ${'ADVISORY':-20} ${'STATE':-10} ${'CVE':-15} ${'SEVERITY':-9} SUMMARY'
		} else if view == 1 {
			'   ${'COMMIT':-10} ${'DATE':-10} ${'ADVISORY':-20} SUBJECT'
		} else {
			'${'NUMBER':-8} ${'TYPE':-5} ${'STATE':-7} ${'ADVISORY':-20} TITLE'
		}
		mut body := []string{}
		for i in top[view] .. int_min(n, top[view] + page) {
			index := visible[view][i]
			mut line := ''
			if view == 0 {
				line = row(advs[index], w)
			} else if view == 1 {
				line = crow(cms[index], advs, w)
			} else {
				line = irow(items[index], advs, w)
			}
			body << if i == sel[view] { term.inverse(term.strip_ansi(line)) } else { line }
		}
		if n == 0 {
			body << term.dim(if queries[view] != '' {
				'No matches. Press / to change or clear the text filter.'
			} else if view == 0 {
				'No entries. Press f/F to change the filter or g to reload.'
			} else {
				'No entries. Press g to reload or n to enter a commit/URL.'
			})
		}
		hint := if status != '' {
			status
		} else if id != '' {
			cve := match advs[ai][2] {
				'requested*' { 'CVE request recorded locally; g reload, s status' }
				'-' { 'no CVE assigned; request status unknown' }
				else { advs[ai][2] }
			}
			'${id} | ${advs[ai][1]} | ${cve}'
		} else {
			'No advisory selected; n creates a draft from a commit, issue or PR'
		}
		filter_hint := if queries[view] == '' { hint } else { '/${queries[view]} | ${hint}' }
		mut headers := [term.bold(header), term.bold(tab_line), term.dim(columns)]
		// Keep the active view visible when a short terminal only has one header.
		if layout.head == 1 { headers[0] = headers[1] }
		screen.draw(list_frame(layout, headers, body, [filter_hint,
			key_hints(['m actions', 'b similar bugs', 'C credits', 's status', ...actions, 'g reload', 'A agent'], width),
			key_hints(['? help', 'q quit', 'tab/shift-tab views', '/ text', 'f/F state', 'j/k/J/K move',
			'enter view', 'e edit', 'r review', 'n new'], width)]), w, h)
		mut k := key(w, h)
		mut show_input := input
		if k == '' { continue }
		status = ''
		if k == 'm' {
			if id == '' {
				status = 'no advisory selected'
				continue
			}
			screen.width = 0
			k = tui_dialog('Actions for ${id}\n${advs[ai][4]}\n${hint}\n\n' + actions.join('\n') +
				'\ns status details\nv view advisory\ne edit advisory\nr AI review\nb Find similar bugs\nC manage credits\n\nChoose a key; Enter/Esc cancels.')
			if k == 'v' {
				k = '\n'
				show_input = ''
			} else if k !in ['s', 'e', 'r', 'b', 'C'] && !actions.any(it.starts_with(k + ' ')) {
				continue
			}
		}
		match k {
			'q', '\x03' {
				break
			}
			'j', '\x1b[B', 'J' {
				sel[view] += if k == 'J' { 10 } else { 1 }
			}
			'k', '\x1b[A', 'K' {
				sel[view] -= if k == 'K' { 10 } else { 1 }
			}
			'\t', '\x1b[Z' {
				// Jump to a linked entry in the destination view when there is one.
				step := if k == '\t' { 1 } else { tabs.len - 1 }
				next := (view + step) % tabs.len
				if next == 0 && ai in advisory_matches {
					if ai !in visible[0] {
						filter = 0
						sel[0] = advisory_matches.index(ai)
					} else {
						sel[0] = visible[0].index(ai)
					}
				} else if next != 0 && ai >= 0 {
					entries := if next == 1 { cms } else { items }
					for c, index in visible[next] {
						entry := entries[index]
						if entry.len >= 3 && adv_of([advs[ai]], entry[0]) == 0 {
							sel[next] = c
							break
						}
					}
				}
				view = next
			}
			'f', 'F' {
				step := if k == 'f' { 1 } else { states.len - 1 }
				filter = (filter + step) % states.len
				sel[0], top[0] = 0, 0
			}
			'/' {
				screen.width = 0
				if query := tui_input('Text filter: Enter applies; empty clears; Esc cancels. Current: ${queries[view]}',
					'Filter text: ', '', false) {
					queries[view] = query.trim_space()
					sel[view], top[view] = 0, 0
				}
			}
			'A' {
				// cycle the agent; a custom GHADV_AI is replaced by the presets
				cur := agents.index(os.getenv_opt('GHADV_AI') or { agents[0] })
				os.setenv('GHADV_AI', agents[(cur + 1) % agents.len], true)
				status = 'agent: ${os.getenv('GHADV_AI')}'
			}
			'g' {
				advs = api.advisories('') or { [['error:', err.msg()]] }
				cms = commits() or { [['error:', err.msg()]] }
				items = api.issues(label) or { [['error:', err.msg()]] }
				git_status = local_git_status()
			}
			'\n', '\r', 'e', 'r', 'b', 'n', 's', 'C', '?' {
				if id == '' && (k in ['e', 'r', 's', 'C'] || (k in ['\n', '\r', 'b'] && input == '')) {
					status = 'no advisory selected; press n to create a draft'
					continue
				}
				screen.width = 0
				if k == '?' {
					tui_dialog(tui_help + '\n\nagent: ${os.getenv_opt('GHADV_AI') or { agents[0] }}')
					continue
				}
				if k == 's' {
					tui_dialog(api.status(id) or { 'error: ${err}' })
					continue
				}
				cooked()
				run(k, api, id, if k in ['e', 'r', 's', 'C'] { '' } else { show_input }) or {
					if err.code() == 130 {
						status = err.msg()
					} else {
						println('error: ${err}')
						action_input('Press Enter to return (Ctrl+C/Esc also returns): ') or {}
					}
				}
				raw()
				advs = api.advisories('') or { advs }
				git_status = local_git_status()
			}
			'a', 'c', 'd', 'p', 'x' {
				if id == '' {
					status = 'no advisory selected'
					continue
				}
				action_key := if k == 'a' { 'c' } else { k }
				if !actions.any(it.starts_with(action_key + ' ')) {
					status = if action_key == 'c' && advs[ai][2] == 'requested*' {
						'CVE request already recorded locally; g reload, s status'
					} else if action_key == 'c' && advs[ai][2] != '-' {
						'CVE already assigned: ${advs[ai][2]}'
					} else {
						'action unavailable for ${advs[ai][1]}; press m for actions'
					}
					continue
				}
				verb := match k {
					'a', 'c' { 'request a CVE for' }
					'd' { 'accept/reopen as draft' }
					'p' { 'PUBLISH' }
					else { 'close' }
				}
				screen.width = 0
				if tui_dialog('${verb} ${id}? [y/N] ') == 'y' {
					status = act(k, api, id) or { 'error: ' + err.msg().replace('\n', ' ') }
					if status.starts_with('CVE request accepted;') {
						// Keep the accepted request visible even if the reload fails.
						advs[ai][2] = 'requested*'
						status = 'CVE request accepted; assignment is asynchronous. g reload, s status'
					}
					advs = api.advisories('') or { advs }
				}
			}
			else {}
		}
	}
}
