module main

import os
import term

const tui_help = 'tab: switch advisories/commits/issues; j/k or mouse wheel: move; J/K: move ten rows
enter: view advisory/commit/issue/PR; e: edit; r: AI review; n: new draft
C: manage advisory credits (finder, reporter, fix developer and other roles)
c (or a): request CVE; d: accept/reopen as draft; p: publish; x: close
s: advisory status; m: actions menu; f: cycle advisory state filter
g: reload; A: cycle AI agent
?: this help; q: quit

States: triage (private report), draft, published, closed.
CVE assignment is separate from the advisory state and happens asynchronously.
Use s to check the assigned CVE; GitHub REST does not expose pending requests.
requested* means a request was accepted during this TUI session.'

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

fn crow(c []string, advs [][]string, w int) string {
	if c.len < 3 {
		return c.join(' ')
	}
	i := adv_of(advs, c[0])
	mark := if i < 0 { term.dim('${'-':-20}') } else { color(advs[i][1], '${advs[i][0]:-20}') }
	return '${c[0][..10]} ${c[1]} ${mark} ${c[2]#[..w - 44]}'
}

fn irow(item []string, advs [][]string, w int) string {
	if item.len < 5 {
		return item.join(' ')
	}
	i := adv_of(advs, item[0])
	mark := if i < 0 { term.dim('${'-':-20}') } else { color(advs[i][1], '${advs[i][0]:-20}') }
	return '${'#' + item[1]:-8} ${item[2]:-5} ${item[3]:-7} ${mark} ${item[4]#[..w - 44]}'
}

fn row(r []string, w int) string {
	if r.len < 5 {
		return r.join(' ')
	}
	return '${r[0]:-20} ${color(r[1], '${r[1]:-10}')} ${r[2]:-15} ${r[3]:-9} ${r[4]#[..w - 59]}'
}

// Suggested actions depend on the advisory lifecycle, independently of CVE assignment.
fn advisory_actions(a []string, requested bool) []string {
	if a.len < 5 {
		return []string{}
	}
	mut actions := []string{}
	if a[1] in ['draft', 'published'] && a[2] == '-' && !requested {
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
		if used + space.len + item.len > width {
			break
		}
		out += space + term.bold(term.cyan(item.all_before(' '))) + ' ' +
			term.dim(item.all_after_first(' '))
		used += space.len + item.len
	}
	return out
}

// Interactive actions run with the terminal in cooked mode; input is a commit or URL.
fn run(k string, api GitHub, id string, input string) ! {
	match k {
		'?' {
			println(tui_help)
			println('\nagent: ${os.getenv_opt('GHAV_AI') or { agents[0] }}')
			os.input('press enter')
		}
		's' {
			println(api.status(id)!)
			os.input('press enter')
		}
		'C' {
			credits_tui(api, id)!
		}
		'e' {
			cmd_edit(api, id)!
			os.input('press enter')
		}
		'r' {
			cmd_review(api, id, os.input('extra context: '))!
			os.input('press enter')
		}
		'n' {
			args := if input != '' {
				input
			} else {
				os.input('commit or issue/PR URL [context]: ').trim_space()
			}
			if args != '' {
				ctx := if args.contains(' ') { args.all_after_first(' ') } else { '' }
				cmd_new(api, args.all_before(' '), ctx)!
				os.input('press enter')
			}
		}
		else {
			if input != '' && !input.starts_with('https://') {
				os.system_args(['git', 'show', input])
				return
			}
			name := if input != '' { 'source-${os.getpid()}' } else { id }
			path := os.join_path(os.temp_dir(), 'ghav-${name}.md')
			text := if input != '' {
				api.source_text(source(api.repo, input)!, false)!
			} else {
				api.advisory(id)!
			}
			os.write_file(path, text)!
			if os.exists_in_system_path('r2') {
				// The leading quote bypasses r2 command parsing for the filename.
				os.system_args(['r2', '-q', '-c', "cat -m ${path}~..", '--'])
			} else {
				sh('${os.getenv_opt('PAGER') or { 'less' }} "\$1"', path)
			}
			os.rm(path)!
		}
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

// polls one key or wheel event (stty time 2); returns '' when the terminal is resized
fn key(resize bool) string {
	w, h := term.get_terminal_size()
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
			return s
		}
		nw, nh := term.get_terminal_size()
		if resize && (nw != w || nh != h) {
			return ''
		}
	}
	return ''
}

// These forms stay in raw mode: Escape/Ctrl+C cancels a form, preserving staged edits.
fn credit_login(current string) ?string {
	print('\x1b[H\x1b[2J\x1b[?25h\x1b[?1000l\x1b[?1006l')
	defer { print('\x1b[?25l\x1b[?1000h\x1b[?1006h') }
	println('Credit a GitHub user\n\nEnter: next   Esc/Ctrl+C: cancel   Ctrl+U: clear\n')
	mut login := current
	for {
		w, _ := term.get_terminal_size()
		width := int_max(10, w - 12)
		print('\r\x1b[2KUsername: ${login#[int_max(0, login.len - width)..]}')
		os.flush()
		k := key(false)
		match k {
			'\x1b', '\x03' { return none }
			'\n', '\r' {
				if login.trim_space() == '' { return none }
				return login
			}
			'\x15' { login = '' }
			'\x7f', '\x08' { login = login#[..login.len - 1] }
			else {
				if k.len == 1 && k[0] >= 0x20 && k[0] < 0x7f && login.len < 80 {
					login += k
				}
			}
		}
	}
	return none
}

fn credit_role_picker(current string) ?string {
	mut sel := int_max(0, credit_roles.map(it.typ).index(current))
	mut top := 0
	for {
		w, h := term.get_terminal_size()
		width := int_max(20, w - 1)
		page := int_max(1, h - 6)
		top = int_min(int_max(top, sel - page + 1), sel)
		mut out := '\x1b[H\x1b[2J' + term.bold('Available credit roles') + '\n\n'
		for i in top .. int_min(credit_roles.len, top + page) {
			role := credit_roles[i]
			number := if i == 9 { 0 } else { i + 1 }
			line := '${number} ${role.typ:-23} ${role.description}'#[..width]
			out += if i == sel { term.inverse(line) } else { line } + '\n'
		}
		out += '\n' + credit_roles[sel].description#[..width]
		out += '\n' + 'j/k or arrows: move; Enter/1-9/0: select; Esc/Ctrl+C: cancel'#[..width]
		print(out)
		os.flush()
		k := key(true)
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
	print('\x1b[?25l\x1b[?1000h\x1b[?1006h')
	defer {
		print('\x1b[?1000l\x1b[?1006l\x1b[?25h\x1b[H\x1b[2J')
		os.system_args(['stty', terminal.output.trim_space()])
	}
	mut sel := 0
	mut top := 0
	mut status := ''
	for {
		w, h := term.get_terminal_size()
		width := int_max(20, w - 1)
		page := int_max(1, h - 7)
		sel = int_min(int_max(0, sel), int_max(0, credits.len - 1))
		top = int_min(int_max(top, sel - page + 1), sel)
		dirty := credits != saved
		mut out := '\x1b[H\x1b[2J' + term.bold('Credits | ${api.repo} | ${id}'#[..width]) + '\n'
		out += '${credits.len} entries' + if dirty { ' | unsaved changes\n' } else { ' | saved\n' }
		out += '${'GITHUB USER':-24} ROLE\n'
		for i in top .. int_min(credits.len, top + page) {
			line := '${'@' + credits[i].login:-24} ${credits[i].typ}'#[..width]
			out += if i == sel { term.inverse(line) } else { line } + '\n'
		}
		if credits.len == 0 { out += 'No credits yet. Press a to add a person.\n' }
		description := if credits.len > 0 {
			credit_description(credits[sel].typ)
		} else {
			'One person can have several roles.'
		}
		out += '\x1b[${int_max(5, h - 3)};1H' + description#[..width] + '\n'
		out += status#[..width] + '\n'
		out += key_hints(['a add', 'e edit', 'd delete', 's save', '? roles', 'q back'], width) + '\n'
		out += key_hints(['j/k move', 'enter edit', 'u undo all', 'Esc back'], width)
		print(out)
		os.flush()
		mut k := key(true)
		mut leave := false
		status = ''
		if k in ['q', '\x1b', '\x03'] {
			if !dirty { return }
			print('\r\x1b[2KUnsaved credits: [s]ave and exit, [d]iscard, [c]ancel: ')
			os.flush()
			match key(false) {
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
			'?' { credit_role_picker('') or {} }
			'a', 'e', '\n', '\r' {
				if k != 'a' && credits.len == 0 { continue }
				index := if k == 'a' { -1 } else { sel }
				old := if index < 0 { Credit{} } else { credits[index] }
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
		os.system_args(['stty', '-icanon', '-echo', 'min', '0', 'time', '2'])
		print('\x1b[?25l\x1b[?1000h\x1b[?1006h')
	}
	cooked := fn [saved] () {
		print('\x1b[?1000l\x1b[?1006l')
		os.system_args(['stty', saved])
		print('\x1b[?25h\x1b[H\x1b[2J')
	}
	mut advs := api.advisories('') or { [['error:', err.msg()]] }
	mut cms := commits() or { [['error:', err.msg()]] }
	mut items := api.issues(label) or { [['error:', err.msg()]] }
	mut view := 0 // 0 advisories, 1 git, 2 labeled issues/PRs
	mut sel := [0, 0, 0]
	mut top := [0, 0, 0]
	mut status := ''
	mut filter := 0
	mut cve_requested := map[string]bool{}
	raw()
	for {
		mut w, mut h := term.get_terminal_size()
		if w < 20 || h < 6 {
			w, h = 80, 24
		}
		mut visible := []int{}
		for i, a in advs {
			if filter == 0 || (a.len > 1 && a[1] == states[filter]) {
				visible << i
			}
		}
		page := h - 5
		n := match view {
			0 { visible.len }
			1 { cms.len }
			else { items.len }
		}
		sel[view] = if n == 0 { 0 } else { int_min(int_max(sel[view], 0), n - 1) }
		top[view] = int_min(int_max(top[view], sel[view] - page + 1), sel[view])
		input := if view == 1 && cms.len > 0 && cms[sel[1]].len > 2 {
			cms[sel[1]][0]
		} else if view == 2 && items.len > 0 && items[sel[2]].len >= 5 {
			items[sel[2]][0]
		} else {
			''
		}
		ai := if view == 0 {
			if visible.len > 0 { visible[sel[0]] } else { -1 }
		} else {
			adv_of(advs, input)
		}
		id := if ai >= 0 && ai < advs.len && advs[ai].len >= 5 { advs[ai][0] } else { '' }
		actions := if id != '' {
			advisory_actions(advs[ai], cve_requested[id])
		} else {
			[]string{}
		}
		mut tabs := ['advisories ${visible.len} (${states[filter]})', 'commits ${cms.len}']
		if label != '' {
			tabs << 'issues/PRs ${items.len} (${label})'
		}
		header := 'ghav ${api.repo} | ' + tabs.map(if it == tabs[view] { '[${it}]' } else { it }).join(' | ')
		columns := if view == 0 {
			'${'ADVISORY':-20} ${'STATE':-10} ${'CVE':-15} ${'SEVERITY':-9} SUMMARY'
		} else if view == 1 {
			'${'COMMIT':-10} ${'DATE':-10} ${'ADVISORY':-20} SUBJECT'
		} else {
			'${'NUMBER':-8} ${'TYPE':-5} ${'STATE':-7} ${'ADVISORY':-20} TITLE'
		}
		mut out := '\x1b[H\x1b[2J' + term.bold(header#[..w - 1]) + '\n' +
			term.dim(columns#[..w - 1]) + '\n'
		for i in top[view] .. int_min(n, top[view] + page) {
			mut line := ''
			if view == 0 {
				mut a := advs[visible[i]].clone()
				if a.len >= 5 && a[2] == '-' && cve_requested[a[0]] {
					a[2] = 'requested*'
				}
				line = row(a, w)
			} else if view == 1 {
				line = crow(cms[i], advs, w)
			} else {
				line = irow(items[i], advs, w)
			}
			out += if i == sel[view] { term.inverse(term.strip_ansi(line)) } else { line } + '\n'
		}
		if n == 0 {
			out += term.dim(if view == 0 {
				'No entries. Press f to change the filter or g to reload.'
			} else {
				'No entries. Press g to reload or n to enter a commit/URL.'
			}) + '\n'
		}
		hint := if status != '' {
			status
		} else if id != '' {
			cve := if advs[ai][2] != '-' {
				advs[ai][2]
			} else if cve_requested[id] {
				'CVE requested this session; g reload'
			} else {
				'no CVE assigned'
			}
			'${id} | ${advs[ai][1]} | ${cve}'
		} else {
			'No advisory selected; n creates a draft from a commit, issue or PR'
		}
		out += '\x1b[${h - 2};1H' + hint#[..w - 1] + '\n'
		out += key_hints(['m actions', 'C credits', 's status', ...actions, 'g reload', 'A agent'], w - 1) + '\n'
		out += key_hints(['? help', 'q quit', 'tab views', 'j/k/J/K move', 'enter view', 'e edit',
			'r review', 'n new', 'f filter'], w - 1)
		print(out)
		mut k := key(true)
		mut show_input := input
		status = ''
		if k == 'm' {
			if id == '' {
				status = 'no advisory selected'
				continue
			}
			print('\x1b[H\x1b[2J')
			println(term.bold('Actions for ${id}'))
			println('${advs[ai][4]}\n${hint}\n')
			for action in actions {
				println(key_hints([action], w - 1))
			}
			println('s status details\nv view advisory\ne edit advisory\nr AI review\nC manage credits\n\nChoose a key; Enter/Esc cancels.')
			k = key(false)
			if k == 'v' {
				k = '\n'
				show_input = ''
			} else if k !in ['s', 'e', 'r', 'C'] && !actions.any(it.starts_with(k + ' ')) {
				continue
			}
		}
		match k {
			'q' {
				break
			}
			'j', '\x1b[B', 'J' {
				sel[view] += if k == 'J' { 10 } else { 1 }
			}
			'k', '\x1b[A', 'K' {
				sel[view] -= if k == 'K' { 10 } else { 1 }
			}
			'\t' {
				// Jump to a linked entry in the next view when there is one.
				next := (view + 1) % tabs.len
				if next == 0 && ai >= 0 {
					if ai !in visible {
						filter = 0
						sel[0] = ai
					} else {
						sel[0] = visible.index(ai)
					}
				} else if ai >= 0 {
					entries := if next == 1 { cms } else { items }
					for c, entry in entries {
						if entry.len >= 3 && adv_of([advs[ai]], entry[0]) == 0 {
							sel[next] = c
							break
						}
					}
				}
				view = next
			}
			'f' {
				filter = (filter + 1) % states.len
				sel[0], top[0] = 0, 0
			}
			'A' {
				// cycle the agent; a custom GHAV_AI is replaced by the presets
				cur := agents.index(os.getenv_opt('GHAV_AI') or { agents[0] })
				os.setenv('GHAV_AI', agents[(cur + 1) % agents.len], true)
				status = 'agent: ${os.getenv('GHAV_AI')}'
			}
			'g' {
				advs = api.advisories('') or { [['error:', err.msg()]] }
				cms = commits() or { [['error:', err.msg()]] }
				items = api.issues(label) or { [['error:', err.msg()]] }
			}
			'\n', '\r', 'e', 'r', 'n', 's', 'C', '?' {
				if id == '' && (k in ['e', 'r', 's', 'C'] || (k in ['\n', '\r'] && input == '')) {
					status = 'no advisory selected; press n to create a draft'
					continue
				}
				cooked()
				run(k, api, id, if k in ['e', 'r', 's', 'C'] { '' } else { show_input }) or {
					println('error: ${err}')
					os.input('press enter')
				}
				raw()
				advs = api.advisories('') or { advs }
			}
			'a', 'c', 'd', 'p', 'x' {
				if id == '' {
					status = 'no advisory selected'
					continue
				}
				action_key := if k == 'a' { 'c' } else { k }
				if !actions.any(it.starts_with(action_key + ' ')) {
					status = if action_key == 'c' && advs[ai][2] != '-' {
						'CVE already assigned: ${advs[ai][2]}'
					} else if action_key == 'c' && cve_requested[id] {
						'CVE request already accepted this session; g reload, s status'
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
				print('\x1b[${h - 1};1H\x1b[2K${verb} ${id}? [y/N] ')
				if key(false) == 'y' {
					status = act(k, api, id) or { 'error: ' + err.msg().replace('\n', ' ') }
					if status.starts_with('CVE request accepted') {
						cve_requested[id] = true
						status = 'CVE request accepted; assignment is asynchronous. g reload, s status'
					}
					advs = api.advisories('') or { advs }
				}
			}
			else {}
		}
	}
	cooked()
}
