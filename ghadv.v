// ghav - GitHub security advisories from the command line
module main

import os
import json2
import term

const help = 'Usage: ghav [-r owner/repo] [command] [args]
  tui                      interactive list (default)
  ls [state]               list all/triage/draft/published/closed advisories
  log                      list ##crash/##security commits and their advisories
  new <commit> [context]   analyze a fix commit with AI and create a draft
  show <ghsa>              print advisory
  status <ghsa>            show lifecycle, CVE and private report details
  edit <ghsa>              edit advisory in \$EDITOR
  review <ghsa> [context]  let the AI review/rewrite it, then edit
  cve <ghsa>               request a CVE id (asynchronous)
  approve <ghsa>           alias for cve
  draft <ghsa>             accept a report or reopen as a draft
  publish <ghsa>           publish the advisory
  close <ghsa>             close (reject) the advisory
Environment:
  GHAV_REPO   default repository (otherwise taken from the cwd checkout)
  GHAV_GREP   git log -E --grep for fix commits (default: ##(crash|security))
  GHAV_AI     agent command, prompt is piped to stdin (default: claude -p)
              e.g. "codex exec -", \'pmai "\$(cat)"\''

const agents = ['claude -p', 'codex exec -', 'pmai "\$(cat)"']
const states = ['all', 'triage', 'draft', 'published', 'closed']

const tui_help = 'tab: switch advisories/commits; j/k or mouse wheel: move; J/K: move ten rows
enter: view advisory/commit; e: edit; r: AI review; n: new draft from commit
c (or a): request CVE; d: accept/reopen as draft; p: publish; x: close
s: advisory status; m: actions menu; f: cycle advisory state filter
g: reload; A: cycle AI agent
?: this help; q: quit

States: triage (private report), draft, published, closed.
CVE assignment is separate from the advisory state and happens asynchronously.
Use s to check the assigned CVE; GitHub REST does not expose pending requests.
requested* means a request was accepted during this TUI session.'

const format = 'summary: <one line title, under 100 chars>
severity: <low|medium|high|critical>
cvss: <CVSS:3.1/... vector, or empty>
cwe: <CWE-nnn, ...>
credits: <github_login:finder, ... or empty>
package: <package name>
ecosystem: other
affected: <vulnerable version range, e.g. < 5.9.8>
patched: <first patched version, e.g. 5.9.8>
functions: <vulnerable function names, comma separated>
---
<markdown description: Impact, Details (root cause), Proof of concept, Patches, References>'

const reply = 'Reply with brief notes (verdict, confidence, doubts), then the advisory as the
last thing in your reply, in exactly this format and without code fences:\n\n${format}'

// renders an advisory from the GET endpoint in the editable text format
const jq_text = '"# \\(.ghsa_id) \\(.state) \\(.cve_id // "no-cve") \\(.html_url)
summary: \\(.summary)
severity: \\(.severity // "")
cvss: \\(.cvss.vector_string // "")
cwe: \\([.cwes[]?.cwe_id] | join(", "))
credits: \\([.credits[]? | "\\(.login):\\(.type)"] | join(", "))
" + ([.vulnerabilities[]? | "package: \\(.package.name // "")
ecosystem: \\(.package.ecosystem)
affected: \\(.vulnerable_version_range // "")
patched: \\(.patched_versions // "")
functions: \\(.vulnerable_functions // [] | join(", "))
"] | join("")) + "---\\n" + (.description // "")'

const jq_status = '"advisory: \\(.ghsa_id)
state: \\(.state)
cve: \\(.cve_id // "unassigned (request status unavailable via REST)")
private report: \\(if .submission == null then "no" elif .submission.accepted then "accepted" else "not accepted" end)
created: \\(.created_at // "-")
updated: \\(.updated_at // "-")
published: \\(.published_at // "-")
closed: \\(.closed_at // "-")
withdrawn: \\(.withdrawn_at // "-")
private fork: \\(.private_fork.html_url // "-")
url: \\(.html_url)"'

struct Pkg {
	ecosystem string
	name      string
}

struct Vuln {
mut:
	package                  Pkg
	vulnerable_version_range string @[omitempty]
	patched_versions         string @[omitempty]
	vulnerable_functions     []string
}

struct Credit {
	login string
	typ   string @[json: 'type']
}

struct Adv {
mut:
	summary            string
	description        string
	severity           string @[omitempty]
	cvss_vector_string string @[omitempty]
	cwe_ids            []string
	credits            []Credit
	vulnerabilities    []Vuln
}

// runs a user configured shell command ($EDITOR, $GHAV_AI..) with $1.. bound to args
fn sh(cmd string, args ...string) int {
	return os.system_args(['sh', '-c', cmd, 'sh', ...args])
}

fn csv(s string) []string {
	return s.split(',').map(it.trim_space()).filter(it != '')
}

fn gh(args ...string) !string {
	r := os.exec(['gh', ...args])
	if r.exit_code != 0 {
		return error(r.output.trim_space())
	}
	return r.output
}

fn parse(text string) !Adv {
	sep := text.index('\n---\n') or { return error('missing --- separator') }
	mut a := Adv{
		description: text[sep + 5..].trim_space().trim_string_right('```').trim_space()
	}
	for line in text[..sep].split_into_lines() {
		l := line.trim_space()
		if l == '' || l.starts_with('#') {
			continue
		}
		k := l.all_before(':').trim_space()
		v := l.all_after_first(':').trim_space()
		if k in ['ecosystem', 'affected', 'patched', 'functions'] && a.vulnerabilities.len == 0 {
			return error('${k}: must follow a package: line')
		}
		mut last := if a.vulnerabilities.len > 0 {
			&a.vulnerabilities[a.vulnerabilities.len - 1]
		} else {
			unsafe { nil }
		}
		match k {
			'summary' { a.summary = v }
			'severity' { a.severity = v }
			'cvss' { a.cvss_vector_string = v }
			'cwe' { a.cwe_ids = csv(v) }
			'credits' {
				a.credits = csv(v).map(Credit{it.all_before(':'), if it.contains(':') {
					it.all_after_first(':')
				} else {
					'finder'
				}})
			}
			'package' { a.vulnerabilities << Vuln{ package: Pkg{'other', v} } }
			'ecosystem' { last.package = Pkg{v, last.package.name} }
			'affected' { last.vulnerable_version_range = v }
			'patched' { last.patched_versions = v }
			'functions' { last.vulnerable_functions = csv(v) }
			else { return error('unknown field: ${k}') }
		}
	}
	if a.summary == '' || a.description == '' {
		return error('summary and description are required')
	}
	if a.cvss_vector_string != '' {
		a.severity = '' // github rejects both
	}
	return a
}

// opens text in $EDITOR until it parses; returns none if emptied or equal to the original
// a .diff name is applied to orig after editing, see apply()
fn edit(name string, text string, orig string) ?Adv {
	path := os.join_path(os.temp_dir(), 'ghav-${name}')
	os.write_file(path, text) or { return none }
	defer {
		os.rm(path) or {}
	}
	for {
		sh('${os.getenv_opt('EDITOR') or { 'vi' }} "\$1"', path)
		mut res := os.read_file(path) or { return none }
		if name.ends_with('.diff') {
			res = apply(orig, res)
		}
		if res.trim_space() == '' || res == orig {
			println('aborted')
			return none
		}
		return parse(res) or {
			if os.input('error: ${err}. edit again? [Y/n] ').to_lower() == 'n' {
				return none
			}
			continue
		}
	}
	return none
}

// spawns the agent and returns its reply as editable text, notes as comments
fn ask_ai(prompt string) !(string, string) {
	pf := os.join_path(os.temp_dir(), 'ghav-prompt-${os.getpid()}.txt')
	of := pf + '.out'
	os.write_file(pf, prompt)!
	defer {
		os.rm(pf) or {}
		os.rm(of) or {}
	}
	ai := os.getenv_opt('GHAV_AI') or { agents[0] }
	println('running ${ai} ...')
	if sh('{ ${ai}\n} < "\$1" > "\$2"', pf, of) != 0 {
		return error('agent failed')
	}
	out := os.read_file(of)!
	at := if out.starts_with('summary:') {
		0
	} else {
		out.last_index('\nsummary:') or {
			return error('no advisory in agent reply:\n${out}')
		} + 1
	}
	return out[..at].trim_space(), out[at..]
}

// unified diff of the whole text, preceded by free text notes
fn udiff(notes string, a string, b string) !string {
	fa := os.join_path(os.temp_dir(), 'ghav-a-${os.getpid()}')
	fb := fa.replace('-a-', '-b-')
	os.write_file(fa, a)!
	os.write_file(fb, b)!
	defer {
		os.rm(fa) or {}
		os.rm(fb) or {}
	}
	d := os.exec(['diff', '-U', '99999', '-L', 'advisory', '-L', 'review', fa, fb]).output
	return notes.split_into_lines().map('  ' + it).join('\n') + '\n\n' + d
}

// rebuilds the text from an edited full-context diff: removed '+' lines are not added,
// removed '-' lines keep the original line, edited
// context lines replace it, everything before the first @@ is ignored
fn apply(orig string, patch string) string {
	src := orig.split_into_lines()
	mut out := []string{}
	mut add := []string{} // '+' lines go after the kept originals they replace
	mut i := 0
	mut body := false
	for l in patch.split_into_lines() {
		if !body || l.starts_with('\\') {
			body = body || l.starts_with('@@')
			continue
		}
		if l.starts_with('+') {
			add << l[1..]
			continue
		}
		t := l#[1..]
		j := src#[i..].index(t)
		if j > 0 {
			out << src[i..i + j] // their '-' lines were removed
			i += j
		}
		out << add
		add.clear()
		if !l.starts_with('-') {
			out << t // context, or an edited context line replacing src[i]
		}
		i++
	}
	out << src#[i..]
	out << add
	return out.join('\n') + '\n'
}

fn fetch(repo string, id string) !string {
	return gh('api', 'repos/${repo}/security-advisories/${id}', '--jq', jq_text)!.replace('\r', '')
}

fn list(repo string, state string) ![][]string {
	if state != '' && state !in states {
		return error('invalid state: ${state}; choose ${states.join(', ')}')
	}
	query := if state in ['', 'all'] { '' } else { '?state=${state}' }
	out := gh('api', '--paginate', 'repos/${repo}/security-advisories${query}', '--jq', '.[] | [.ghsa_id, .state, .cve_id // "-", .severity // "-", .summary, ([.description // "" | scan("[0-9a-f]{10,40}")] | join(","))] | @tsv')!
	return out.split_into_lines().filter(it != '').map(it.split('\t'))
}

fn advisory_status(repo string, id string) !string {
	return gh('api', 'repos/${repo}/security-advisories/${id}', '--jq', jq_status)
}

fn request_cve(repo string, id string) !string {
	cve := gh('api', 'repos/${repo}/security-advisories/${id}', '--jq', '.cve_id // ""')!.trim_space()
	if cve != '' {
		return 'CVE already assigned: ${cve}'
	}
	gh('api', '--method', 'POST', 'repos/${repo}/security-advisories/${id}/cve')!
	return 'CVE request accepted; assignment is asynchronous. Check with ghav status ${id}'
}

// tagged fix commits in the cwd checkout: sha, date, subject
fn commits() ![][]string {
	grep := os.getenv_opt('GHAV_GREP') or { '##(crash|security)' }
	r := os.exec(['git', 'log', '-E', '--grep=${grep}', '-n', '2000', '--format=%H%x09%as%x09%s'])
	if r.exit_code != 0 {
		return error(r.output.trim_space())
	}
	return r.output.split_into_lines().filter(it != '').map(it.split('\t'))
}

// index of the advisory whose description references the commit
fn adv_of(advs [][]string, sha string) int {
	for i, a in advs {
		if a.len > 5 && a[5].split(',').any(it != '' && sha.starts_with(it)) {
			return i
		}
	}
	return -1
}

fn send(method string, path string, a Adv) !string {
	f := os.join_path(os.temp_dir(), 'ghav-${os.getpid()}.json')
	os.write_file(f, json2.encode(a))!
	defer {
		os.rm(f) or {}
	}
	return gh('api', '--method', method, path, '--input', f, '--jq', '.ghsa_id')
}

fn set_state(repo string, id string, state string) ! {
	gh('api', '--method', 'PATCH', 'repos/${repo}/security-advisories/${id}', '-f', 'state=${state}')!
}

fn cmd_new(repo string, commit string, ctx string) ! {
	patch := gh('api', '-H', 'Accept: application/vnd.github.patch', 'repos/${repo}/commits/${commit}')!
	existing := list(repo, '')!.map(it.join(' ')).join('\n')
	url := 'https://github.com/${repo}/commit/${commit}'
	notes, text := ask_ai('You are a security engineer preparing a GitHub Security Advisory for ${repo}.
Analyze the fix commit below. You may inspect the repository checkout in the current directory,
its git history and tags, and build and run reproducers against the vulnerable and patched revisions.
Determine whether it fixes a real vulnerability, the root cause, attack vector and preconditions,
the CWE, the CVSS 3.1 vector, the vulnerable functions and the affected and patched releases.
Do not assume every older release is affected: find when the vulnerable code was introduced.
If the commit fixes several independent vulnerabilities, describe the most important one and
list the others in your notes. Flag duplicates of the existing advisories listed below.
Include ${url} in the references.

${reply}

Fix commit: ${url}
Extra context: ${ctx}
Existing advisories:
${existing}

${patch#[..200000]}')!
	a := edit('${commit}.md', notes.split_into_lines().map('# ' + it).join('\n') + '\n' + text,
		'') or { return }
	println(send('POST', 'repos/${repo}/security-advisories', a)!.trim_space())
}

fn cmd_edit(repo string, id string, name string, text string, orig string) ! {
	a := edit(name, text, orig) or { return }
	send('PATCH', 'repos/${repo}/security-advisories/${id}', a)!
}

fn cmd_review(repo string, id string, ctx string) ! {
	orig := fetch(repo, id)!
	notes, text := ask_ai('Review this draft GitHub Security Advisory for ${repo}. Verify its claims against
the fix commit referenced in it (use gh, git and the checkout in the current directory), check the
affected and patched versions, CWE, CVSS and severity, and improve the wording: be concise and precise.
${reply}

Extra context: ${ctx}

${orig}')!
	head := if orig.starts_with('#') { orig.all_before('\n') + '\n' } else { '' }
	patch := udiff(notes, orig, head + text)!
	cmd_edit(repo, id, '${id}.diff', patch, orig)!
}

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

// interactive actions, run with the terminal in cooked mode; sha is set in the git view
fn run(k string, repo string, id string, sha string) ! {
	match k {
		'?' {
			println(tui_help)
			println('\nagent: ${os.getenv_opt('GHAV_AI') or { agents[0] }}')
			os.input('press enter')
		}
		's' {
			println(advisory_status(repo, id)!)
			os.input('press enter')
		}
		'e' {
			text := fetch(repo, id)!
			cmd_edit(repo, id, '${id}.md', text, text)!
		}
		'r' {
			cmd_review(repo, id, os.input('extra context: '))!
		}
		'n' {
			args := if sha != '' { sha } else { os.input('commit [context]: ').trim_space() }
			if args != '' {
				cmd_new(repo, args.all_before(' '), args.all_after_first(' '))!
			}
		}
		else {
			if sha != '' {
				os.system_args(['git', 'show', sha])
				return
			}
			path := os.join_path(os.temp_dir(), 'ghav-${id}.md')
			os.write_file(path, fetch(repo, id)!)!
			if os.exists_in_system_path('r2') {
				// The leading quote bypasses r2 command parsing for the filename.
				os.system_args(['r2', '-q', '-c', "'cat -m ${path}", '--'])
				os.input('press enter')
			} else {
				sh('${os.getenv_opt('PAGER') or { 'less' }} "\$1"', path)
			}
			os.rm(path)!
		}
	}
}

fn act(k string, repo string, id string) !string {
	match k {
		'a', 'c' { return request_cve(repo, id) }
		'd' { set_state(repo, id, 'draft')! }
		'p' { set_state(repo, id, 'published')! }
		'x' { set_state(repo, id, 'closed')! }
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

fn tui(repo string) {
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
	mut advs := list(repo, '') or { [['error:', err.msg()]] }
	mut cms := commits() or { [['error:', err.msg()]] }
	mut view := 0 // 0 advisories, 1 git
	mut sel := [0, 0]
	mut top := [0, 0]
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
		n := if view == 0 { visible.len } else { cms.len }
		sel[view] = if n == 0 { 0 } else { int_min(int_max(sel[view], 0), n - 1) }
		top[view] = int_min(int_max(top[view], sel[view] - page + 1), sel[view])
		sha := if view == 1 && cms.len > 0 && cms[sel[1]].len > 2 { cms[sel[1]][0] } else { '' }
		ai := if view == 0 {
			if visible.len > 0 { visible[sel[0]] } else { -1 }
		} else {
			adv_of(advs, sha)
		}
		id := if ai >= 0 && ai < advs.len && advs[ai].len >= 5 { advs[ai][0] } else { '' }
		actions := if id != '' {
			advisory_actions(advs[ai], cve_requested[id])
		} else {
			[]string{}
		}
		tabs := ['advisories ${visible.len} (${states[filter]})', 'commits ${cms.len}']
		header := 'ghav ${repo} | ' + tabs.map(if it == tabs[view] { '[${it}]' } else { it }).join(' | ')
		columns := if view == 0 {
			'${'ADVISORY':-20} ${'STATE':-10} ${'CVE':-15} ${'SEVERITY':-9} SUMMARY'
		} else {
			'${'COMMIT':-10} ${'DATE':-10} ${'ADVISORY':-20} SUBJECT'
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
			} else {
				line = crow(cms[i], advs, w)
			}
			out += if i == sel[view] { term.inverse(term.strip_ansi(line)) } else { line } + '\n'
		}
		if n == 0 {
			out += term.dim('No entries. Press f to change the filter or g to reload.') + '\n'
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
			'No advisory selected; n creates a draft from a commit'
		}
		out += '\x1b[${h - 2};1H' + hint#[..w - 1] + '\n'
		out += key_hints(['m actions', 's status', ...actions, 'g reload', 'A agent'], w - 1) + '\n'
		out += key_hints(['? help', 'q quit', 'tab views', 'j/k/J/K move', 'enter view', 'e edit',
			'r review', 'n new', 'f filter'], w - 1)
		print(out)
		mut k := key(true)
		mut show_sha := sha
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
			println('s status details\nv view advisory\ne edit advisory\nr AI review\n\nChoose a key; Enter/Esc cancels.')
			k = key(false)
			if k == 'v' {
				k = '\n'
				show_sha = ''
			} else if k !in ['s', 'e', 'r'] && !actions.any(it.starts_with(k + ' ')) {
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
				// jump to the linked commit or advisory when there is one
				if view == 1 && ai >= 0 {
					if ai !in visible {
						filter = 0
						sel[0] = ai
					} else {
						sel[0] = visible.index(ai)
					}
				} else if view == 0 && ai >= 0 {
					for c, cm in cms {
						if adv_of([advs[ai]], cm[0]) == 0 {
							sel[1] = c
							break
						}
					}
				}
				view = 1 - view
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
				advs = list(repo, '') or { [['error:', err.msg()]] }
				cms = commits() or { [['error:', err.msg()]] }
			}
			'\n', '\r', 'e', 'r', 'n', 's', '?' {
				if id == '' && (k in ['e', 'r', 's'] || (k in ['\n', '\r'] && sha == '')) {
					status = 'no advisory for this commit, press n to report it'
					continue
				}
				cooked()
				run(k, repo, id, if k in ['e', 'r', 's'] { '' } else { show_sha }) or {
					println('error: ${err}')
					os.input('press enter')
				}
				raw()
				advs = list(repo, '') or { advs }
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
					status = act(k, repo, id) or { 'error: ' + err.msg().replace('\n', ' ') }
					if status.starts_with('CVE request accepted') {
						cve_requested[id] = true
						status = 'CVE request accepted; assignment is asynchronous. g reload, s status'
					}
					advs = list(repo, '') or { advs }
				}
			}
			else {}
		}
	}
	cooked()
}

fn main() {
	mut args := os.args[1..].clone()
	mut repo := os.getenv('GHAV_REPO')
	if args.len > 1 && args[0] == '-r' {
		repo = args[1]
		args = args[2..].clone()
	}
	if args.len > 0 && args[0] in ['-h', '--help', 'help'] {
		println(help)
		return
	}
	if repo == '' {
		repo = gh('repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner') or {
			eprintln('cannot find repository, use -r owner/repo or GHAV_REPO')
			exit(1)
		}.trim_space()
	}
	cmd := if args.len > 0 { args[0] } else { 'tui' }
	id := if args.len > 1 { args[1] } else { '' }
	ctx := if args.len > 2 { args[2..].join(' ') } else { '' }
	if cmd !in ['tui', 'ls', 'log'] && id == '' {
		eprintln(help)
		exit(1)
	}
	match cmd {
		'tui' {
			tui(repo)
		}
		'ls' {
			for r in list(repo, id)! {
				println(row(r, 999))
			}
		}
		'log' {
			advs := list(repo, '')!
			for c in commits()! {
				println(crow(c, advs, 999))
			}
		}
		'new' {
			cmd_new(repo, id, ctx)!
		}
		'show' {
			print(fetch(repo, id)!)
		}
		'status' {
			println(advisory_status(repo, id)!)
		}
		'edit' {
			text := fetch(repo, id)!
			cmd_edit(repo, id, '${id}.md', text, text)!
		}
		'review' {
			cmd_review(repo, id, ctx)!
		}
		'cve', 'approve' {
			println(request_cve(repo, id)!)
		}
		'draft', 'publish', 'close' {
			if os.input('${cmd} ${id}? [y/N] ') == 'y' {
				state := match cmd {
					'draft' { 'draft' }
					'publish' { 'published' }
					else { 'closed' }
				}
				set_state(repo, id, state)!
			}
		}
		else {
			eprintln(help)
			exit(1)
		}
	}
}
