module main

import term

enum TuiLoadKind {
	repository
	advisories
	commits
	issues
	git_status
}

struct TuiLoad {
	kind TuiLoadKind
	rows [][]string
	text string
	error string
}

// Workers own their results; only the input loop changes the displayed snapshot.
fn tui_load(api GitHub, label string, kind TuiLoadKind, results chan TuiLoad) {
	mut rows := [][]string{}
	mut text := ''
	mut failure := ''
	match kind {
		.repository {
			text = github_repository() or { failure = err.msg(); '' }
			if text == '' && failure == '' { failure = 'cannot find repository' }
		}
		.advisories { rows = api.advisories('') or { failure = err.msg(); [][]string{} } }
		.commits { rows = commits() or { failure = err.msg(); [][]string{} } }
		.issues { rows = api.issues(label) or { failure = err.msg(); [][]string{} } }
		.git_status { text = local_git_status() }
	}
	results <- TuiLoad{kind, rows, text, failure}
}

struct TuiLoader {
	results chan TuiLoad = chan TuiLoad{cap: 5}
mut:
	pending []bool = []bool{len: 5}
	again []bool = []bool{len: 5}
}

// Coalesce repeated reloads. A workflow may require a fresh snapshot after an
// already running request; discard that old result before starting its successor.
fn (mut loader TuiLoader) request(api GitHub, label string, kind TuiLoadKind, fresh bool) {
	i := int(kind)
	if loader.pending[i] {
		loader.again[i] = loader.again[i] || fresh
		return
	}
	loader.pending[i] = true
	spawn tui_load(api, label, kind, loader.results)
}

fn (mut loader TuiLoader) poll(api GitHub, label string) ?TuiLoad {
	for {
		mut result := TuiLoad{}
		if loader.results.try_pop(mut result) != .success { return none }
		i := int(result.kind)
		loader.pending[i] = false
		if loader.again[i] {
			loader.again[i] = false
			loader.request(api, label, result.kind, false)
			continue
		}
		return result
	}
	return none
}

struct TuiActionResult {
	id string
	key string
	message string
}

fn tui_action(api GitHub, k string, id string, results chan TuiActionResult) {
	message := act(k, api, id) or { 'error: ' + err.msg().replace('\n', ' ') }
	results <- TuiActionResult{id, k, message}
}

fn tui_status_load(api GitHub, id string, results chan string) {
	results <- api.status(id) or { 'error: ${err}' }
}

fn tui_status(api GitHub, id string) {
	results := chan string{cap: 1}
	spawn tui_status_load(api, id, results)
	mut screen := TuiScreen{}
	for {
		mut text := ''
		if results.try_pop(mut text) == .success {
			tui_dialog(text)
			return
		}
		w, h := terminal_size()
		screen.draw(['Loading status for ${id}...', 'Esc/Ctrl+C/q: back'], w, h)
		if poll_key() in ['\x1b', '\x03', 'q', '\n', '\r'] { return }
	}
}

struct TuiRow {
	normal string
	selected string
}

// Search/link work is tied to data changes. Row formatting is lazy and cached at
// the current width, including the selected variant, so movement only paints it.
struct TuiList {
mut:
	links []int
	search []string
	matches []int
	visible []int
	formatted map[int]TuiRow
	width int
	query string
	state string
	filtered bool
}

fn (mut list TuiList) rebuild(entries [][]string, advs [][]string, links AdvisoryLinks, view int) {
	list.links = []int{len: entries.len, init: -1}
	list.search = []string{len: entries.len}
	for i, entry in entries {
		linked := if view == 0 { i } else if entry.len > 0 { links.find(entry[0]) } else { -1 }
		list.links[i] = linked
		list.search[i] = (entry.join(' ') + if view != 0 && linked >= 0 { ' ' + advs[linked][0] } else { '' }).to_lower()
	}
	list.formatted.clear()
	list.filtered = false
}

fn (mut list TuiList) filter(entries [][]string, query string, state string) {
	if list.filtered && list.query == query && list.state == state { return }
	list.query, list.state = query, state
	list.matches = []int{}
	list.visible = []int{}
	needle := query.to_lower()
	for i, text in list.search {
		if needle == '' || text.contains(needle) {
			list.matches << i
			if state == 'all' || (entries[i].len > 1 && entries[i][1] == state) { list.visible << i }
		}
	}
	list.filtered = true
}

fn (mut list TuiList) line(index int, entries [][]string, advs [][]string, view int, width int, selected bool) string {
	if list.width != width {
		list.formatted.clear()
		list.width = width
	}
	if index !in list.formatted {
		linked := list.links[index]
		a := if linked >= 0 { advs[linked] } else { []string{} }
		normal := match view {
			0 { row(entries[index], width) }
			1 { commit_row(entries[index], a, width) }
			else { issue_row(entries[index], a, width) }
		}
		list.formatted[index] = TuiRow{normal, term.inverse(term.strip_ansi(normal))}
	}
	line := list.formatted[index]
	return if selected { line.selected } else { line.normal }
}
