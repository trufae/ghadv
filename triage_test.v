module main

import os
import term

fn test_invalid_marks_persist_and_are_scoped_to_host_repository_and_item() ! {
	dir := os.join_path(os.temp_dir(), 'gsadv-invalid-test-${os.getpid()}')
	old_state := os.getenv_opt('XDG_STATE_HOME')
	old_host := os.getenv_opt('GH_HOST')
	os.setenv('XDG_STATE_HOME', dir, true)
	os.setenv('GH_HOST', 'github.com', true)
	defer {
		if value := old_state { os.setenv('XDG_STATE_HOME', value, true) } else { os.unsetenv('XDG_STATE_HOME') }
		if value := old_host { os.setenv('GH_HOST', value, true) } else { os.unsetenv('GH_HOST') }
		os.rmdir_all(dir) or {}
	}
	api := Repository{repo: 'owner/repo'}
	assert api.invalid_marks()!.len == 0
	assert !os.exists(dir)
	target := invalid_target(api.repo, 'GHSA-abcd-efgh-ijkl')!
	api.mark_invalid(target, ' No tagged release shipped vulnerable code.\nIntroduced and fixed after v1. ' )!
	assert Repository{repo: 'OWNER/REPO'}.invalid_marks()![target] == 'No tagged release shipped vulnerable code.\nIntroduced and fixed after v1.'
	assert Repository{repo: 'other/repo'}.invalid_marks()!.len == 0
	os.setenv('GH_HOST', 'enterprise.example', true)
	assert Repository{repo: api.repo, host: 'enterprise.example'}.invalid_marks()!.len == 0
	os.setenv('GH_HOST', 'github.com', true)
	issue := 'https://github.com/owner/repo/issues/1'
	api.mark_invalid(issue, 'Duplicate report')!
	api.mark_invalid(target, 'Corrected reason')!
	if _ := api.mark_invalid(target, '  ') { assert false, 'accepted empty reason' }
	assert api.invalid_marks()![target] == 'Corrected reason'
	api.unmark_invalid(target)!
	api.unmark_invalid(target)!
	assert api.invalid_marks()! == {issue: 'Duplicate report'}
	// A broken record is reported, rather than silently hiding a triage decision.
	os.write_file(api.invalid_path(issue), 'broken json')!
	if _ := api.invalid_marks() { assert false, 'ignored a corrupt record' }
}

fn test_invalid_target_normalization() ! {
	sha := 'a'.repeat(40)
	assert invalid_target('owner/repo', sha.to_upper())! == sha
	assert invalid_target('owner/repo', 'https://github.com/OWNER/REPO/commit/${sha}')! == sha
	assert invalid_target('owner/repo', 'https://github.com/OWNER/REPO/issues/42/?q=x#comment')! == 'https://github.com/owner/repo/issues/42'
	assert invalid_target('owner/repo', 'https://github.com/owner/repo/pull/42')! != invalid_target('owner/repo', 'https://github.com/owner/repo/issues/42')!
	if _ := invalid_target('owner/repo', 'https://github.com/other/repo/issues/42') {
		assert false, 'accepted another repository'
	}
}

fn test_invalid_tags_in_lists_search_and_clear_without_changing_lifecycle() {
	advs := [['GHSA-one', 'draft', '-', 'high', 'Bounds check', 'abcdef1234', '']]
	entries := [['abcdef1234567890', '2026-11-09', 'Fix bounds check']]
	mut list := TuiList{}
	list.rebuild(entries, advs, advisory_links(advs), 1)
	list.mark_invalid(entries, {'abcdef1234567890': 'No tagged release affected'})
	list.filter(entries, 'no tagged release', 'all')
	assert list.visible == [0]
	for width in [10, 30, 80, 120] {
		line := list.line(0, entries, advs, 1, width, false)
		assert line.starts_with('[invalid]')
		assert clip_line(line, line_width(width)) == line
		assert term.strip_ansi(list.line(0, entries, advs, 1, width, true)) == term.strip_ansi(line)
	}
	// Marking a source does not implicitly mark its linked advisory.
	list.rebuild(advs, advs, advisory_links(advs), 0)
	list.mark_invalid(advs, {'abcdef1234567890': 'No tagged release affected'})
	assert !list.line(0, advs, advs, 0, 120, false).contains('[invalid]')
	list.mark_invalid(advs, {'ghsa-one': 'No tagged release affected'})
	list.filter(advs, 'invalid', 'draft')
	assert list.visible == [0]
	assert list.line(0, advs, advs, 0, 120, false).contains('[invalid]')
	assert advs[0][1] == 'draft'
	list.rebuild(advs, advs, advisory_links(advs), 0)
	list.mark_invalid(advs, map[string]string{})
	list.filter(advs, 'invalid', 'all')
	assert list.visible == []int{}
	assert !list.line(0, advs, advs, 0, 120, false).contains('[invalid]')
}
