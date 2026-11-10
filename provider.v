module main

fn (api Repository) states() []string {
	return if api.provider == 'gitlab' { ['all', 'opened', 'closed'] } else { states }
}

fn (api Repository) cli() string {
	return if api.provider == 'gitlab' { 'glab' } else { 'gh' }
}

fn (api Repository) is_advisory(input string) bool {
	return if api.provider == 'gitlab' { input.starts_with('GL-') } else { input.starts_with('GHSA-') }
}

fn (api Repository) actions(a []string) []string {
	if api.provider == 'github' { return advisory_actions(a) }
	if a.len < 5 { return []string{} }
	mut actions := ['c CVE request instructions']
	if a[1] == 'closed' { actions << 'd reopen issue' }
	if a[1] == 'opened' { actions << 'x close issue' }
	return actions
}

fn (api Repository) advisories(state string) ![][]string {
	if state != '' && state !in api.states() { return error('invalid state: ${state}; choose ${api.states().join(', ')}') }
	return if api.provider == 'gitlab' { api.gitlab_advisories(state)! } else { api.github_advisories(state)! }
}

fn (api Repository) advisory(id string) !string {
	return if api.provider == 'gitlab' { api.gitlab_advisory(id)! } else { api.github_advisory(id)! }
}

fn (api Repository) status(id string) !string {
	return if api.provider == 'gitlab' { api.gitlab_status(id)! } else { api.github_status(id)! }
}

fn (api Repository) issues(label string) ![][]string {
	return if api.provider == 'gitlab' { api.gitlab_issues(label)! } else { api.github_issues(label)! }
}

fn (api Repository) source_text(s Source, with_patch bool) !string {
	return if api.provider == 'gitlab' { api.gitlab_source_text(s, with_patch)! } else { api.github_source_text(s, with_patch)! }
}

fn (api Repository) create_advisory(a Adv) !string {
	return if api.provider == 'gitlab' { api.gitlab_create_advisory(a)! } else { api.github_create_advisory(a)! }
}

fn (api Repository) update_advisory(id string, a Adv) ! {
	if api.provider == 'gitlab' { api.gitlab_update_advisory(id, a)! } else { api.github_update_advisory(id, a)! }
	text := api.advisory(id) or { return error('Update accepted, but reloading ${id} failed: ${err}') }
	saved := parse(text) or { return error('Update accepted, but the reloaded advisory is invalid: ${err}') }
	fields := advisory_changes(a, saved)
	if fields.len > 0 { return error('Update accepted, but the reloaded advisory differs in: ${fields.join(', ')}') }
}

fn (api Repository) set_state(id string, state string) ! {
	if api.provider == 'gitlab' { api.gitlab_set_state(id, state)! } else { api.github_set_state(id, state)! }
}

fn (api Repository) request_cve(id string) !string {
	return if api.provider == 'gitlab' { api.gitlab_cve_guidance(id)! } else { api.github_request_cve(id)! }
}

fn (api Repository) credits(id string) ![]Credit {
	if api.provider == 'gitlab' { return error('GitLab has no structured advisory credits; use edit to maintain attribution in the report') }
	return api.github_credits(id)
}

fn (api Repository) update_credits(id string, credits []Credit) ! {
	if api.provider == 'gitlab' { return error('GitLab has no structured advisory credits; use edit') }
	api.github_update_credits(id, credits)!
}
