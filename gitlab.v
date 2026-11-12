module main

import os
import json2
import net.urllib
import regex

// Keep the serialized marker compatible with existing disclosure issues.
const gitlab_advisory_marker = '<!-- ghadv:advisory -->\n```text\n'

struct GitLabUser {
	username string
}

struct GitLabIssue {
	iid int
	title string
	description string
	state string
	confidential bool
	web_url string
	labels []string
	author GitLabUser
	created_at string
	updated_at string
	closed_at string
	merged_at string
	merge_commit_sha string
	source_branch string
	target_branch string
}

struct GitLabNote {
	id int
	body string
	author GitLabUser
}

struct GitLabDiff {
	old_path string
	new_path string
	diff string
	too_large bool
	collapsed bool
}

struct GitLabCommit {
	id string
	message string
	author_name string
	web_url string
}

struct GitLabEdit {
	title string
	description string
}

struct GitLabCreate {
	title string
	description string
	confidential bool = true
	labels string
}

fn gitlab_advisory_label() string {
	label := setting('ADVISORY_LABEL') or { '' }
	return if label != '' { label } else { 'security-advisory' }
}

fn (api Repository) gitlab_project() string {
	return 'projects/' + urllib.path_escape(api.repo)
}

fn (api Repository) gitlab_request(args ...string) !string {
	r := os.exec(['glab', 'api', '--hostname', api.host, ...args])
	if r.exit_code != 0 { return error(r.output.trim_space()) }
	return r.output
}

fn (api Repository) gitlab_send(method string, path string, payload string) !string {
	file := os.join_path(os.temp_dir(), 'gsadv-gitlab-${os.getpid()}.json')
	os.write_file(file, payload)!
	defer { os.rm(file) or {} }
	return api.gitlab_request('--method', method, path, '--input', file)
}

fn (api Repository) gitlab_list[T](path string) ![]T {
	out := api.gitlab_request(path, '--paginate', '--output', 'ndjson')!
	mut items := []T{}
	for line in out.split_into_lines().filter(it.trim_space() != '') {
		items << json2.decode[T](line)!
	}
	return items
}

fn gitlab_iid(id string) !string {
	number := id.trim_string_left('GL-').trim_string_left('#')
	if number == '' || !number.bytes().all(it.is_digit()) || number.u64() == 0 {
		return error('expected a GitLab disclosure ID such as GL-123')
	}
	return number
}

fn (api Repository) gitlab_issue(id string) !GitLabIssue {
	iid := gitlab_iid(id)!
	issue := json2.decode[GitLabIssue](api.gitlab_request('${api.gitlab_project()}/issues/${iid}')!)!
	if issue.iid == 0 { return error('GitLab returned an issue without an IID') }
	return issue
}

fn text_matches(text string, pattern string) []string {
	mut re := regex.regex_opt(pattern) or { return []string{} }
	mut matches := []string{}
	for value in re.find_all_str(text) {
		if value !in matches { matches << value }
	}
	return matches
}

fn gitlab_cves(issue GitLabIssue) string {
	ids := text_matches('${issue.title}\n${issue.description}', 'CVE-[0-9]{4}-[0-9]{4,}')
	return if ids.len == 0 { '-' } else { ids.join(',') }
}

// The issue title is authoritative. Metadata is ordinary issue text, not native
// GitLab security fields. Unstructured labeled reports can be edited losslessly.
fn gitlab_issue_advisory(issue GitLabIssue) !Adv {
	if !issue.description.starts_with(gitlab_advisory_marker) {
		return Adv{summary: issue.title, description: issue.description}
	}
	text := issue.description[gitlab_advisory_marker.len..]
	end := text.index('\n```\n\n') or { return error('damaged gsadv metadata in GL-${issue.iid}; repair the issue description') }
	mut a := parse(text[..end] + '\n---\n' + text[end + 6..])!
	a.summary = issue.title
	return a
}

fn advisory_text(a Adv) string {
	mut text := 'summary: ${a.summary}\nseverity: ${a.severity}\ncvss: ${a.cvss_vector_string}\ncwe: ${a.cwe_ids.join(', ')}\ncredits: ' +
		a.credits.map('${it.login}:${it.typ}').join(', ') + '\n'
	for v in a.vulnerabilities {
		text += 'package: ${v.package.name}\necosystem: ${v.package.ecosystem}\naffected: ${v.vulnerable_version_range}\npatched: ${v.patched_versions}\n'
	}
	return text + '---\n' + a.description
}

fn gitlab_description(a Adv) string {
	text := advisory_text(a)
	return gitlab_advisory_marker + text.all_before('\n---\n') + '\n```\n\n' + a.description
}

fn (api Repository) gitlab_advisory(id string) !string {
	issue := api.gitlab_issue(id)!
	visibility := if issue.confidential { 'confidential' } else { 'public' }
	return '# GL-${issue.iid} ${issue.state} ${visibility} ${gitlab_cves(issue)} ${issue.web_url}\n' + advisory_text(gitlab_issue_advisory(issue)!)
}

fn (api Repository) gitlab_advisories(state string) ![][]string {
	filter := if state in ['', 'all'] { 'all' } else { state }
	items := api.gitlab_list[GitLabIssue]('${api.gitlab_project()}/issues?scope=all&state=${filter}&per_page=100&labels=${urllib.query_escape(gitlab_advisory_label())}')!
	mut rows := [][]string{}
	for item in items {
		a := gitlab_issue_advisory(item)!
		mut urls := [item.web_url]
		for token in item.description.fields() {
			if at := token.index('https://') {
				url := token[at..].trim_right(').,;]>"')
				if s := api.source(url) { urls << s.url }
			}
		}
		rows << ['GL-${item.iid}', item.state, gitlab_cves(item), a.severity, item.title,
			text_matches(item.description, '[0-9a-f]{10,40}').join(','), urls.join(','),
			if item.confidential { 'confidential' } else { 'public' }]
	}
	return rows
}

fn (api Repository) gitlab_issues(label string) ![][]string {
	if label == '' { return [][]string{} }
	mut rows := [][]string{}
	for kind in ['issues', 'merge_requests'] {
		for item in api.gitlab_list[GitLabIssue]('${api.gitlab_project()}/${kind}?scope=all&state=all&per_page=100&labels=${urllib.query_escape(label)}')! {
			rows << [item.web_url, item.iid.str(), if kind == 'issues' { 'issue' } else { 'MR' },
				item.state, item.title]
		}
	}
	return rows
}

fn (api Repository) gitlab_status(id string) !string {
	issue := api.gitlab_issue(id)!
	return 'disclosure: GL-${issue.iid}\nstate: ${issue.state}\nvisibility: ' +
		if issue.confidential { 'confidential' } else { 'public' } +
		'\ncve references: ${gitlab_cves(issue)}\ncreated: ${issue.created_at}\nupdated: ${issue.updated_at}\nclosed: ${issue.closed_at}\nurl: ${issue.web_url}\n\nThis is a GitLab issue, not a published CVE record.'
}

fn (api Repository) gitlab_source_text(s Source, with_patch bool) !string {
	if s.kind == 'commit' {
		path := '${api.gitlab_project()}/repository/commits/${urllib.path_escape(s.ref)}'
		commit := json2.decode[GitLabCommit](api.gitlab_request(path)!)!
		return '# ${commit.id}\nAuthor: ${commit.author_name}\nURL: ${commit.web_url}\n\n${commit.message}\n\n' + api.gitlab_diff('${path}/diff?per_page=100')!
	}
	path := '${api.gitlab_project()}/${s.kind}/${s.ref}'
	item := json2.decode[GitLabIssue](api.gitlab_request(path)!)!
	mut text := '# ${item.title}\n\nURL: ${item.web_url}\nAuthor: @${item.author.username}\nState: ${item.state}\nConfidential: ${item.confidential}\n'
	if s.kind == 'merge_requests' {
		text += 'Merged: ${item.state == 'merged'}\nMerged at: ${item.merged_at}\nMerge commit: ${item.merge_commit_sha}\nBase: ${item.target_branch}\nHead: ${item.source_branch}\n'
	}
	text += '\n${item.description}\n\n## Discussion\n'
	for note in api.gitlab_list[GitLabNote]('${path}/notes?per_page=100&sort=asc')! {
		text += '\n### @${note.author.username}\n${item.web_url}#note_${note.id}\n\n${note.body}\n'
	}
	if s.kind == 'merge_requests' && with_patch { text += '\nMR patch:\n' + api.gitlab_diff('${path}/diffs?per_page=100')! }
	return text
}

fn (api Repository) gitlab_diff(path string) !string {
	mut text := ''
	for diff in api.gitlab_list[GitLabDiff](path)! {
		text += 'diff --git a/${diff.old_path} b/${diff.new_path}\n--- a/${diff.old_path}\n+++ b/${diff.new_path}\n${diff.diff}\n'
		if diff.too_large || diff.collapsed || diff.diff == '' { text += '[GitLab omitted this diff; inspect the commit locally.]\n' }
	}
	if text.len > 200000 { return text[..200000] + '\n[Diff truncated by gsadv; inspect the commit locally.]\n' }
	return text
}

fn (api Repository) gitlab_create_advisory(a Adv) !string {
	payload := GitLabCreate{title: a.summary, description: gitlab_description(a), labels: gitlab_advisory_label()}
	issue := json2.decode[GitLabIssue](api.gitlab_send('POST', '${api.gitlab_project()}/issues', json2.encode(payload))!)!
	if issue.iid == 0 { return error('GitLab accepted creation but returned no issue IID; check the project before retrying') }
	if !issue.confidential { return error('GL-${issue.iid} was created but GitLab did not confirm confidentiality; inspect ${issue.web_url}') }
	return 'GL-${issue.iid}'
}

fn (api Repository) gitlab_update_advisory(id string, a Adv) ! {
	iid := gitlab_iid(id)!
	// Editing content never changes labels, state or confidentiality.
	api.gitlab_send('PUT', '${api.gitlab_project()}/issues/${iid}', json2.encode(GitLabEdit{a.summary, gitlab_description(a)}))!
}

fn (api Repository) gitlab_set_state(id string, state string) ! {
	if state !in ['opened', 'closed'] { return error('GitLab disclosures use opened/closed; use reopen or close. Publishing is not supported; manage visibility on GitLab.') }
	iid := gitlab_iid(id)!
	event := if state == 'opened' { 'reopen' } else { 'close' }
	api.gitlab_send('PUT', '${api.gitlab_project()}/issues/${iid}', json2.encode({'state_event': event}))!
}

fn (api Repository) gitlab_cve_guidance(id string) !string {
	issue := api.gitlab_issue(id)!
	if api.host != 'gitlab.com' {
		return 'GitLab CNA requests are available for public projects on GitLab.com, not this host.\nUse your CNA to request a CVE, then record its ID in ${issue.web_url}'
	}
	return 'No CVE request was submitted. GitLab uses a separate CVE request issue.\nFor a public GitLab.com project, a Maintainer/Owner can open the confidential disclosure\nand select Create CVE ID Request: ${issue.web_url}\n' +
		if issue.confidential { '' } else { 'This issue is currently public; GitLab requires a confidential source issue.\n' } +
		'https://docs.gitlab.com/user/application_security/cve_id_request/'
}
