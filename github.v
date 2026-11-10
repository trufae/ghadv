module main

import os
import json2
import net.urllib
import time

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
"] | join("")) + "---\\n" + (.description // "")'

const jq_status = '"advisory: \\(.ghsa_id)
state: \\(.state)
cve: \\(.cve_id // "unassigned")
private report: \\(if .submission == null then "no" elif .submission.accepted then "accepted" else "not accepted" end)
created: \\(.created_at // "-")
updated: \\(.updated_at // "-")
published: \\(.published_at // "-")
closed: \\(.closed_at // "-")
withdrawn: \\(.withdrawn_at // "-")
private fork: \\(.private_fork.html_url // "-")
url: \\(.html_url)"'

const jq_source = '"# \\(.title)\n\nURL: \\(.html_url)\nAuthor: @\\(.user.login)\nState: \\(.state)\n" +
(if has("merged") then "Merged: \\(.merged)\nMerged at: \\(.merged_at // "-")\nMerge commit: \\(.merge_commit_sha // "-")\nBase: \\(.base.ref)\nHead: \\(.head.ref)\n" else "" end) +
"\n" + (.body // "")'

fn (api Repository) github_source_text(s Source, with_patch bool) !string {
	if s.kind == 'commit' {
		patch := api.github_request('-H', 'Accept: application/vnd.github.patch', 'repos/${api.repo}/commits/${s.ref}')!
		return patch#[..200000]
	}
	endpoint := if s.kind == 'pull' { 'pulls' } else { 'issues' }
	mut text := api.github_request('repos/${api.repo}/${endpoint}/${s.ref}', '--jq', jq_source)!
	comments := api.github_request('--paginate', 'repos/${api.repo}/issues/${s.ref}/comments?per_page=100',
		'--jq', '.[] | "### @\\(.user.login)\n\\(.html_url)\n\n\\(.body // "")\n"')!
	text += '\n## Discussion\n${comments}'
	if s.kind == 'pull' && with_patch {
		patch := api.github_request('-H', 'Accept: application/vnd.github.patch', 'repos/${api.repo}/pulls/${s.ref}')!
		text += '\nPR patch:\n${patch#[..200000]}'
	}
	return text
}

fn (api Repository) github_advisory(id string) !string {
	return api.github_request('repos/${api.repo}/security-advisories/${id}', '--jq', jq_text)!.replace('\r', '')
}

fn (api Repository) github_advisories(state string) ![][]string {
	if state != '' && state !in states {
		return error('invalid state: ${state}; choose ${states.join(', ')}')
	}
	query := '?per_page=100' + if state in ['', 'all'] { '' } else { '&state=${state}' }
	out := api.github_request('--paginate', 'repos/${api.repo}/security-advisories${query}', '--jq', '.[] | [.ghsa_id, .state, .cve_id // "-", .severity // "-", .summary, ([.description // "" | scan("[0-9a-f]{10,40}")] | join(",")), ([.description // "" | scan("https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull)/[0-9]+")] | join(","))] | @tsv')!
	mut rows := out.split_into_lines().filter(it != '').map(it.split('\t'))
	for mut row in rows {
		if row.len >= 5 && row[2] == '-' && api.cve_requested_at(row[0]) != '' {
			row[2] = 'requested*'
		}
	}
	return rows
}

fn (api Repository) github_status(id string) !string {
	text := api.github_request('repos/${api.repo}/security-advisories/${id}', '--jq', jq_status)!
	requested_at := api.cve_requested_at(id)
	cve := if requested_at != '' {
		'requested* (no CVE assigned)\nrequest accepted: ${requested_at} (recorded locally; current GitHub request status unavailable)'
	} else {
		'unassigned (request status unknown; GitHub REST does not expose it)'
	}
	return text.replace_once('\ncve: unassigned\n', '\ncve: ${cve}\n')
}

// GitHub exposes assigned IDs, but no pending-request status. Keep a receipt of
// successful requests, shared by the CLI and TUI, without treating it as live status.
fn (api Repository) cve_request_path(id string) string {
	return api.state_path('cve-requests', id)
}

fn (api Repository) cve_requested_at(id string) string {
	text := os.read_file(api.cve_request_path(id)) or { return '' }
	stamp := text.trim_space()
	time.parse_rfc3339(stamp) or { return '' }
	return stamp
}

fn (api Repository) save_cve_request(id string) ! {
	path := api.cve_request_path(id)
	os.mkdir_all(os.dir(path), mode: 0o700)!
	os.write_file(path, time.utc().format_rfc3339() + '\n')!
}

fn (api Repository) github_request_cve(id string) !string {
	cve := api.github_request('repos/${api.repo}/security-advisories/${id}', '--jq', '.cve_id // ""')!.trim_space()
	if cve != '' {
		return 'CVE already assigned: ${cve}'
	}
	api.github_request('--method', 'POST', 'repos/${api.repo}/security-advisories/${id}/cve')!
	api.save_cve_request(id) or {
		return 'CVE request accepted, but could not save the local request receipt: ${err}. Check with ghadv status ${id}'
	}
	return 'CVE request accepted; assignment is asynchronous. Check with ghadv status ${id}'
}

// The issues endpoint includes pull requests. Closed items may still need a CVE.
fn (api Repository) github_issues(label string) ![][]string {
	if label == '' {
		return [][]string{}
	}
	out := api.github_request('--paginate',
		'repos/${api.repo}/issues?state=all&per_page=100&labels=${urllib.query_escape(label)}',
		'--jq', '.[] | [(.pull_request.html_url // .html_url), .number, (if .pull_request then "PR" else "issue" end), .state, .title] | @tsv')!
	return out.split_into_lines().filter(it != '').map(it.split('\t'))
}

struct AdvisoryCredits {
	credits []Credit
}

fn (api Repository) github_credits(id string) ![]Credit {
	return json2.decode[[]Credit](api.github_request('repos/${api.repo}/security-advisories/${id}',
		'--jq', '.credits // []')!)
}

fn (api Repository) github_update_credits(id string, credits []Credit) ! {
	api.github_send('PATCH', 'repos/${api.repo}/security-advisories/${id}',
		json2.encode(AdvisoryCredits{ credits: credits }))!
}

fn (api Repository) github_send(method string, path string, payload string) !string {
	f := os.join_path(os.temp_dir(), 'ghadv-${os.getpid()}.json')
	os.write_file(f, payload)!
	defer {
		os.rm(f) or {}
	}
	return api.github_request('--method', method, path, '--input', f, '--jq', '.ghsa_id')
}

fn (api Repository) github_set_state(id string, state string) ! {
	api.github_request('--method', 'PATCH', 'repos/${api.repo}/security-advisories/${id}', '-f', 'state=${state}')!
}

fn (api Repository) github_create_advisory(a Adv) !string {
	return api.github_send('POST', 'repos/${api.repo}/security-advisories', json2.encode(a))!.trim_space()
}

fn (api Repository) github_update_advisory(id string, a Adv) ! {
	api.github_send('PATCH', 'repos/${api.repo}/security-advisories/${id}', json2.encode(a))!
}

fn (api Repository) github_request(args ...string) !string {
	r := os.exec(['gh', 'api', '--hostname', api.host, ...args])
	if r.exit_code != 0 { return error(r.output.trim_space()) }
	return r.output
}
