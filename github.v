module main

import os
import json2
import net.urllib

// Repository-scoped GitHub API. All requests use the authenticated gh CLI.
struct GitHub {
	repo string
}

fn github_repository() !string {
	return gh('repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner')!.trim_space()
}

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

const jq_source = '"# \\(.title)\n\nURL: \\(.html_url)\nAuthor: @\\(.user.login)\nState: \\(.state)\n" +
(if has("merged") then "Merged: \\(.merged)\nMerged at: \\(.merged_at // "-")\nMerge commit: \\(.merge_commit_sha // "-")\nBase: \\(.base.ref)\nHead: \\(.head.ref)\n" else "" end) +
"\n" + (.body // "")'

fn gh(args ...string) !string {
	r := os.exec(['gh', ...args])
	if r.exit_code != 0 {
		return error(r.output.trim_space())
	}
	return r.output
}

fn (api GitHub) source_text(s Source, with_patch bool) !string {
	if s.kind == 'commit' {
		patch := gh('api', '-H', 'Accept: application/vnd.github.patch', 'repos/${api.repo}/commits/${s.ref}')!
		return patch#[..200000]
	}
	endpoint := if s.kind == 'pull' { 'pulls' } else { 'issues' }
	mut text := gh('api', 'repos/${api.repo}/${endpoint}/${s.ref}', '--jq', jq_source)!
	comments := gh('api', '--paginate', 'repos/${api.repo}/issues/${s.ref}/comments?per_page=100',
		'--jq', '.[] | "### @\\(.user.login)\n\\(.html_url)\n\n\\(.body // "")\n"')!
	text += '\n## Discussion\n${comments}'
	if s.kind == 'pull' && with_patch {
		patch := gh('api', '-H', 'Accept: application/vnd.github.patch', 'repos/${api.repo}/pulls/${s.ref}')!
		text += '\nPR patch:\n${patch#[..200000]}'
	}
	return text
}

fn (api GitHub) advisory(id string) !string {
	return gh('api', 'repos/${api.repo}/security-advisories/${id}', '--jq', jq_text)!.replace('\r', '')
}

fn (api GitHub) advisories(state string) ![][]string {
	if state != '' && state !in states {
		return error('invalid state: ${state}; choose ${states.join(', ')}')
	}
	query := if state in ['', 'all'] { '' } else { '?state=${state}' }
	out := gh('api', '--paginate', 'repos/${api.repo}/security-advisories${query}', '--jq', '.[] | [.ghsa_id, .state, .cve_id // "-", .severity // "-", .summary, ([.description // "" | scan("[0-9a-f]{10,40}")] | join(",")), ([.description // "" | scan("https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull)/[0-9]+")] | join(","))] | @tsv')!
	return out.split_into_lines().filter(it != '').map(it.split('\t'))
}

fn (api GitHub) status(id string) !string {
	return gh('api', 'repos/${api.repo}/security-advisories/${id}', '--jq', jq_status)
}

fn (api GitHub) request_cve(id string) !string {
	cve := gh('api', 'repos/${api.repo}/security-advisories/${id}', '--jq', '.cve_id // ""')!.trim_space()
	if cve != '' {
		return 'CVE already assigned: ${cve}'
	}
	gh('api', '--method', 'POST', 'repos/${api.repo}/security-advisories/${id}/cve')!
	return 'CVE request accepted; assignment is asynchronous. Check with ghav status ${id}'
}

// The issues endpoint includes pull requests. Closed items may still need a CVE.
fn (api GitHub) issues(label string) ![][]string {
	if label == '' {
		return [][]string{}
	}
	out := gh('api', '--paginate',
		'repos/${api.repo}/issues?state=all&per_page=100&labels=${urllib.query_escape(label)}',
		'--jq', '.[] | [(.pull_request.html_url // .html_url), .number, (if .pull_request then "PR" else "issue" end), .state, .title] | @tsv')!
	return out.split_into_lines().filter(it != '').map(it.split('\t'))
}

struct AdvisoryCredits {
	credits []Credit
}

fn (api GitHub) credits(id string) ![]Credit {
	return json2.decode[[]Credit](gh('api', 'repos/${api.repo}/security-advisories/${id}',
		'--jq', '.credits // []')!)
}

fn (api GitHub) update_credits(id string, credits []Credit) ! {
	send('PATCH', 'repos/${api.repo}/security-advisories/${id}',
		json2.encode(AdvisoryCredits{ credits: credits }))!
}

fn send(method string, path string, payload string) !string {
	f := os.join_path(os.temp_dir(), 'ghav-${os.getpid()}.json')
	os.write_file(f, payload)!
	defer {
		os.rm(f) or {}
	}
	return gh('api', '--method', method, path, '--input', f, '--jq', '.ghsa_id')
}

fn (api GitHub) set_state(id string, state string) ! {
	gh('api', '--method', 'PATCH', 'repos/${api.repo}/security-advisories/${id}', '-f', 'state=${state}')!
}

fn (api GitHub) create_advisory(a Adv) !string {
	return send('POST', 'repos/${api.repo}/security-advisories', json2.encode(a))!.trim_space()
}

fn (api GitHub) update_advisory(id string, a Adv) ! {
	send('PATCH', 'repos/${api.repo}/security-advisories/${id}', json2.encode(a))!
	// A successful request alone does not prove the edited fields were saved.
	text := api.advisory(id) or {
		return error('GitHub accepted the update, but reloading ${id} failed: ${err}')
	}
	saved := parse(text) or {
		return error('GitHub accepted the update, but the reloaded advisory is invalid: ${err}')
	}
	fields := advisory_changes(a, saved)
	if fields.len > 0 {
		return error('GitHub accepted the update, but the reloaded advisory differs in: ${fields.join(', ')}')
	}
}
