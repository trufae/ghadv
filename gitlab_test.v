module main

import json2
import os
import crypto.sha256

fn test_gitlab_disclosure_roundtrip_and_unstructured_reports() ! {
	a := parse('summary: Bounds check\nseverity: high\ncvss: \ncwe: CWE-125\ncredits: alice:finder\npackage: parser\necosystem: other\naffected: < 2\npatched: 2\n---\nDetails with a code block:\n```c\nfoo();\n```\n\nCVE-2026-12345\n')!
	issue := GitLabIssue{iid: 42, title: a.summary, description: gitlab_description(a)}
	assert advisory_changes(a, gitlab_issue_advisory(issue)!) == []string{}
	assert gitlab_cves(issue) == 'CVE-2026-12345'
	assert gitlab_cves(GitLabIssue{description: 'CVE-2026-12345 CVE-2026-12345 CVE-2025-123456'}) == 'CVE-2026-12345,CVE-2025-123456'
	assert gitlab_cves(GitLabIssue{}) == '-'
	raw := GitLabIssue{title: 'Existing issue', description: 'Original report\n\n# Details\nText'}
	assert gitlab_issue_advisory(raw)!.description == raw.description
	assert gitlab_issue_advisory(raw)!.summary == raw.title
	if _ := gitlab_issue_advisory(GitLabIssue{description: gitlab_advisory_marker + 'broken'}) { assert false }
	assert gitlab_iid('GL-123')! == '123'
	for id in ['GL-0', 'GL-../1', 'GHSA-foo', 'GL-nope'] {
		if _ := gitlab_iid(id) { assert false, id }
	}
}

fn test_gitlab_payload_confidentiality_and_supported_actions() ! {
	payload := json2.encode(GitLabCreate{title: 'Test', description: 'Report', labels: 'security-advisory'})
	assert payload.contains('"confidential":true')
	edit := json2.encode(GitLabEdit{'Title', 'Body'})
	assert !edit.contains('confidential') && !edit.contains('labels') && !edit.contains('state')
	api := Repository{repo: 'group/repo', provider: 'gitlab', host: 'gitlab.com'}
	assert api.states() == ['all', 'opened', 'closed']
	assert api.actions(['GL-1', 'opened', '-', '', 'Title']) == ['c CVE request instructions', 'x close issue']
	assert api.actions(['GL-1', 'closed', '-', '', 'Title']) == ['c CVE request instructions', 'd reopen issue']
	assert api.reply_instructions().contains('Use glab')
	assert !api.reply_instructions().contains('GitHub')
	assert !api.help_text().contains('p: publish')
	assert api.help_text().contains('States: opened, closed')
	assert api.help_text().contains('Confidentiality is shown separately')
	for state in ['draft', 'published'] {
		if _ := api.set_state('GL-1', state) { assert false, 'unsupported transition reached API' }
	}
	assert api.gitlab_project() == 'projects/group%2Frepo'
	assert Repository{repo: 'group/sub/repo', provider: 'gitlab'}.gitlab_project() == 'projects/group%2Fsub%2Frepo'
}

fn test_provider_identity_in_saved_sessions_and_local_tags() ! {
	api := Repository{repo: 'group/sub/repo', provider: 'gitlab', host: 'code.example'}
	dir := start_edit(api, 'GL-7', 'review', 'original', 'prompt')!
	defer { os.rmdir_all(dir) or {} }
	session := json2.decode[EditSession](os.read_file(os.join_path(dir, 'session.json'))!)!
	assert session.provider == 'gitlab' && session.host == 'code.example'
	assert session.repo == api.repo && session.id == 'GL-7'
	old := json2.decode[EditSession]('{"repo":"owner/repo","id":"GHSA-test","kind":"edit"}')!
	assert old.provider == 'github'
	assert api.invalid_target('GL-7')! == api.invalid_target('https://code.example/group/sub/repo/-/issues/7')!
	assert api.state_path('invalid', '') != Repository{repo: api.repo, host: api.host}.state_path('invalid', '')
	github := Repository{repo: 'owner/repo'}
	assert os.file_name(github.state_path('cve-requests', 'GHSA-test')) == sha256.hexhash('github.com\nowner/repo\nghsa-test')
}
