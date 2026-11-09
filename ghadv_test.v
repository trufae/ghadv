module main

fn test_advisory_changes_compare_saved_fields() ! {
	a := parse('summary: Test\nseverity: high\ncvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\ncwe: CWE-787, CWE-125\ncredits: Alice:finder, Bob:reporter\npackage: one\necosystem: other\naffected: < 2\npatched: 2\nfunctions: foo, bar\npackage: two\n---\nDetails\n')!
	mut b := a
	b.cwe_ids = a.cwe_ids.reverse()
	b.credits = [Credit{'bob', 'reporter'}, Credit{'alice', 'finder'}]
	b.vulnerabilities = a.vulnerabilities.reverse()
	b.vulnerabilities[1].vulnerable_functions = ['bar', 'foo']
	assert advisory_changes(a, b) == []string{}
	b.summary = 'Different'
	b.description = 'Changed body'
	b.cvss_vector_string = ''
	b.severity = 'low'
	b.cwe_ids = []string{}
	b.credits = []Credit{}
	b.vulnerabilities = []Vuln{}
	assert advisory_changes(a, b) == ['summary', 'description', 'severity', 'cvss', 'cwe', 'credits',
		'vulnerabilities']
}

fn test_functions_discarded_by_github() ! {
	sent := parse('summary: Test\npackage: one\necosystem: other\nfunctions: foo\n---\nDetails\n')!
	saved := without_functions(sent)
	assert functions_discarded(sent, saved)
	assert !functions_discarded(saved, saved)
	mut other := saved
	other.summary = 'Different'
	assert !functions_discarded(sent, other)
}

fn test_advisory_sources() ! {
	commit := source('owner/repo', 'abc1234')!
	assert commit.kind == 'commit'
	assert commit.url == 'https://github.com/owner/repo/commit/abc1234'
	assert source('', commit.url)!.ref == 'abc1234'
	issue := source('', 'https://github.com/owner/repo/issues/123/?q=test#issuecomment-1')!
	assert issue.repo == 'owner/repo'
	assert issue.kind == 'issues'
	assert issue.ref == '123'
	assert issue.url == 'https://github.com/owner/repo/issues/123'
	pr := source('OWNER/REPO', 'https://github.com/owner/repo/pull/456')!
	assert pr.kind == 'pull'
	assert pr.ref == '456'
}

fn test_reject_invalid_sources() {
	for input in ['', 'https://example.com/owner/repo/issues/1', 'http://github.com/owner/repo/issues/1',
		'https://github.com/owner/repo', 'https://github.com/owner/repo/issues/0',
		'https://github.com/owner/repo/issues/-1', 'https://github.com/owner/repo/pull/nope',
		'https://github.com/owner/repo/commit/not-a-sha', 'https://github.com/owner/../issues/1',
		'https://github.com/me/another/issues/1', 'https://user@github.com/owner/repo/issues/1'] {
		if s := source('owner/repo', input) {
			assert false, 'unexpected source: ${s}'
		}
	}
}

fn test_source_advisory_links() {
	advs := [
		['GHSA-one', 'draft', '-', 'high', 'First', 'abcdef1234',
			'https://github.com/owner/repo/issues/123,https://github.com/owner/repo/pull/456'],
		['GHSA-two', 'published', '-', 'low', 'Second', '', 'https://github.com/owner/repo/issues/12'],
	]
	assert adv_of(advs, 'abcdef1234567890') == 0
	assert adv_of(advs, 'https://github.com/owner/repo/issues/123') == 0
	assert adv_of(advs, 'https://github.com/OWNER/REPO/pull/456') == 0
	assert adv_of(advs, 'https://github.com/owner/repo/issues/12') == 1
	assert adv_of(advs, 'https://github.com/owner/repo/issues/1') == -1
	assert adv_of(advs, 'https://github.com/owner/repo/issues/1234') == -1
	assert adv_of(advs, 'https://github.com/other/repo/issues/123') == -1
	assert adv_of([['error:', 'unavailable']], 'https://github.com/owner/repo/issues/123') == -1
	assert adv_of(advs, '') == -1
}
