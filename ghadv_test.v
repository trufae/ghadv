module main

import term
import encoding.utf8.east_asian

fn test_commit_severity_from_crash_subjects() {
	cases := {
		'Fix null deref crash when parsing unnamed pdb globals ##crash': 'low'
		'Fix NULL deref in ~?ea on empty output ##crash': 'low'
		'Fix PEF overlapping import name leaks ##crash': 'low'
		'Fix UAF of cached BP/SP alias names in fcn_scan after asm.bits switches ##crash': 'high'
		'Fix use-after-free of current_code_attr in the Java StackMapTable parser ##crash': 'high'
		'Fix leak and double free in dietline clipboard ##crash': 'high'
		'Fix type confusion and null derefs in the pyc disassembler ##crash': 'high'
		'Fix type confussion in tlj/tllj commands ##crash': 'high'
		'Fix z80 assembler oobread oobwrite bugs ##crash': 'high'
		'Fix stack buffer overflow in the z80 assembler db and ds directives ##crash': 'high'
		'Fix heap overflows in asm.sub.tail and asm.sub.reg substitutions ##crash': 'high'
		'Fix heap oobread in radiff2 -i z in lua strings with embedded nulls ##crash': 'medium'
		'Fix stack out-of-bounds read in the HFS catalog key compare ##crash': 'medium'
		'Fix heap OOBreads and infinite loops in SFS ##crash': 'medium'
		'Fix buffer under-reads on empty macro, search and att2intel input ##crash': 'medium'
		'Fix integer overflows in io_dsc slide info table sizes ##crash': 'medium'
		'Fix stack exhaustion on cyclic PDB type references ##crash': 'medium'
		'Fix divby0 in JFS ##crash': 'medium'
		'Fix command injection in iddlg via global symbol names ##crash': 'critical'
		'Fix UAF and cmdinj in fs.r2, add RCoreBind.cfgSet ##crash': 'critical'
		'Prevent wwwdir sandbox escape, harden on windows ##crash': 'critical'
		'Fix shell injection in curl headers ##crash': 'critical'
		'Validate PDB stream pages before reading ##crash': ''
		'Update nullable metadata ##security': ''
		'##crash ##security': ''
		'': ''
	}
	for subject, expected in cases {
		assert commit_severity(subject) == expected, subject
	}
}

fn test_severity_circles_in_lists() {
	c := ['abcdef1234567890', '2026-11-09', 'Fix UAF ##crash']
	mut a := ['GHSA-test', 'draft', '-', 'low', 'Test advisory', 'abcdef1234']
	assert crow(c, [][]string{}, 80).starts_with('🟠 abcdef1234 ')
	assert crow(c, [a], 80).starts_with('🟢 abcdef1234 ')
	for severity, icon in {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'moderate': '🟡',
		'low': '🟢', '-': '⚪', '': '⚪'} {
		a[3] = severity
		assert row(a, 80).starts_with('${icon} GHSA-test ')
	}
	a[3] = '-'
	assert crow(c, [a], 80).starts_with('🟠 abcdef1234 ')
	assert crow(['abcdef1234567890', '2026-11-09', 'Validate PDB streams ##crash'],
		[][]string{}, 80).starts_with('⚪ ')
	assert row(['error:', 'unavailable'], 80) == 'error: unavailable'
	assert crow(['error:', 'unavailable'], [][]string{}, 80) == 'error: unavailable'
	// Reserve two terminal columns for each circle and one for its following space.
	long := 'A'.repeat(100)
	assert east_asian.display_width(term.strip_ansi(crow([c[0], c[1], long], [a], 80)), 1) == 79
	a[4] = long
	assert east_asian.display_width(term.strip_ansi(row(a, 80)), 1) == 79
}

fn test_advisory_changes_compare_saved_fields() ! {
	a := parse('summary: Test\nseverity: high\ncvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\ncwe: CWE-787, CWE-125\ncredits: Alice:finder, Bob:reporter\npackage: one\necosystem: other\naffected: < 2\npatched: 2\nfunctions:\npackage: two\n---\nDetails\n')!
	mut b := a
	b.cwe_ids = a.cwe_ids.reverse()
	b.credits = [Credit{'bob', 'reporter'}, Credit{'alice', 'finder'}]
	b.vulnerabilities = a.vulnerabilities.reverse()
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

fn test_functions_are_rejected() {
	if _ := parse('summary: Test\npackage: one\nfunctions: foo\n---\nDetails\n') {
		assert false
	}
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
