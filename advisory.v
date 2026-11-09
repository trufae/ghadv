module main

const states = ['all', 'triage', 'draft', 'published', 'closed']

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

struct CreditRole {
	typ         string
	description string
}

// GitHub repository advisory credit types. Keep their API spellings in one place.
const credit_roles = [
	CreditRole{'finder', 'Discovered the vulnerability'},
	CreditRole{'reporter', 'Reported the vulnerability'},
	CreditRole{'analyst', 'Analyzed or documented the vulnerability'},
	CreditRole{'coordinator', 'Coordinated disclosure and response'},
	CreditRole{'remediation_developer', 'Developed the fix'},
	CreditRole{'remediation_reviewer', 'Reviewed the fix'},
	CreditRole{'remediation_verifier', 'Verified that the fix works'},
	CreditRole{'tool', 'Tool used to discover or investigate the bug'},
	CreditRole{'sponsor', 'Supported or funded the work'},
	CreditRole{'other', 'Another contribution'},
]

fn credit_description(typ string) string {
	for role in credit_roles {
		if role.typ == typ { return role.description }
	}
	return 'Unknown role: ${typ}'
}

// A person can hold several roles, but each login/role pair must be unique.
fn change_credit(credits []Credit, index int, input Credit) ![]Credit {
	login := input.login.trim_space().trim_string_left('@')
	name := login.trim_string_right('[bot]')
	if name == '' || !name.bytes().all(it.is_alnum() || it == `-`) {
		return error('enter a GitHub username, optionally starting with @')
	}
	if !credit_roles.any(it.typ == input.typ) {
		return error('choose a credit role from the list')
	}
	if index < -1 || index >= credits.len {
		return error('no credit selected')
	}
	for i, item in credits {
		if i != index && item.login.to_lower() == login.to_lower() && item.typ == input.typ {
			return error('@${login} already has the ${input.typ} credit')
		}
	}
	mut result := credits.clone()
	value := Credit{login, input.typ}
	if index == -1 { result << value } else { result[index] = value }
	return result
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

fn csv(s string) []string {
	return s.split(',').map(it.trim_space()).filter(it != '')
}

// Compare editable values, ignoring the order of sets and GitHub username casing.
fn advisory_changes(a Adv, b Adv) []string {
	mut fields := []string{}
	if a.summary != b.summary { fields << 'summary' }
	if a.description != b.description { fields << 'description' }
	if a.severity != b.severity { fields << 'severity' }
	if a.cvss_vector_string != b.cvss_vector_string { fields << 'cvss' }
	if a.cwe_ids.sorted() != b.cwe_ids.sorted() { fields << 'cwe' }
	if a.credits.map(it.login.to_lower() + ':' + it.typ).sorted()
		!= b.credits.map(it.login.to_lower() + ':' + it.typ).sorted() {
		fields << 'credits'
	}
	mut av := a.vulnerabilities.clone()
	mut bv := b.vulnerabilities.clone()
	for mut v in av { v.vulnerable_functions = v.vulnerable_functions.sorted() }
	for mut v in bv { v.vulnerable_functions = v.vulnerable_functions.sorted() }
	if av.map(it.str()).sorted() != bv.map(it.str()).sorted() { fields << 'vulnerabilities' }
	return fields
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

// URL references link issues/PRs; hex prefixes link commits.
fn adv_of(advs [][]string, input string) int {
	if input == '' {
		return -1
	}
	for i, a in advs {
		if input.starts_with('https://') {
			if a.len > 6 && a[6].split(',').any(it.to_lower() == input.to_lower()) {
				return i
			}
		} else if a.len > 5 && a[5].split(',').any(it != '' && input.starts_with(it)) {
			return i
		}
	}
	return -1
}
