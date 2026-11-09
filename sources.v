module main

import os
import net.urllib

struct Source {
	repo string
	kind string // commit, issues or pull
	ref  string
	url  string
}

// URLs select their repository unless an explicit repository was supplied.
fn source(repo string, input string) !Source {
	if !input.contains('://') {
		if input == '' || input.contains_any('?#') {
			return error('expected a commit or a GitHub issue/PR URL')
		}
		return Source{repo, 'commit', input, 'https://github.com/${repo}/commit/${input}'}
	}
	u := urllib.parse(input)!
	parts := u.path.trim('/').split('/')
	auth := u.user or { urllib.Userinfo{} }
	if u.scheme != 'https' || u.host.to_lower() != 'github.com' || auth.username != '' || auth.password_set
		|| parts.len != 4 || parts[2] !in ['issues', 'pull', 'commit'] {
		return error('expected https://github.com/owner/repo/issues/number, /pull/number or /commit/sha')
	}
	for part in parts[..2] {
		if part in ['', '.', '..'] || !part.bytes().all(it.is_alnum() || it in [`-`, `_`, `.`]) {
			return error('invalid repository in URL')
		}
	}
	ref := parts[3]
	if (parts[2] == 'commit' && (ref == '' || !ref.bytes().all(it.is_hex_digit())))
		|| (parts[2] != 'commit' && (ref == '' || !ref.bytes().all(it.is_digit()) || ref.u64() == 0)) {
		return error('invalid commit or issue/PR number in URL')
	}
	url_repo := '${parts[0]}/${parts[1]}'
	if repo != '' && repo.to_lower() != url_repo.to_lower() {
		return error('URL repository ${url_repo} does not match ${repo}')
	}
	return Source{url_repo, parts[2], ref, 'https://github.com/${url_repo}/${parts[2]}/${ref}'}
}

// tagged fix commits in the cwd checkout: sha, date, subject
fn commits() ![][]string {
	grep := os.getenv_opt('GHADV_GREP') or { '##(crash|security)' }
	r := os.exec(['git', 'log', '-E', '--grep=${grep}', '-n', '2000', '--format=%H%x09%as%x09%s'])
	if r.exit_code != 0 {
		return error(r.output.trim_space())
	}
	return r.output.split_into_lines().filter(it != '').map(it.split('\t'))
}

// Porcelain -z keeps filenames opaque, including newlines and rename sources.
fn git_changes(porcelain string) string {
	mut staged, unstaged, untracked, conflicted := false, false, false, false
	mut rename_source := false
	for entry in porcelain.split('\x00') {
		if rename_source {
			rename_source = false
			continue
		}
		if entry.len < 3 { continue }
		xy := entry[..2]
		if xy == '??' {
			untracked = true
		} else if xy in ['DD', 'AU', 'UD', 'UA', 'DU', 'AA', 'UU'] {
			conflicted = true
		} else if xy != '!!' {
			staged = staged || entry[0] != ` `
			unstaged = unstaged || entry[1] != ` `
			rename_source = entry[0] in [`R`, `C`] || entry[1] in [`R`, `C`]
		}
	}
	mut changes := []string{}
	if conflicted { changes << 'conflicts' }
	if unstaged { changes << 'unstaged' }
	if staged { changes << 'staged' }
	if untracked { changes << 'untracked' }
	return if changes.len == 0 { 'clean' } else { changes.join(', ') }
}

// This describes the cwd checkout, which may differ from an explicit -r repo.
fn local_git_status() string {
	status := os.exec(['git', '--no-optional-locks', 'status', '--porcelain=v1', '-z',
		'--untracked-files=normal', '--ignore-submodules=none'])
	if status.exit_code != 0 { return 'unavailable' }
	changes := git_changes(status.output)
	latest := os.exec(['git', 'log', '-1', '--format=%h%x09%s', '--no-show-signature'])
	if latest.exit_code != 0 { return 'HEAD unavailable | ${changes}' }
	parts := latest.output.trim_space().split('\t')
	return '${parts[0]} | ${changes}' + if parts.len > 1 { ' | ' + parts[1..].join(' ') } else { '' }
}

// Rough display-only ratings from radare2 ##crash subjects, strongest match first.
fn commit_severity(subject string) string {
	message := subject.to_lower().replace('##crash', '').replace('##security', '')
	text := ' ' + message.bytes().map(if it.is_alnum() { it } else { u8(` `) }).bytestr()
		.fields().join(' ') + ' '
	for severity in ['critical', 'high', 'medium', 'low'] {
		keywords := match severity {
			'critical' {
				['rce', 'remote code execution', 'arbitrary code execution', 'command injection',
					'cmdinj', 'shell injection', 'script injection', 'sandbox escape', 'sandbox bypass']
			}
			'high' {
				['uaf', 'use after free', 'double free', 'type confusion', 'type confussion',
					'format string', 'heap overflow', 'stack overflow', 'buffer overflow',
					'oobwrite', 'oob write', 'out of bounds write', 'memory corruption', 'arbitrary write']
			}
			'medium' {
				['oobread', 'oob read', 'out of bounds read', 'overread', 'over read', 'underread',
					'under read', 'invalid read', 'invalid memory read', 'integer overflow', 'int overflow',
					'intovf', 'wraparound', 'memory disclosure', 'uninitialized memory', 'memory exhaustion',
					'excessive memory', 'exhaust memory', 'stack exhaustion', 'exhaust the stack',
					'infinite loop', 'infinite recursion', 'unbounded recursion', 'unbound recursion',
					'nesting depth', 'hang', 'hanging', 'division by zero', 'divisions by zero', 'divby0',
					'zipbomb', 'xzbomb', 'decompression bomb', 'denial of service', 'dos']
			}
			else { ['null', 'nullptr', 'segfault', 'crash', 'leak', 'assertion'] }
		}
		if keywords.any(text.contains(' ${it} ') || text.contains(' ${it}s ')) {
			return severity
		}
	}
	return ''
}
