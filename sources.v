module main

import os
import net.urllib

struct Source {
	repo string
	kind string // commit, issues, pull or merge_requests
	ref  string
	url  string
	provider string = 'github'
	host string = 'github.com'
}

// Compatibility helper for callers that only supply a GitHub repository path.
fn source(repo string, input string) !Source {
	if repo == '' && input.contains('://') {
		return source_url(input, 'github', 'github.com')
	}
	return Repository{repo: repo}.source(input)
}

fn source_url(input string, provider string, host string) !Source {
	u := urllib.parse(input)!
	if u.scheme != 'https' { return error('expected an HTTPS source URL') }
	parts := u.path.trim('/').split('/')
	if parts.len < 4 { return error('expected a commit, issue or pull/merge request URL') }
	kind, ref := parts[parts.len - 2], parts.last()
	is_gitlab := parts.len >= 5 && parts[parts.len - 3] == '-'
	if (is_gitlab && kind !in ['commit', 'issues', 'merge_requests'])
		|| (!is_gitlab && kind !in ['commit', 'issues', 'pull']) {
		return error('unsupported source URL')
	}
	end := parts.len - if is_gitlab { 3 } else { 2 }
	// Keep credentials in this validation URL so repository_location rejects them.
	base := input.all_before('?').all_before('#').trim_right('/')
	path := base[..base.len - (parts[end..].join('/').len + 1)]
	location := repository_location(path, provider, host)!
	if is_gitlab != (location.provider == 'gitlab') { return error('source URL does not match provider') }
	if ref == '' || (kind == 'commit' && !ref.bytes().all(it.is_hex_digit()))
		|| (kind != 'commit' && (!ref.bytes().all(it.is_digit()) || ref.u64() == 0)) {
		return error('invalid commit or issue/MR number in URL')
	}
	return Source{repo: location.repo, kind: kind, ref: ref,
		url: location.url() + if is_gitlab { '/-/' } else { '/' } + '${kind}/${ref}',
		provider: location.provider, host: location.host}
}

fn (api Repository) source(input string) !Source {
	if input.contains('://') {
		s := source_url(input, api.provider, api.host)!
		if api.repo != '' && s.repo.to_lower() != api.repo.to_lower() {
			return error('URL repository ${s.repo} does not match ${api.repo}')
		}
		return s
	}
	if input == '' || input.contains_any('?#') { return error('expected a commit or issue/MR URL') }
	return Source{repo: api.repo, kind: 'commit', ref: input,
		url: api.url() + if api.provider == 'gitlab' { '/-/commit/' } else { '/commit/' } + input,
		provider: api.provider, host: api.host}
}

// tagged fix commits in the cwd checkout: sha, date, subject
fn commits() ![][]string {
	grep := setting('GREP') or { '##(crash|security|vulnerability|sandbox)' }
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

// Rough display-only ratings from tagged fix subjects, strongest match first.
fn commit_severity(subject string) string {
	message := subject.to_lower().replace('##crash', '').replace('##security', '')
		.replace('##vulnerability', '').replace('##sandbox', '')
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
