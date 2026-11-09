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
	grep := os.getenv_opt('GHAV_GREP') or { '##(crash|security)' }
	r := os.exec(['git', 'log', '-E', '--grep=${grep}', '-n', '2000', '--format=%H%x09%as%x09%s'])
	if r.exit_code != 0 {
		return error(r.output.trim_space())
	}
	return r.output.split_into_lines().filter(it != '').map(it.split('\t'))
}
