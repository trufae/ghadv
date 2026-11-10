module main

import os
import net.urllib
import crypto.sha256

// Keep the host with the project: identical paths can exist on different forges.
struct Repository {
	repo string
	provider string = 'github'
	host string = 'github.com'
}

fn (api Repository) url() string {
	return 'https://${api.host}/${api.repo}'
}

fn (api Repository) state_path(kind string, id string) string {
	configured := os.getenv('XDG_STATE_HOME')
	base := if configured != '' { configured } else { os.join_path(os.home_dir(), '.local', 'state') }
	// Preserve the existing GitHub filenames while isolating GitLab records.
	identity := '${api.host}\n${api.repo}\n${id}'.to_lower()
	receipt := sha256.hexhash(if api.provider == 'gitlab' { 'gitlab\n${identity}' } else { identity })
	return os.join_path(base, 'ghadv', kind, receipt)
}

fn repository_location(input string, provider string, host string) !Repository {
	if provider !in ['', 'github', 'gitlab'] { return error('provider must be github or gitlab') }
	mut name := input.trim_space()
	mut server := host.to_lower()
	mut forge := provider
	if name.contains('@') && name.contains(':') && !name.contains('://') {
		name = 'ssh://' + name.all_before(':') + '/' + name.all_after_first(':')
	}
	if name.contains('://') {
		u := urllib.parse(name)!
		auth := u.user or { urllib.Userinfo{} }
		if u.scheme !in ['https', 'ssh'] || u.raw_query != '' || u.fragment != ''
			|| auth.password_set || (u.scheme == 'https' && auth.username != '') {
			return error('expected an HTTPS or SSH repository URL without credentials, query or fragment')
		}
		url_host := if u.scheme == 'ssh' { u.hostname() } else { u.host }
		if server != '' && server != url_host.to_lower() { return error('repository URL does not match host ${server}') }
		server = url_host.to_lower()
		name = u.path.trim('/')
	}
	if server == '' { server = if forge == 'gitlab' { 'gitlab.com' } else { 'github.com' } }
	known := match server {
		'github.com' { 'github' }
		'gitlab.com' { 'gitlab' }
		else { '' }
	}
	if forge == '' {
		if known == '' { return error('unknown forge for ${server}; set --provider github or gitlab') }
		forge = known
	} else if known != '' && known != forge {
		return error('${server} does not match provider ${forge}')
	}
	if server == '' || !server.bytes().all(it.is_alnum() || it in [`-`, `.`, `:`]) {
		return error('invalid repository host')
	}
	name = name.trim_string_right('.git')
	parts := name.split('/')
	if parts.len < 2 || (forge == 'github' && parts.len != 2) { return error('expected a repository namespace/project') }
	for part in parts {
		if part in ['', '.', '..'] || !part.bytes().all(it.is_alnum() || it in [`-`, `_`, `.`]) {
			return error('invalid repository path')
		}
	}
	return Repository{repo: name, provider: forge, host: server}
}

// Choose a remote deterministically; never infer a forge from an auth failure.
fn repository_remote(preferred string) !string {
	mut remote := preferred
	if remote == '' {
		branch := os.exec(['git', 'symbolic-ref', '--quiet', '--short', 'HEAD'])
		if branch.exit_code == 0 {
			r := os.exec(['git', 'config', '--get', 'branch.${branch.output.trim_space()}.remote'])
			if r.exit_code == 0 && r.output.trim_space() != '.' { remote = r.output.trim_space() }
		}
	}
	if remote == '' {
		r := os.exec(['git', 'remote'])
		if r.exit_code != 0 { return error('cannot read Git remotes; use -r with a repository URL') }
		remotes := r.output.split_into_lines().filter(it != '')
		remote = if 'origin' in remotes { 'origin' } else if remotes.len == 1 { remotes[0] } else { '' }
	}
	if remote == '' || remote.starts_with('-') { return error('choose a Git remote with --remote, or use -r with a repository URL') }
	r := os.exec(['git', 'remote', 'get-url', remote])
	if r.exit_code != 0 { return error('cannot read Git remote ${remote}') }
	return r.output.trim_space()
}

fn resolve_repository(input string, provider string, host string, remote string) !Repository {
	if input.contains('://') || input.contains('@') { return repository_location(input, provider, host) }
	if input != '' && (provider != '' || host != '') { return repository_location(input, provider, host) }
	url := repository_remote(remote) or {
		if input != '' { return repository_location(input, provider, host) }
		return err
	}
	location := repository_location(url, provider, host)!
	return if input == '' { location } else { repository_location(input, location.provider, location.host)! }
}

fn configured_repository(input string) !Repository {
	repo := os.getenv('GHADV_REPO')
	mut provider := os.getenv('GHADV_PROVIDER')
	mut host := os.getenv('GHADV_HOST')
	if host == '' && !repo.contains('://') && !repo.contains('@') && !input.contains('://') {
		host = os.getenv(if provider == 'gitlab' { 'GITLAB_HOST' } else { 'GH_HOST' })
		if provider == '' && host != '' { provider = 'github' }
	}
	if input.contains('://') {
		s := source_url(input, provider, host)!
		if repo != '' {
			selected := repository_location(repo, s.provider, s.host)!
			if selected.repo.to_lower() != s.repo.to_lower() { return error('source URL does not match selected repository') }
		}
		return Repository{repo: s.repo, host: s.host, provider: s.provider}
	}
	return resolve_repository(repo, provider, host, os.getenv('GHADV_REMOTE'))
}
