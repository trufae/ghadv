module main

import os

fn test_repository_urls_and_provider_validation() ! {
	for url in ['https://gitlab.com/group/sub/project.git', 'git@gitlab.com:group/sub/project.git',
		'ssh://git@gitlab.com:2222/group/sub/project.git'] {
		api := repository_location(url, '', '')!
		assert api == Repository{repo: 'group/sub/project', provider: 'gitlab', host: 'gitlab.com'}
	}
	assert repository_location('owner/repo', '', '')!.provider == 'github'
	assert repository_location('git@code.example:group/sub/project.git', 'gitlab', '')!.host == 'code.example'
	assert repository_location('https://code.example:8443/group/repo', 'gitlab', '')!.host == 'code.example:8443'
	for url in ['https://unknown.example/owner/repo', 'https://gitlab.com/group/../repo',
		'https://user:secret@gitlab.com/group/repo', 'https://user@gitlab.com/group/repo',
		'https://github.com/group/sub/project', 'https://gitlab.com/group/repo?x=1',
		'https://gitlab.com/group/repo#fragment', 'file:///group/repo'] {
		if _ := repository_location(url, '', '') { assert false, url }
	}
	if _ := repository_location('https://gitlab.com/group/repo', 'github', '') { assert false }
	if _ := repository_location('https://gitlab.com/group/repo', '', 'other.example') { assert false }
}

fn test_gitlab_sources_support_subgroups_and_preserve_identity() ! {
	api := Repository{repo: 'group/sub/repo', provider: 'gitlab', host: 'code.example'}
	for kind in ['issues', 'merge_requests', 'commit'] {
		ref := if kind == 'commit' { 'abcd1234' } else { '42' }
		url := '${api.url()}/-/${kind}/${ref}'
		s := api.source('${url}/?x=1#note_2')!
		assert s.url == url
		assert s.repo == api.repo && s.host == api.host && s.provider == 'gitlab'
		assert s.kind == kind && s.ref == ref
	}
	assert api.source('abc1234')!.url == 'https://code.example/group/sub/repo/-/commit/abc1234'
	for url in ['https://code.example/other/repo/-/issues/42',
		'https://elsewhere.example/group/sub/repo/-/issues/42',
		'https://code.example/group/sub/repo/issues/42',
		'https://code.example/group/sub/repo/-/issues/0',
		'https://code.example/group/sub/repo/-/merge_requests/nope'] {
		if _ := api.source(url) { assert false, url }
	}
}

fn test_repository_detection_selects_remote_without_network_requests() ! {
	dir := os.join_path(os.temp_dir(), 'ghadv-remotes-${os.getpid()}')
	os.mkdir_all(dir)!
	old := os.getwd()
	os.chdir(dir)!
	defer { os.chdir(old) or {}; os.rmdir_all(dir) or {} }
	assert os.exec(['git', 'init', '-q']).exit_code == 0
	assert os.exec(['git', 'remote', 'add', 'origin', 'git@gitlab.com:group/sub/repo.git']).exit_code == 0
	assert resolve_repository('', '', '', '')!.provider == 'gitlab'
	assert resolve_repository('another/project', '', '', '')!.host == 'gitlab.com'
	assert os.exec(['git', 'remote', 'add', 'upstream', 'https://github.com/owner/repo.git']).exit_code == 0
	assert resolve_repository('', '', '', 'upstream')!.provider == 'github'
	assert resolve_repository('https://gitlab.com/explicit/repo', '', '', '')!.repo == 'explicit/repo'
	assert os.exec(['git', 'remote', 'rename', 'origin', 'fork']).exit_code == 0
	if _ := resolve_repository('', '', '', '') { assert false, 'ambiguous remotes selected silently' }
}
