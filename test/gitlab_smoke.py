#!/usr/bin/env python3
"""Offline integration checks: python3 test/gitlab_smoke.py /path/to/gsadv."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit


def stub():
    args = sys.argv[1:]
    client = Path(sys.argv[0]).name
    root = Path(os.environ['FORGE_FIXTURE'])
    if client == 'r2':
        return
    if client == 'agent':
        (root / 'prompt').write_text(sys.stdin.read())
        print('summary: Reviewed report\nseverity: high\ncwe: CWE-125\ncredits: alice:finder\n'
              'package: parser\necosystem: other\naffected: < 2\npatched: 2\n---\n'
              'Verified bounds check. CVE-2026-12345\n'
              'https://gitlab.com/group/sub/repo/-/merge_requests/42')
        sys.exit(1 if os.environ.get('FAIL_AI') else 0)
    assert args[0] == 'api', args
    host = args[args.index('--hostname') + 1]
    method = args[args.index('--method') + 1] if '--method' in args else 'GET'
    path = next(a for a in args if a.startswith(('projects/', 'repos/')))
    payload = json.loads(Path(args[args.index('--input') + 1]).read_text()) if '--input' in args else {}
    with (root / 'calls').open('a') as f:
        f.write(json.dumps(dict(client=client, host=host, method=method, path=path, payload=payload, args=args)) + '\n')
    if os.environ.get('FAIL_API'):
        sys.exit('403 Forbidden: fixture denied access')
    if client == 'gh':
        assert host in ['github.com', 'code.example']
        assert path.startswith('repos/owner/repo/security-advisories')
        if '?' in path:
            print('GHSA-abcd-efgh-ijkl\tdraft\t-\thigh\tGitHub report\t\t')
        elif method == 'POST':
            print('{}')
        elif '.cve_id' in args[-1]:
            print('')
        else:
            print('advisory: GHSA-abcd-efgh-ijkl\nstate: draft\ncve: unassigned\nurl: https://github.com/owner/repo')
        return
    assert client == 'glab'
    assert path.startswith('projects/group%2Fsub%2Frepo/'), path
    state_path = root / 'issues.json'
    issues = json.loads(state_path.read_text())
    endpoint = urlsplit(path).path.split('/', 2)[2]
    query = parse_qs(urlsplit(path).query)
    if method == 'POST':
        assert endpoint == 'issues' and payload['confidential'] is True
        iid = str(max(map(int, issues)) + 1)
        issues[iid] = dict(iid=int(iid), title=payload['title'], description=payload['description'],
                           confidential=True, state='opened', labels=payload['labels'].split(','),
                           web_url=f'https://{host}/group/sub/repo/-/issues/{iid}')
        result = issues[iid]
    elif method == 'PUT':
        assert endpoint.startswith('issues/')
        result = issues[endpoint.split('/')[1]]
        if 'state_event' in payload:
            assert set(payload) == {'state_event'}
            result['state'] = 'closed' if payload['state_event'] == 'close' else 'opened'
        else:
            assert set(payload) == {'title', 'description'}
            result.update(payload)
    elif endpoint == 'issues':
        result = [i for i in issues.values() if query['labels'][0] in i['labels']
                  and (query['state'][0] == 'all' or query['state'][0] == i['state'])]
    elif endpoint == 'merge_requests' or endpoint == 'merge_requests/42':
        mr = dict(iid=42, title='Fix parser', description='Merge request report', state='merged',
                  web_url=f'https://{host}/group/sub/repo/-/merge_requests/42',
                  author={'username': 'alice'}, merge_commit_sha='a'*40,
                  source_branch='fix', target_branch='main')
        result = [mr] if endpoint == 'merge_requests' else mr
    elif endpoint.endswith('/notes'):
        result = [dict(id=1, body='Reproduction evidence', author={'username': 'alice'}),
                  dict(id=2, body='Follow-up evidence', author={'username': 'bob'})]
    elif endpoint.endswith(('/diffs', '/diff')):
        result = [dict(old_path='parser.c', new_path='parser.c', diff='@@ -1 +1 @@\n-old\n+fixed'),
                  dict(old_path='large.c', new_path='large.c', diff='', too_large=True)]
    elif endpoint.startswith('repository/commits/'):
        result = dict(id='a'*40, message='Fix parser', author_name='Alice', web_url='https://gitlab.com/commit')
    elif endpoint.startswith('issues/'):
        result = issues[endpoint.split('/')[1]]
    else:
        raise AssertionError((method, endpoint))
    if method != 'GET':
        state_path.write_text(json.dumps(issues))
    if isinstance(result, list):
        assert '--paginate' in args and args[args.index('--output') + 1] == 'ndjson'
        for item in result:
            print(json.dumps(item))
    else:
        print(json.dumps(result))


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='gsadv-gitlab-smoke-') as directory:
        root = Path(directory)
        version = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
        for option in ['--version', '-v', 'version']:
            # No Git checkout or provider CLI; invalid settings must not be consulted.
            result = subprocess.run([binary, option], cwd=root,
                                    env=dict(os.environ, PATH=str(root), GSADV_PROVIDER='invalid'),
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == 0 and result.stdout == f'gsadv {version}\n', result
            assert result.stderr == '', result.stderr
        bindir = root / 'bin'
        bindir.mkdir()
        for name in ['glab', 'gh', 'agent', 'r2']:
            script = bindir / name
            script.write_text(f'#!{sys.executable}\n' + Path(__file__).read_text().split('\n', 1)[1])
            script.chmod(0o755)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('GSADV_', 'GHADV_')) and k not in ['GH_HOST', 'GITLAB_HOST']}
        env.update(PATH=str(bindir) + os.pathsep + env['PATH'], FORGE_FIXTURE=str(root),
                   XDG_STATE_HOME=str(root / 'state'), TMPDIR=str(root), EDITOR='true',
                   GSADV_AI=shlex.quote(str(bindir / 'agent')))
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', 'git@gitlab.com:group/sub/repo.git'], check=True)
        (root / 'issues.json').write_text(json.dumps({'42': dict(iid=42, title='Original report',
            description='Original details. CVE-2026-12345', confidential=True, state='opened',
            labels=['security-advisory', 'cve'], web_url='https://gitlab.com/group/sub/repo/-/issues/42')}))

        def run(*args, expected=0, stdin='', overrides=None):
            p = subprocess.run([binary, *args], cwd=root, env=dict(env, **(overrides or {})),
                               input=stdin, text=True, capture_output=True, timeout=30)
            assert (p.returncode == 0) == (expected == 0), (args, p.stdout, p.stderr)
            return p.stdout + p.stderr

        def calls():
            return [json.loads(line) for line in (root / 'calls').read_text().splitlines()]

        listing = run('ls')
        assert 'GL-42' in listing and '[confidential]' in listing and 'CVE-2026-12345' in listing
        assert 'Usage: gsadv ' in run('--help')
        legacy = {'GHADV_PROVIDER': 'github', 'GHADV_REPO': 'https://github.com/owner/repo'}
        assert 'GitHub report' in run('ls', overrides=legacy)
        current = dict(legacy, GSADV_PROVIDER='gitlab', GSADV_REPO='https://gitlab.com/group/sub/repo')
        assert 'GL-42' in run('ls', overrides=current)
        assert 'GL-42' in run('ls', overrides=dict(legacy, GSADV_PROVIDER='', GSADV_REPO=''))
        assert 'GL-42' in run('--provider', 'gitlab', '-r', 'https://gitlab.com/group/sub/repo', 'ls', overrides=legacy)
        assert 'MR' in run('issues') and 'merged' in run('issues')
        assert 'visibility: confidential' in run('status', 'GL-42')
        count = len(calls())
        run('invalid', 'GL-42', 'No released version affected')
        assert 'No released version' in run('invalid', 'https://gitlab.com/group/sub/repo/-/issues/42')
        assert len(calls()) == count
        assert '[invalid]' in run('ls')
        run('unmark', 'https://gitlab.com/group/sub/repo/-/issues/42')
        assert '[invalid]' not in run('ls')
        count = len(calls())
        run('publish', 'GL-42', expected=1)
        run('draft', 'GL-42', expected=1)
        run('ls', 'draft', expected=1)
        run('close', 'GL-42', stdin='n\n')
        assert len(calls()) == count
        assert 'No CVE request was submitted' in run('cve', 'GL-42')
        assert calls()[-1]['method'] == 'GET'
        run('close', 'GL-42', stdin='y\n')
        assert 'closed' in run('ls', 'closed')
        run('reopen', 'GL-42', stdin='y\n')
        assert json.loads((root / 'issues.json').read_text())['42']['confidential'] is True
        output = run('new', 'https://gitlab.com/group/sub/repo/-/merge_requests/42')
        assert 'GL-43' in output
        prompt = (root / 'prompt').read_text()
        assert 'Use glab' in prompt and 'Merged: true' in prompt
        assert 'Follow-up evidence' in prompt and '+fixed' in prompt and 'GitLab omitted' in prompt
        assert 'Reviewed report' in run('show', 'GL-43')
        run('review', 'GL-42')
        assert 'Reviewed report' in run('show', 'GL-42')
        assert json.loads((root / 'issues.json').read_text())['42']['labels'] == ['security-advisory', 'cve']
        output = run('new', 'a'*40, expected=1, overrides={'FAIL_AI': '1'})
        recovery = re.search(r'Recovery files: (.+)', output).group(1)
        assert json.loads((Path(recovery) / 'session.json').read_text())['provider'] == 'gitlab'
        try:
            run('resume', recovery, overrides={'GSADV_PROVIDER': 'github', 'GSADV_REPO': 'wrong/repo', 'FAIL_AI': '1'})
        finally:
            # V uses /tmp on macOS even when TMPDIR is set. Remove only this run's session.
            if Path(recovery).exists():
                shutil.rmtree(recovery)
        assert calls()[-1]['client'] == 'glab' and calls()[-1]['host'] == 'gitlab.com'
        assert '403' in run('ls', expected=1, overrides={'FAIL_API': '1'})
        assert 'not this host' in run('--provider', 'gitlab', '-r', 'https://code.example/group/sub/repo', 'cve', 'GL-42')
        assert calls()[-1]['host'] == 'code.example'
        assert 'GitHub report' in run('-r', 'https://github.com/owner/repo', 'ls')
        run('-r', 'https://github.com/owner/repo', 'cve', 'GHSA-abcd-efgh-ijkl')
        assert 'requested*' in run('-r', 'https://github.com/owner/repo', 'ls')
        run('ls', overrides={'GSADV_REPO': 'owner/repo', 'GH_HOST': 'code.example'})
        assert calls()[-1]['client'] == 'gh' and calls()[-1]['host'] == 'code.example'
        assert 'https://code[.]example/' in calls()[-1]['args'][-1]
        if os.name == 'posix':
            tui_smoke(binary, root, env)
        print('Passed offline GitLab/GitHub CLI, source, mutation, recovery and local-tag checks.')


def tui_smoke(binary, root, env):
    import fcntl
    import pty
    import select
    import struct
    import termios

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 140, 0, 0))
    process = subprocess.Popen([binary], cwd=root, env=dict(env, TERM='xterm-256color'),
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)

    def until(needle):
        output = b''
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                output += os.read(master, 65536)
                if needle.encode() in output:
                    return output.decode(errors='replace')
        raise AssertionError((needle, output.decode(errors='replace')))

    try:
        until('[confidential]')
        os.write(master, b'm')
        menu = until('Choose a key')
        assert 'CVE request instructions' in menu and 'p publish' not in menu
        os.write(master, b'c')
        until('No CVE request was submitted')
        os.write(master, b'\x1b')
        until('disclosures')
        os.write(master, b'i')
        until('Reason:')
        os.write(master, b'Not shipped\r')
        until('[invalid]')
        os.write(master, b'I')
        until('Removed local invalid tag')
        os.write(master, b'\t')
        until('[commits')
        os.write(master, b'\t')
        until('[issues/MRs')
        os.write(master, b'q')
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


if __name__ == '__main__':
    if Path(sys.argv[0]).name in ['glab', 'gh', 'agent', 'r2']:
        stub()
    else:
        main()
