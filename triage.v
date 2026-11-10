module main

import os
import json2
import crypto.sha256

// Local triage annotations are independent of GitHub's advisory lifecycle.
struct InvalidMark {
	target string
	reason string
}

fn invalid_key(input string) string {
	return input.to_lower()
}

fn invalid_target(repo string, input string) !string {
	if input.to_lower().starts_with('ghsa-') {
		return invalid_key(input)
	}
	s := source(repo, input)!
	if s.kind != 'commit' { return invalid_key(s.url) }
	if s.ref.len == 40 && s.ref.bytes().all(it.is_hex_digit()) {
		return invalid_key(s.ref)
	}
	// Short hashes and refs must resolve to the same full hash used by the list.
	r := os.exec(['git', 'rev-parse', '--verify', '--end-of-options', '${s.ref}^{commit}'])
	if r.exit_code != 0 {
		return error('cannot resolve commit ${s.ref}; use its full SHA or the matching checkout')
	}
	return invalid_key(r.output.trim_space())
}

fn (api GitHub) invalid_path(target string) string {
	return os.join_path(api.state_path('invalid', ''), sha256.hexhash(invalid_key(target)) + '.json')
}

fn (api GitHub) invalid_marks() !map[string]string {
	dir := api.state_path('invalid', '')
	mut marks := map[string]string{}
	if !os.exists(dir) { return marks }
	for name in os.ls(dir)! {
		if !name.ends_with('.json') { continue }
		path := os.join_path(dir, name)
		mark := json2.decode[InvalidMark](os.read_file(path)!)!
		if mark.target == '' || mark.reason.trim_space() == '' {
			return error('invalid local triage record: ${path}')
		}
		marks[invalid_key(mark.target)] = mark.reason
	}
	return marks
}

fn (api GitHub) mark_invalid(target string, reason string) ! {
	if target == '' || reason.trim_space() == '' {
		return error('an invalid tag requires a target and a reason')
	}
	path := api.invalid_path(target)
	os.mkdir_all(os.dir(path), mode: 0o700)!
	tmp := '${path}.${os.getpid()}.tmp'
	defer { os.rm(tmp) or {} }
	os.write_file(tmp, json2.encode(InvalidMark{invalid_key(target), reason.trim_space()}))!
	os.rename(tmp, path)!
}

fn (api GitHub) unmark_invalid(target string) ! {
	path := api.invalid_path(target)
	if os.exists(path) { os.rm(path)! }
}

fn marked_row(line string, reason string, width int) string {
	if reason == '' { return line }
	return clip_line('[invalid] ${line}', line_width(width))
}
