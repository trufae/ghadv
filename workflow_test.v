module main

import os
import json2

fn test_review_diff_choices() ! {
	orig := 'summary: Old\nseverity: high\n---\nBefore\n'
	proposed := 'summary: New\nseverity: high\n---\nAfter\n'
	diff := udiff('Review notes', orig, proposed)!
	assert apply(orig, diff)! == proposed
	assert apply(orig, diff.replace('+summary: New\n', ''))!.starts_with('severity: high\n')
	assert apply(orig, diff.replace('-summary: Old\n', ''))!.starts_with('summary: Old\nsummary: New\n')
	assert apply(orig, diff.replace(' severity: high', ' severity: low'))!.contains('severity: low\n')
	assert apply(orig, diff.replace('+After', '+Reworded'))!.ends_with('Reworded\n')
	// Removing both sides rejects the replacement without consuming the next line.
	assert apply(orig, diff.replace('-summary: Old\n+summary: New\n', ''))!.starts_with('summary: Old\nseverity: high\n')
}

fn test_review_diff_rejects_damage() ! {
	orig := 'summary: Old\n---\nBefore\n'
	diff := udiff('', orig, 'summary: New\n---\nAfter\n')!
	for damaged in [diff.all_before('@@'), diff + 'broken\n',
		diff.replace('-Before', '-not in original'), diff.replace('@@ -1,3', '@@ -2,3'),
		diff + ' extra context\n', diff + '@@ -1,3 +1,3 @@\n'] {
		if result := apply(orig, damaged) {
			assert false, 'accepted damaged diff: ${result}'
		}
	}
}

fn test_review_diff_empty_and_single_line() ! {
	assert udiff('No changes', 'same\n', 'same\n')! == ''
	assert apply('old\n', udiff('', 'old\n', 'new\n')!)! == 'new\n'
	assert apply('', udiff('', '', 'new\n')!)! == 'new\n'
	assert apply('old', udiff('', 'old', 'new')!)! == 'new\n'
}

fn test_saved_ai_reply() ! {
	notes, text := ai_reply('Review notes\n\nsummary: Revised\n---\nDetails\n')!
	assert notes == 'Review notes'
	assert parse(text)!.summary == 'Revised'
	bare_notes, bare_text := ai_reply('summary: Revised\n---\nDetails\n')!
	assert bare_notes == ''
	assert bare_text == text
	if _, _ := ai_reply('unfinished analysis') {
		assert false, 'accepted a reply without an advisory'
	}
}

fn test_recovery_sessions_do_not_overwrite_previous_work() ! {
	api := Repository{ repo: 'owner/repo' }
	a := start_edit(api, 'GHSA-test', 'review', 'original', 'prompt')!
	b := start_edit(api, 'GHSA-test', 'review', 'other original', 'other prompt')!
	defer {
		os.rmdir_all(a) or {}
		os.rmdir_all(b) or {}
	}
	assert a != b
	assert os.read_file(os.join_path(a, 'original.md'))! == 'original'
	assert os.read_file(os.join_path(a, 'prompt.txt'))! == 'prompt'
	assert os.read_file(os.join_path(b, 'original.md'))! == 'other original'
}

fn test_claude_progress_keeps_text_separate_from_events() ! {
	dir := start_edit(Repository{repo: 'owner/repo'}, 'GHSA-test', 'review', '', '')!
	defer { os.rmdir_all(dir) or {} }
	path := os.join_path(dir, 'reply.txt')
	os.write_file(path, '')!
	mut stream := ClaudeStream{}
	partial := '{"type":"assistant","parent_tool_use_id":null,"message":{"content":[{"type":"thinking","thinking":"private"},{"type":"text","text":"Checking café"},{"type":"tool_use","name":"Read","input":{"file_path":"parser.c"}}]}}\n'
	for byte in partial.bytes() {
		stream.feed([byte].bytestr(), path, false)
	}
	assert stream.failure == ''
	assert os.read_file(path)! == 'Checking café\n'
	stream.feed('{"type":"assistant","parent_tool_use_id":"child","message":{"content":[{"type":"text","text":"child notes"}]}}\n', path, false)
	assert os.read_file(path)! == 'Checking café\n'
	final := 'summary: Final\n---\nVerified café\n'
	// A short-lived child may leave its last event without a trailing newline.
	stream.feed('{"type":"result","is_error":false,"result":${json2.encode(final)}}', path, true)
	assert stream.failure == ''
	assert stream.finished
	assert os.read_file(path)! == final
}

fn test_claude_errors_retain_partial_reply() ! {
	dir := start_edit(Repository{repo: 'owner/repo'}, 'GHSA-test', 'review', '', '')!
	defer { os.rmdir_all(dir) or {} }
	path := os.join_path(dir, 'reply.txt')
	os.write_file(path, 'partial review')!
	mut stream := ClaudeStream{}
	stream.feed('{"type":"result","is_error":true,"errors":["request failed"]}\n', path, true)
	assert stream.failure.contains('request failed')
	assert !stream.finished
	assert os.read_file(path)! == 'partial review'
	stream.feed('not JSON\n', path, true)
	assert stream.failure.contains('invalid Claude event')
	assert os.read_file(path)! == 'partial review'
}
