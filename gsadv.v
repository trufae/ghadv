module main

import os

// Prefer the current name, including explicitly empty settings, then legacy aliases.
fn setting(name string) ?string {
	return os.getenv_opt('GSADV_${name}') or { return os.getenv_opt('GHADV_${name}') }
}

const help = 'Usage: gsadv [-r namespace/repo|url] [--provider github|gitlab] [--host hostname] [--remote name] [command] [args]
  tui [label]              advisory, commit and labeled issues/PRs tabs (default)
  ls [state]               GitHub advisories or GitLab disclosure issues (opened/closed)
  log                     list tagged fix commits and their advisories
  issues [label]           list labeled issues/PRs (default: GSADV_LABEL or cve)
  new <commit|url> [context] analyze a commit, issue or PR/MR with AI and create a draft
  show <id>               print advisory
  status <id>             show lifecycle, CVE and private report details
  credits <id>            manage credited people and roles in the TUI
  edit <id>               edit advisory in \$EDITOR
  review <id> [context]   let the AI review/rewrite it, then edit
  similar <id|commit|url> [context] find similar bugs using the selection as a template
  resume <directory>       continue saved work without running the AI again
  cve <id>                 GitHub: request CVE; GitLab: show CVE request instructions
  approve <id>            alias for cve
  draft <id>              accept a report or reopen as a draft
  publish <id>            publish the advisory
  close <id>               close the advisory/disclosure
  reopen <id>              reopen a closed advisory/disclosure
  invalid <id|commit|url> [reason] show its local tag, or mark invalid with a reason
  unmark <id|commit|url>  remove its local invalid tag
GitLab disclosure IDs use GL-<issue number>; publish/draft/credits are GitHub-only.
Environment:
  GSADV_PROVIDER  github or gitlab (default: detect from Git remote or source URL)
  GSADV_HOST      server hostname (custom hosts also need a provider)
  GSADV_REMOTE    Git remote to use instead of upstream/origin
  GSADV_ADVISORY_LABEL  GitLab disclosure label (default: security-advisory)
  GSADV_REPO   default repository (otherwise taken from the cwd checkout)
  GSADV_GREP   git log -E --grep for fix commits (default: ##(crash|security|vulnerability|sandbox))
  GSADV_LABEL  issues/PRs label (default: cve; includes open and closed items)
  GSADV_AI     agent command, prompt is piped to stdin (default: claude -p)
               progress goes to stderr; replies are saved for recovery
               e.g. "codex exec -", \'pmai --progress "\$(cat)"\', \'opencode run "\$(cat)"\''

fn issue_label(label string) string {
	if label != '' {
		return label
	}
	configured := setting('LABEL') or { '' }
	return if configured != '' { configured } else { 'cve' }
}

fn main() {
	mut args := os.args[1..].clone()
	for args.len > 0 && args[0] in ['-r', '--provider', '--host', '--remote'] {
		if args.len < 2 { eprintln('missing value for ${args[0]}'); exit(1) }
		name := match args[0] {
			'-r' { 'GSADV_REPO' }
			'--provider' { 'GSADV_PROVIDER' }
			'--host' { 'GSADV_HOST' }
			else { 'GSADV_REMOTE' }
		}
		os.setenv(name, args[1], true)
		args = args[2..].clone()
	}
	if args.len > 0 && args[0] in ['-h', '--help', 'help'] {
		println(help)
		return
	}
	cmd := if args.len > 0 { args[0] } else { 'tui' }
	id := if args.len > 1 { args[1] } else { '' }
	ctx := if args.len > 2 { args[2..].join(' ') } else { '' }
	if cmd == 'resume' {
		if id == '' {
			eprintln('usage: gsadv resume <recovery-directory>')
			exit(1)
		}
		resume_edit(os.real_path(id), false) or {
			eprintln('error: ${err}')
			exit(1)
		}
		return
	}
	if cmd == 'tui' {
		tui(Repository{}, issue_label(id))
		return
	}
	input := if cmd in ['new', 'similar', 'invalid', 'unmark'] { id } else { '' }
	api := configured_repository(input) or {
		eprintln('cannot select repository: ${err}')
		exit(1)
	}
	if cmd !in ['ls', 'log', 'issues'] && id == '' {
		eprintln(help)
		exit(1)
	}
	if api.provider == 'gitlab' && cmd in ['draft', 'publish'] {
		eprintln('GitLab disclosure issues use close/reopen; manage confidentiality explicitly on GitLab. This does not publish a CVE.')
		exit(1)
	}
	match cmd {
		'ls' {
			marks := api.invalid_marks()!
			for r in api.advisories(id)! {
				println(marked_row(row(r, 999), marks[invalid_key(r[0])], 999))
			}
		}
		'log' {
			marks := api.invalid_marks()!
			advs := api.advisories('')!
			for c in commits()! {
				println(marked_row(crow(c, advs, 999), marks[invalid_key(c[0])], 999))
			}
		}
		'issues' {
			marks := api.invalid_marks()!
			advs := api.advisories('')!
			for item in api.issues(issue_label(id))! {
				println(marked_row(irow(item, advs, 999), marks[invalid_key(item[0])], 999))
			}
		}
		'invalid', 'unmark' {
			target := api.invalid_target(id) or {
				eprintln('error: ${err}')
				exit(1)
			}
			if cmd == 'invalid' {
				if ctx.trim_space() == '' {
					marks := api.invalid_marks()!
					reason := marks[target]
					println(if reason == '' { 'No local invalid tag for ${id}' } else { 'invalid (local): ${reason}' })
					return
				}
				api.mark_invalid(target, ctx) or {
					eprintln('error: ${err}')
					exit(1)
				}
				println('Marked ${id} invalid locally: ${ctx}')
			} else {
				api.unmark_invalid(target)!
				println('Removed local invalid tag from ${id}')
			}
		}
		'new' {
			cmd_new(api, id, ctx) or {
				eprintln('error: ${err}')
				exit(1)
			}
		}
		'show' {
			print(api.advisory(id)!)
		}
		'status' {
			println(api.status(id)!)
		}
		'credits' {
			credits_tui(api, id) or {
				eprintln('error: ${err}')
				exit(1)
			}
		}
		'edit' {
			cmd_edit(api, id) or {
				eprintln('error: ${err}')
				exit(1)
			}
		}
		'review' {
			cmd_review(api, id, ctx) or {
				eprintln('error: ${err}')
				exit(1)
			}
		}
		'similar' {
			cmd_similar(api, id, ctx) or {
				eprintln('error: ${err}')
				exit(1)
			}
		}
		'cve', 'approve' {
			println(api.request_cve(id)!)
		}
		'draft', 'publish', 'close', 'reopen' {
			if os.input('${cmd} ${id}? [y/N] ') == 'y' {
				state := match cmd {
					'draft' { 'draft' }
					'reopen' { if api.provider == 'gitlab' { 'opened' } else { 'draft' } }
					'publish' { 'published' }
					else { 'closed' }
				}
				api.set_state(id, state)!
			}
		}
		else {
			eprintln(help)
			exit(1)
		}
	}
}
