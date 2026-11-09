module main

import os

const help = 'Usage: ghav [-r owner/repo] [command] [args]
  tui [label]              advisory, commit and labeled issues/PRs tabs (default)
  ls [state]               list all/triage/draft/published/closed advisories
  log                      list ##crash/##security commits and their advisories
  issues [label]           list labeled issues/PRs (default: GHAV_LABEL or cve)
  new <commit|url> [context] analyze a commit, issue or PR with AI and create a draft
  show <ghsa>              print advisory
  status <ghsa>            show lifecycle, CVE and private report details
  credits <ghsa>           manage credited people and roles in the TUI
  edit <ghsa>              edit advisory in \$EDITOR
  review <ghsa> [context]  let the AI review/rewrite it, then edit
  similar <ghsa|commit|url> [context] find similar bugs using the selection as a template
  resume <directory>       continue saved work without running the AI again
  cve <ghsa>               request a CVE id (asynchronous)
  approve <ghsa>           alias for cve
  draft <ghsa>             accept a report or reopen as a draft
  publish <ghsa>           publish the advisory
  close <ghsa>             close (reject) the advisory
Environment:
  GHAV_REPO   default repository (otherwise taken from the cwd checkout)
  GHAV_GREP   git log -E --grep for fix commits (default: ##(crash|security))
  GHAV_LABEL  issues/PRs label (default: cve; includes open and closed items)
  GHAV_AI     agent command, prompt is piped to stdin (default: claude -p)
              e.g. "codex exec -", \'pmai "\$(cat)"\', \'opencode run "\$(cat)"\''

fn issue_label(label string) string {
	if label != '' {
		return label
	}
	configured := os.getenv('GHAV_LABEL')
	return if configured != '' { configured } else { 'cve' }
}

fn main() {
	mut args := os.args[1..].clone()
	mut repo := os.getenv('GHAV_REPO')
	if args.len > 1 && args[0] == '-r' {
		repo = args[1]
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
			eprintln('usage: ghav resume <recovery-directory>')
			exit(1)
		}
		resume_edit(os.real_path(id), false) or {
			eprintln('error: ${err}')
			exit(1)
		}
		return
	}
	if id != '' && (cmd == 'new' || (cmd == 'similar' && !id.starts_with('GHSA-'))) {
		s := source(repo, id) or {
			eprintln(err)
			exit(1)
		}
		repo = s.repo
	}
	if repo == '' {
		repo = github_repository() or {
			eprintln('cannot find repository, use -r owner/repo or GHAV_REPO')
			exit(1)
		}
	}
	if cmd !in ['tui', 'ls', 'log', 'issues'] && id == '' {
		eprintln(help)
		exit(1)
	}
	api := GitHub{ repo: repo }
	match cmd {
		'tui' {
			tui(api, issue_label(id))
		}
		'ls' {
			for r in api.advisories(id)! {
				println(row(r, 999))
			}
		}
		'log' {
			advs := api.advisories('')!
			for c in commits()! {
				println(crow(c, advs, 999))
			}
		}
		'issues' {
			advs := api.advisories('')!
			for item in api.issues(issue_label(id))! {
				println(irow(item, advs, 999))
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
		'draft', 'publish', 'close' {
			if os.input('${cmd} ${id}? [y/N] ') == 'y' {
				state := match cmd {
					'draft' { 'draft' }
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
