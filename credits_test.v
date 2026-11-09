module main

import json2

fn test_credit_roles_and_changes() ! {
	original := [Credit{'alice', 'finder'}]
	for role in credit_roles {
		updated := change_credit(original, -1, Credit{' @bob ', role.typ})!
		assert updated == [Credit{'alice', 'finder'}, Credit{'bob', role.typ}]
		assert credit_description(role.typ) != ''
	}
	assert credit_roles.len == 10
	assert original == [Credit{'alice', 'finder'}]
	// A reporter and finder may be the same person, and editing an entry is not a duplicate.
	assert change_credit(original, -1, Credit{'ALICE', 'reporter'})!.len == 2
	assert change_credit(original, 0, Credit{'alice', 'finder'})! == original
	assert change_credit(original, 0, Credit{'bob', 'remediation_developer'})! == [
		Credit{'bob', 'remediation_developer'},
	]
	assert change_credit([]Credit{}, -1, Credit{'scanner[bot]', 'tool'})![0].login == 'scanner[bot]'
}

fn test_credit_rejects_duplicates_and_invalid_input() {
	credits := [Credit{'alice', 'finder'}, Credit{'bob', 'reporter'}]
	for value in [Credit{'ALICE', 'finder'}, Credit{'', 'reporter'}, Credit{'@', 'finder'},
		Credit{'alice bob', 'finder'}, Credit{'alice:finder', 'reporter'},
		Credit{'https://github.com/alice', 'finder'}, Credit{'someone', 'invented_role'}] {
		if _ := change_credit(credits, -1, value) {
			assert false, 'accepted invalid credit ${value}'
		}
	}
	if _ := change_credit(credits, 1, Credit{'alice', 'finder'}) {
		assert false, 'editing created a duplicate'
	}
	for index in [-2, 2] {
		if _ := change_credit(credits, index, Credit{'carol', 'analyst'}) {
			assert false, 'accepted invalid selection'
		}
	}
}

fn test_credits_payload_and_markdown_compatibility() ! {
	assert json2.encode(AdvisoryCredits{ credits: []Credit{} }) == '{"credits":[]}'
	credits := [Credit{'alice', 'finder'}, Credit{'bob', 'remediation_developer'}]
	payload := json2.encode(AdvisoryCredits{ credits: credits })
	assert payload == '{"credits":[{"login":"alice","type":"finder"},{"login":"bob","type":"remediation_developer"}]}'
	assert json2.decode[[]Credit]('[{"login":"alice","type":"finder"}]')! == [credits[0]]
	advisory := parse('summary: Test\ncredits: alice, bob:remediation_developer\n---\nDescription\n')!
	assert advisory.credits == credits
}
