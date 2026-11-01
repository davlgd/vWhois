module vwhois

fn test_normalize_query_accepts_domain() {
	got := normalize_query('  Example.COM.  ') or {
		assert false
		return
	}
	assert got == 'example.com'
}

fn test_normalize_query_rejects_urls_and_control_chars() {
	normalize_query('https://example.com') or {
		assert err.msg().contains('domain name')
		return
	}
	assert false
}

fn test_suffixes_for_domain() {
	assert suffixes_for('www.example.co.uk') == ['www.example.co.uk', 'example.co.uk', 'co.uk',
		'uk']
}

fn test_normalize_query_rejects_invalid_inputs() {
	invalid := [
		'',
		'.',
		'example',
		'-example.com',
		'example-.com',
		'exa..mple.com',
		'foo@example.com',
		'a${'a'.repeat(63)}.com',
		'éxample.com',
		'example.com..',
		'${'a'.repeat(63)}.'.repeat(4) + 'com',
	]
	for input in invalid {
		if _ := normalize_query(input) {
			assert false, 'expected error for input: ${input}'
		}
	}
}

fn test_tld_for_returns_last_label() {
	assert tld_for('example.com') == 'com'
	assert tld_for('a.b.c.uk') == 'uk'
	assert tld_for('') == ''
}
