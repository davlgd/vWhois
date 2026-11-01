module vwhois

fn test_classify_whois_text_not_found() {
	assert classify_whois_text('No match for "EXAMPLE-AVAILABLE.COM".') == 'not_found'
}

fn test_classify_whois_text_registered() {
	assert classify_whois_text('Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar') == 'registered'
}

fn test_classify_whois_text_matches_line_starts_only() {
	assert classify_whois_text('%% NOT FOUND') == 'not_found'
	assert classify_whois_text('Domain Name: EXAMPLE.COM\nNotice: a domain that is not found here may be available') == 'registered'
	assert classify_whois_text('Domain: example.fr\nNo match for example.fr') == 'unknown'
}

fn test_lookup_whois_rejects_invalid_queries_without_network() {
	result := lookup_whois('example.com\r\nexample.org')
	assert result.status == 'error'
	assert result.server == ''
}

fn test_query_whois_rejects_multi_line_queries() {
	if _ := query_whois('127.0.0.1:1', 'a.com\r\nb.com') {
		assert false
	} else {
		assert err.msg() == 'invalid WHOIS query'
	}
}

fn test_classify_whois_text_unknown_when_no_marker() {
	assert classify_whois_text('Some unrelated banner text') == 'unknown'
	assert classify_whois_text('') == 'unknown'
}

fn test_parse_iana_whois_server_extracts_whois_field() {
	raw := '% IANA WHOIS server\ndomain:       ME\nwhois:        whois.nic.me\nstatus:       ACTIVE\n'
	server := parse_iana_whois_server(raw) or {
		assert false
		return
	}
	assert server == 'whois.nic.me'
}

fn test_parse_iana_whois_server_extracts_refer_field() {
	raw := 'domain:       COM\nrefer:        whois.verisign-grs.com\n'
	server := parse_iana_whois_server(raw) or {
		assert false
		return
	}
	assert server == 'whois.verisign-grs.com'
}

fn test_parse_iana_whois_server_rejects_invalid_hosts() {
	if _ := parse_iana_whois_server('whois: whois.example.com:4343\n') {
		assert false
	}
}

fn test_is_host_name_checks_each_label() {
	assert is_host_name('whois.nic.co.uk')
	assert is_host_name('xn--p1ai')
	for s in ['', '.uk', 'uk.', 'a..b', '-a.b', 'a-.b', '${'a'.repeat(64)}.b', 'a_b.c', 'A.b'] {
		assert !is_host_name(s), s
	}
}

fn test_parse_iana_whois_server_errors_when_missing() {
	if _ := parse_iana_whois_server('% no whois field here\ndomain: XX\n') {
		assert false
	}
}
