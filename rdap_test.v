module vwhois

fn test_rdap_domain_url_trims_slash_and_escapes_domain() {
	assert rdap_domain_url('https://rdap.example/', 'example.com') == 'https://rdap.example/domain/example.com'
}

fn test_parse_rdap_summary_handles_minimal_response() {
	summary := parse_rdap_summary('{"objectClassName":"domain","ldhName":"X.IO"}') or {
		assert false
		return
	}
	assert summary.ldh_name == 'X.IO'
	assert summary.statuses == []
	assert summary.nameservers == []
	assert summary.events == []
	assert summary.entities == []
}

fn test_parse_rdap_summary_drops_nameservers_with_empty_ldh() {
	body := '{"objectClassName":"domain","ldhName":"X","nameservers":[{"ldhName":"NS1"},{"ldhName":""},{"ldhName":"NS2"}]}'
	summary := parse_rdap_summary(body) or {
		assert false
		return
	}
	assert summary.nameservers == ['NS1', 'NS2']
}

fn test_parse_rdap_summary_extracts_public_fields() {
	body := '{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["active"],"nameservers":[{"ldhName":"NS1.EXAMPLE.COM"}],"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}],"entities":[{"roles":["registrar"],"handle":"REG-1"}]}'
	summary := parse_rdap_summary(body) or {
		assert false
		return
	}
	assert summary.object_class_name == 'domain'
	assert summary.ldh_name == 'EXAMPLE.COM'
	assert summary.statuses == ['active']
	assert summary.nameservers == ['NS1.EXAMPLE.COM']
	assert summary.events.len == 1
	assert summary.events[0].action == 'registration'
	assert summary.entities.len == 1
	assert summary.entities[0].roles == ['registrar']
}

fn test_parse_domain_response_requires_a_domain_object_for_the_query() {
	ok := parse_domain_response('{"objectClassName":"domain","ldhName":"EXAMPLE.COM."}', 'example.com')!
	assert ok.ldh_name == 'EXAMPLE.COM.'
	for body in ['not json', '{"objectClassName":"entity"}',
		'{"objectClassName":"domain","ldhName":"other.com"}'] {
		if _ := parse_domain_response(body, 'example.com') {
			assert false, 'expected error for ${body}'
		}
	}
}

fn test_lookup_many_reports_invalid_queries_without_network() {
	results := lookup_many(['', 'not a domain', 'a.com\r\nX'], Config{
		bootstrap_url: 'http://invalid'
	})
	assert results.len == 3
	for result in results {
		assert result.status == 'error'
		assert result.error != ''
		assert result.protocol == ''
	}
}
