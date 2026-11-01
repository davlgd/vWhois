module vwhois

fn test_format_json_emits_compact_array() {
	results := [
		LookupResult{
			query:    'example.com'
			protocol: 'rdap'
			status:   'registered'
		},
	]
	out := format_json(results)
	assert out.starts_with('[{')
	assert out.ends_with('}]')
	assert !out.contains('\n')
	assert !out.contains('\t')
	assert out.contains('"query":"example.com"')
}

fn test_format_text_renders_sections() {
	result := LookupResult{
		query:    'example.com'
		protocol: 'rdap'
		server:   'https://rdap.example/'
		status:   'registered'
		rdap:     RdapSummary{
			ldh_name:    'EXAMPLE.COM'
			statuses:    ['active']
			nameservers: ['ns1.example.com']
			events:      [
				RdapEventSummary{
					action: 'registration'
					date:   '2020-01-01'
				},
			]
			entities:    [
				RdapEntitySummary{
					roles:  ['registrar']
					handle: 'REG-1'
				},
			]
		}
	}
	out := format_text([result])
	assert out.contains('# example.com')
	assert out.contains('Protocol: RDAP')
	assert out.contains('Server: https://rdap.example/')
	assert out.contains('Status: registered')
	assert out.contains('Name: EXAMPLE.COM')
	assert out.contains('RDAP status: active')
	assert out.contains('  ns1.example.com')
	assert out.contains('  registration: 2020-01-01')
	assert out.contains('  registrar: REG-1')
}

fn test_format_text_includes_raw_when_present() {
	result := LookupResult{
		query:    'example.com'
		protocol: 'whois'
		status:   'registered'
		raw:      'Domain Name: EXAMPLE.COM\n'
	}
	out := format_text([result])
	assert out.contains('Domain Name: EXAMPLE.COM')
}
