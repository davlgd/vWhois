module vwhois

import json2
import net.urllib

// lookup looks up one domain: over RDAP when the IANA bootstrap lists a server
// for its top-level domain, over WHOIS otherwise, or over WHOIS only when
// `config.whois_only` is set.
pub fn lookup(query string, config Config) LookupResult {
	return lookup_many([query], config)[0]
}

// lookup_many looks up several domains, and loads the RDAP bootstrap once per
// call, when at least one valid domain needs RDAP.
pub fn lookup_many(queries []string, config Config) []LookupResult {
	mut normalized := []string{len: queries.len}
	mut results := []LookupResult{len: queries.len}
	mut needs_rdap := false
	for i, query in queries {
		normalized[i] = normalize_query(query) or {
			results[i] = LookupResult{
				query:  query
				status: 'error'
				error:  err.msg()
			}
			continue
		}
		needs_rdap = needs_rdap || !config.whois_only
	}
	mut bootstrap := BootstrapFile{}
	mut bootstrap_error := ''
	if needs_rdap {
		bootstrap = load_bootstrap(config) or {
			bootstrap_error = err.msg()
			BootstrapFile{}
		}
	}
	for i, name in normalized {
		if name != '' {
			results[i] = lookup_one(name, config, bootstrap, bootstrap_error)
		}
	}
	return results
}

fn lookup_one(query string, config Config, bootstrap BootstrapFile, bootstrap_error string) LookupResult {
	if config.whois_only {
		return lookup_whois(query)
	}
	if bootstrap_error != '' {
		return LookupResult{
			query:    query
			protocol: 'rdap'
			status:   'error'
			error:    bootstrap_error
		}
	}
	servers := find_rdap_servers_in_bootstrap(query, bootstrap) or { return lookup_whois(query) }
	if servers.len == 0 {
		return LookupResult{
			query:    query
			protocol: 'rdap'
			status:   'error'
			error:    'the RDAP bootstrap lists no usable server for `${query}`'
		}
	}
	mut last_error := ''
	for server in servers {
		result := fetch_rdap_domain(query, server, rdap_domain_url(server, query), config)
		if result.error == '' || result.status == 'throttled' {
			return result
		}
		last_error = result.error
	}
	return LookupResult{
		query:    query
		protocol: 'rdap'
		server:   servers[0]
		status:   'error'
		error:    last_error
	}
}

fn fetch_rdap_domain(query string, server string, url string, config Config) LookupResult {
	response := https_get(url, 'application/rdap+json, application/json', config) or {
		return LookupResult{
			query:    query
			protocol: 'rdap'
			server:   server
			status:   'error'
			error:    err.msg()
		}
	}
	if response.status_code == 404 {
		return LookupResult{
			query:       query
			protocol:    'rdap'
			server:      server
			status:      'not_found'
			http_status: response.status_code
		}
	}
	if response.status_code == 429 {
		return LookupResult{
			query:       query
			protocol:    'rdap'
			server:      server
			status:      'throttled'
			http_status: response.status_code
			error:       'RDAP server throttled the request'
		}
	}
	if response.status_code < 200 || response.status_code > 299 {
		return LookupResult{
			query:       query
			protocol:    'rdap'
			server:      server
			status:      'error'
			http_status: response.status_code
			error:       'HTTP ${response.status_code}'
		}
	}
	summary := parse_domain_response(response.body, query) or {
		return LookupResult{
			query:       query
			protocol:    'rdap'
			server:      server
			status:      'error'
			http_status: response.status_code
			error:       err.msg()
		}
	}
	return LookupResult{
		query:       query
		protocol:    'rdap'
		server:      server
		status:      'registered'
		http_status: response.status_code
		rdap:        summary
	}
}

// parse_domain_response accepts an RDAP response if it is a domain object (RFC
// 9083 §5.3) whose `ldhName`, when present, is `query`.
fn parse_domain_response(body string, query string) !RdapSummary {
	summary := parse_rdap_summary(body) or { return error('invalid RDAP response: ${err.msg()}') }
	if summary.object_class_name != 'domain' {
		return error('RDAP response is not a domain object')
	}
	if summary.ldh_name != '' && summary.ldh_name.to_lower().trim_right('.') != query {
		return error('RDAP response is for `${summary.ldh_name}`, not `${query}`')
	}
	return summary
}

// parse_rdap_summary extracts the public fields from an RDAP JSON response body.
pub fn parse_rdap_summary(body string) !RdapSummary {
	rdap := json2.decode[RdapResponse](body)!
	mut nameservers := []string{cap: rdap.nameservers.len}
	for ns in rdap.nameservers {
		if ns.ldh_name != '' {
			nameservers << ns.ldh_name
		}
	}
	mut events := []RdapEventSummary{cap: rdap.events.len}
	for event in rdap.events {
		events << RdapEventSummary{
			action: event.event_action
			date:   event.event_date
		}
	}
	mut entities := []RdapEntitySummary{cap: rdap.entities.len}
	for entity in rdap.entities {
		entities << RdapEntitySummary{
			roles:  entity.roles
			handle: entity.handle
		}
	}
	return RdapSummary{
		object_class_name: rdap.object_class_name
		ldh_name:          rdap.ldh_name
		statuses:          rdap.statuses
		nameservers:       nameservers
		events:            events
		entities:          entities
	}
}

// rdap_domain_url builds the domain lookup URL from an RDAP base URL, which the
// bootstrap validation guarantees to be an HTTPS URL without query or fragment.
fn rdap_domain_url(server string, query string) string {
	mut base := server
	for base.ends_with('/') {
		base = base[..base.len - 1]
	}
	return '${base}/domain/${urllib.path_escape(query)}'
}
