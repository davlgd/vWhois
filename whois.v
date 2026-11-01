module vwhois

import io
import net
import strings
import time

const iana_whois_server = 'whois.iana.org'

// lookup_whois looks up `query` over WHOIS, on the server that whois.iana.org
// designates for its top-level domain. The query is normalized first, like in
// `lookup`.
pub fn lookup_whois(query string) LookupResult {
	name := normalize_query(query) or {
		return LookupResult{
			query:    query
			protocol: 'whois'
			status:   'error'
			error:    err.msg()
		}
	}
	server := resolve_whois_server(tld_for(name)) or {
		return LookupResult{
			query:    name
			protocol: 'whois'
			status:   'error'
			error:    err.msg()
		}
	}
	address := '${server}:${whois_port}'
	raw := query_whois(address, name) or {
		return LookupResult{
			query:    name
			protocol: 'whois'
			server:   address
			status:   'error'
			error:    err.msg()
		}
	}
	return LookupResult{
		query:    name
		protocol: 'whois'
		server:   address
		status:   classify_whois_text(raw)
		raw:      raw
	}
}

fn resolve_whois_server(tld string) !string {
	if tld == '' {
		return error('no WHOIS server: empty TLD')
	}
	raw := query_whois('${iana_whois_server}:${whois_port}', tld) or {
		return error('no WHOIS server for .${tld}: ${err.msg()}')
	}
	return parse_iana_whois_server(raw) or { error('no WHOIS server for .${tld}: ${err.msg()}') }
}

// parse_iana_whois_server returns the `whois:` or `refer:` server of an IANA
// response, if it is a valid host name.
fn parse_iana_whois_server(raw string) !string {
	for line in raw.split_into_lines() {
		lower := line.to_lower()
		if lower.starts_with('whois:') || lower.starts_with('refer:') {
			value := lower.all_after(':').trim_space()
			if value != '' {
				if !is_host_name(value) {
					return error('invalid WHOIS server `${value}` in IANA response')
				}
				return value
			}
		}
	}
	return error('no whois server in IANA response')
}

// is_host_name reports whether `s` is a lowercase host name: labels of 1 to 63
// letters, digits and hyphens, not starting or ending with a hyphen, and 253
// characters at most.
fn is_host_name(s string) bool {
	if s == '' || s.len > 253 {
		return false
	}
	for label in s.split('.') {
		if label == '' || label.len > 63 || label.starts_with('-') || label.ends_with('-') {
			return false
		}
		for b in label.bytes() {
			if !is_domain_byte(b) {
				return false
			}
		}
	}
	return true
}

// query_whois sends the single-line `query` to the WHOIS server at `address`
// and returns its response, read until the server closes the connection. It
// fails on read errors, on a response longer than `max_whois_body_bytes`, and
// when reading the response takes more than `whois_timeout_seconds` in all.
fn query_whois(address string, query string) !string {
	if query.contains_any('\r\n\x00') {
		return error('invalid WHOIS query')
	}
	deadline := time.now().add(whois_timeout_seconds * time.second)
	mut conn := net.dial_tcp(address)!
	defer {
		conn.close() or {}
	}
	conn.set_write_timeout(whois_timeout_seconds * time.second)
	conn.write_string(query + '\r\n')!
	mut builder := strings.new_builder(4096)
	mut buf := []u8{len: 4096}
	for {
		left := deadline - time.now()
		if left <= 0 {
			return error('WHOIS server ${address} timed out')
		}
		conn.set_read_timeout(left)
		n := conn.read(mut buf) or {
			if err is io.Eof {
				break
			}
			return error('reading from ${address}: ${err.msg()}')
		}
		if n <= 0 {
			break
		}
		if builder.len + n > max_whois_body_bytes {
			return error('WHOIS response from ${address} exceeds ${max_whois_body_bytes} bytes')
		}
		builder.write(buf[..n]) or { return err }
	}
	return builder.str()
}

// classify_whois_text classifies a WHOIS response as `registered`, `not_found`
// or `unknown`, from the lines it starts with. A response with markers of both
// kinds, or of neither, is `unknown`.
pub fn classify_whois_text(raw string) string {
	not_found_markers := [
		'no match',
		'not found',
		'no entries found',
		'status: free',
		'object not found',
		'domain not found',
		'not registered',
		'available for registration',
	]
	registered_markers := [
		'domain name:',
		'domain:',
		'registrar:',
		'creation date:',
		'created:',
		'status: active',
	]
	mut not_found := false
	mut registered := false
	for line in raw.split_into_lines() {
		l := line.trim_space().to_lower().trim_left('%#> ')
		if not_found_markers.any(l.starts_with(it)) {
			not_found = true
		}
		if registered_markers.any(l.starts_with(it)) {
			registered = true
		}
	}
	return match true {
		registered && !not_found { 'registered' }
		not_found && !registered { 'not_found' }
		else { 'unknown' }
	}
}
