module vwhois

// normalize_query trims and lowercases a domain name, removes one trailing dot,
// and validates it: at least two labels of letters, digits and hyphens, within
// DNS length limits. Internationalized names must be in their punycode form.
pub fn normalize_query(input string) !string {
	mut query := input.trim_space().to_lower()
	if query.ends_with('.') {
		query = query[..query.len - 1]
	}
	if query == '' {
		return error('empty query')
	}
	if query.len > 253 {
		return error('domain name is longer than 253 characters')
	}
	if query.contains('://') || query.contains('/') || query.contains('@') {
		return error('query must be a domain name, not a URL or email address')
	}
	if query.starts_with('-') || query.ends_with('-') || query.contains('..') {
		return error('invalid domain name')
	}
	labels := query.split('.')
	if labels.len < 2 {
		return error('query must have at least two labels')
	}
	for label in labels {
		if label == '' || label.len > 63 {
			return error('invalid domain label')
		}
		if label.starts_with('-') || label.ends_with('-') {
			return error('invalid domain label')
		}
		for b in label.bytes() {
			if !is_domain_byte(b) {
				return error('invalid character in domain name')
			}
		}
	}
	return query
}

fn is_domain_byte(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `0` && b <= `9`) || b == `-`
}

fn suffixes_for(query string) []string {
	labels := query.split('.')
	mut suffixes := []string{cap: labels.len}
	for i in 0 .. labels.len {
		suffixes << labels[i..].join('.')
	}
	return suffixes
}

fn tld_for(query string) string {
	parts := query.split('.')
	if parts.len == 0 {
		return ''
	}
	return parts[parts.len - 1]
}
