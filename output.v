module vwhois

import json2

// format_json encodes results as a compact JSON array.
pub fn format_json(results []LookupResult) string {
	return json2.encode(results, escape_unicode: true, time_as_unix: true)
}

// format_text renders results as a human-readable, multi-section text report.
pub fn format_text(results []LookupResult) string {
	mut chunks := []string{}
	for result in results {
		chunks << format_one_text(result)
	}
	return chunks.join('\n\n')
}

fn format_one_text(result LookupResult) string {
	mut lines := []string{}
	lines << '# ${result.query}'
	if result.protocol != '' {
		lines << 'Protocol: ${result.protocol.to_upper()}'
	}
	if result.server != '' {
		lines << 'Server: ${result.server}'
	}
	if result.http_status > 0 {
		lines << 'HTTP: ${result.http_status}'
	}
	lines << 'Status: ${result.status}'
	if result.error != '' {
		lines << 'Error: ${result.error}'
	}
	if result.rdap.ldh_name != '' {
		lines << 'Name: ${result.rdap.ldh_name}'
	}
	if result.rdap.statuses.len > 0 {
		lines << 'RDAP status: ${result.rdap.statuses.join(', ')}'
	}
	if result.rdap.nameservers.len > 0 {
		lines << 'Nameservers:'
		for ns in result.rdap.nameservers {
			lines << '  ${ns}'
		}
	}
	if result.rdap.events.len > 0 {
		lines << 'Events:'
		for event in result.rdap.events {
			lines << '  ${event.action}: ${event.date}'
		}
	}
	if result.rdap.entities.len > 0 {
		lines << 'Entities:'
		for entity in result.rdap.entities {
			if entity.handle != '' {
				lines << '  ${entity.roles.join(', ')}: ${entity.handle}'
			} else {
				lines << '  ${entity.roles.join(', ')}'
			}
		}
	}
	if result.raw != '' {
		lines << ''
		lines << result.raw.trim_space()
	}
	return lines.join('\n')
}
