module vwhois

import os
import time

fn test_find_rdap_servers_in_bootstrap_prefers_longest_suffix() {
	bootstrap := parse_bootstrap('{"services":[[["uk"],["https://rdap.uk/"]],[["co.uk"],["https://rdap.co.uk/"]],[["com"],["https://rdap.com/"]]]}') or {
		assert false
		return
	}
	servers := find_rdap_servers_in_bootstrap('example.co.uk', bootstrap) or {
		assert false
		return
	}
	assert servers == ['https://rdap.co.uk/']
}

fn test_find_rdap_servers_in_bootstrap_returns_none_for_unknown_tld() {
	bootstrap := parse_bootstrap('{"services":[[["com"],["https://rdap.com/"]]]}') or {
		assert false
		return
	}
	if _ := find_rdap_servers_in_bootstrap('example.me', bootstrap) {
		assert false
	}
}

fn test_parse_https_url_accepts_only_plain_https_urls() {
	assert parse_https_url('https://data.iana.org/rdap/dns.json')!.host == 'data.iana.org'
	for url in ['http://data.iana.org/rdap/dns.json', 'https://data.iana.org/rdap/dns.json\nHost: x',
		'https:///path', 'https://rdap.test/?q=1', 'https://rdap.test/#top', 'https://user@rdap.test/',
		'/rdap/dns.json', 'ftp://rdap.test/'] {
		if _ := parse_https_url(url) {
			assert false, 'expected error for ${url}'
		}
	}
}

fn test_parse_bootstrap_keeps_only_usable_services() {
	bootstrap := parse_bootstrap('{"services":[[["A"],["http://rdap.a/"]],[["b"," ","bad_suffix"],["https://rdap.b/?x=1","https://rdap.b/"]],[["c"]],[[],["https://rdap.d/"]],[["e."],["https://rdap.e/"]]]}')!
	assert bootstrap.services == [[['a'], []], [['b'], ['https://rdap.b/']]]
	// A listed suffix without a usable URL is found, with no URL.
	assert find_rdap_servers_in_bootstrap('example.a', bootstrap)? == []
	assert find_rdap_servers_in_bootstrap('example.b', bootstrap)? == ['https://rdap.b/']
}

fn test_parse_bootstrap_rejects_documents_without_usable_service() {
	for body in ['', '{}', '{"services":[]}', '{"services":[[["a"],["http://rdap.a/"]]]}'] {
		if _ := parse_bootstrap(body) {
			assert false, 'expected error for ${body}'
		}
	}
}

fn test_redirect_target_resolves_relative_locations_and_requires_https() {
	assert redirect_target('https://rdap.test/v1/domain/a.test', '/v2/domain/a.test')! == 'https://rdap.test/v2/domain/a.test'
	assert redirect_target('https://rdap.test/x', 'https://other.test/y')! == 'https://other.test/y'
	if _ := redirect_target('https://rdap.test/x', 'http://rdap.test/x') {
		assert false, 'a redirect to http must be refused'
	}
}

fn test_bootstrap_cache_file_depends_on_the_bootstrap_url() {
	default_path := bootstrap_cache_file(Config{})
	assert default_path.ends_with('rdap-dns.json')
	other := bootstrap_cache_file(Config{ bootstrap_url: 'https://rdap.test/dns.json' })
	assert other != default_path && other.ends_with('.json')
	assert bootstrap_cache_file(Config{ cache_file: '/x/y.json' }) == '/x/y.json'
}

fn test_write_bootstrap_cache_replaces_the_file() {
	path := os.join_path(os.temp_dir(), 'vwhois-write-${os.getpid()}-${time.now().unix_nano()}.json')
	defer {
		os.rm(path) or {}
	}
	config := Config{
		cache_file: path
	}
	write_bootstrap_cache(config, 'first')!
	write_bootstrap_cache(config, 'second')!
	assert os.read_file(path)! == 'second'
	assert read_bootstrap_cache(config)! == 'second'
}

fn test_load_bootstrap_rejects_non_https_url() {
	if _ := load_bootstrap(Config{ bootstrap_url: 'http://data.iana.org/rdap/dns.json' }) {
		assert false, 'expected error for non-https bootstrap url'
	}
}

fn test_load_bootstrap_uses_fresh_cache_file() {
	path := os.join_path(os.temp_dir(), 'vwhois-rdap-cache-${time.now().unix()}.json')
	os.write_file(path, '{"services":[[["test"],["https://rdap.test/"]]]}') or {
		assert false
		return
	}
	bootstrap := load_bootstrap(Config{
		cache_file: path
	}) or {
		assert false
		return
	}
	assert find_rdap_servers_in_bootstrap('example.test', bootstrap)? == ['https://rdap.test/']
}

fn test_load_bootstrap_does_not_use_an_invalid_cache() {
	path := os.join_path(os.temp_dir(), 'vwhois-invalid-${os.getpid()}-${time.now().unix_nano()}.json')
	defer {
		os.rm(path) or {}
	}
	os.write_file(path, 'not json')!
	// An unroutable bootstrap URL makes the refresh fail without leaving the machine.
	config := Config{
		bootstrap_url: 'https://127.0.0.1:1/dns.json'
		cache_file:    path
	}
	if _ := load_bootstrap(config) {
		assert false, 'an invalid cache must not be used'
	}
	assert os.read_file(path)! == 'not json'
}

fn test_load_bootstrap_uses_a_stale_cache_when_the_refresh_fails() {
	path := os.join_path(os.temp_dir(), 'vwhois-stale-${os.getpid()}-${time.now().unix_nano()}.json')
	defer {
		os.rm(path) or {}
	}
	os.write_file(path, '{"services":[[["test"],["https://rdap.test/"]]]}')!
	old := time.now().unix() - 2 * default_cache_ttl_seconds
	os.utime(path, int(old), int(old))!
	bootstrap := load_bootstrap(Config{
		bootstrap_url: 'https://127.0.0.1:1/dns.json'
		cache_file:    path
	})!
	assert find_rdap_servers_in_bootstrap('example.test', bootstrap)? == ['https://rdap.test/']
}

fn test_read_bounded_rejects_files_over_the_limit() {
	path := os.join_path(os.temp_dir(), 'vwhois-big-${os.getpid()}-${time.now().unix_nano()}.json')
	defer {
		os.rm(path) or {}
	}
	os.write_file(path, 'x'.repeat(max_rdap_body_bytes + 1))!
	if _ := read_bounded(path) {
		assert false
	}
	os.write_file(path, 'x'.repeat(max_rdap_body_bytes))!
	assert read_bounded(path)!.len == max_rdap_body_bytes
}
