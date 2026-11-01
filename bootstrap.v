module vwhois

import crypto.sha256
import json2
import net.http
import net.urllib
import os
import rand
import time

// load_bootstrap returns the RDAP bootstrap: from the cache while it is fresh,
// otherwise downloaded, validated and cached. When the download fails, a
// previously validated copy is used.
fn load_bootstrap(config Config) !BootstrapFile {
	parse_https_url(config.bootstrap_url)!
	if config.cache_enabled && !config.refresh_cache {
		if body := read_fresh_bootstrap_cache(config) {
			if bootstrap := parse_bootstrap(body) {
				return bootstrap
			}
		}
	}
	body, bootstrap := fetch_bootstrap(config) or {
		if config.cache_enabled {
			if stale := read_bootstrap_cache(config) {
				if bootstrap := parse_bootstrap(stale) {
					return bootstrap
				}
			}
		}
		return err
	}
	if config.cache_enabled {
		write_bootstrap_cache(config, body) or {}
	}
	return bootstrap
}

fn fetch_bootstrap(config Config) !(string, BootstrapFile) {
	body := fetch_text(config.bootstrap_url, config)!
	return body, parse_bootstrap(body)!
}

// parse_bootstrap decodes an RDAP bootstrap file (RFC 9224). Each service maps
// domain suffixes to RDAP base URLs; suffixes are kept when they are valid host
// names, and base URLs when they are HTTPS URLs without query or fragment. A
// service whose suffixes are valid but whose URLs are not is kept with no URL,
// so that its suffixes are reported as unusable instead of being unknown.
fn parse_bootstrap(body string) !BootstrapFile {
	raw := json2.decode[BootstrapFile](body)!
	mut services := [][][]string{}
	mut usable := 0
	for service in raw.services {
		if service.len != 2 {
			continue
		}
		mut suffixes := []string{}
		for suffix in service[0] {
			s := suffix.to_lower()
			if is_host_name(s) {
				suffixes << s
			}
		}
		if suffixes.len == 0 {
			continue
		}
		mut servers := []string{}
		for server in service[1] {
			if _ := parse_https_url(server) {
				servers << server
			}
		}
		if servers.len > 0 {
			usable++
		}
		services << [suffixes, servers]
	}
	if usable == 0 {
		return error('RDAP bootstrap has no usable service')
	}
	return BootstrapFile{
		services: services
	}
}

// find_rdap_servers_in_bootstrap returns the base URLs of the longest suffix of
// `query` listed in the bootstrap, or none when no suffix is listed. The list
// is empty when the suffix is listed without a usable URL.
fn find_rdap_servers_in_bootstrap(query string, bootstrap BootstrapFile) ?[]string {
	for suffix in suffixes_for(query) {
		for service in bootstrap.services {
			if service.len == 2 && suffix in service[0] {
				return service[1].clone()
			}
		}
	}
	return none
}

// parse_https_url accepts an absolute HTTPS URL with a host, and without
// credentials, query or fragment.
fn parse_https_url(url string) !urllib.URL {
	for b in url.bytes() {
		if b <= 32 || b == 127 {
			return error('invalid URL `${url}`')
		}
	}
	u := urllib.parse(url) or { return error('invalid URL `${url}`') }
	userinfo := u.user or { urllib.Userinfo{} }
	if userinfo.username != '' || userinfo.password_set {
		return error('URL must not contain credentials: `${url}`')
	}
	if u.scheme != 'https' || u.host == '' || u.raw_query != '' || u.fragment != '' {
		return error('URL must be an https:// URL without query or fragment: `${url}`')
	}
	return u
}

fn fetch_text(url string, config Config) !string {
	response := https_get(url, 'application/rdap+json, application/json, text/plain', config)!
	if response.status_code < 200 || response.status_code > 299 {
		return error('HTTP ${response.status_code} from ${url}')
	}
	return response.body
}

// https_get fetches `url` with certificate validation, following up to
// `max_redirects` redirects to other HTTPS URLs. It asks for an uncompressed
// body, stops receiving after `max_rdap_body_bytes` plus room for the headers,
// and rejects responses whose body exceeds `max_rdap_body_bytes`.
fn https_get(url string, accept string, config Config) !http.Response {
	mut current := url
	for _ in 0 .. max_redirects + 1 {
		parse_https_url(current)!
		mut header := http.new_header(key: .accept, value: accept)
		header.add(.accept_encoding, 'identity')
		response := http.fetch(
			method:               .get
			url:                  current
			header:               header
			user_agent:           config.user_agent
			validate:             true
			allow_redirect:       false
			max_retries:          1
			stop_receiving_limit: max_rdap_body_bytes + 16 * 1024
		)!
		if response.body.len > max_rdap_body_bytes {
			return error('response from ${current} exceeds ${max_rdap_body_bytes} bytes')
		}
		if response.status_code in [301, 302, 303, 307, 308] {
			location := response.header.get(.location) or {
				return error('HTTP ${response.status_code} without Location from ${current}')
			}
			current = redirect_target(current, location)!
			continue
		}
		return response
	}
	return error('too many redirects from ${url}')
}

// redirect_target resolves a Location header against the URL that returned it,
// and accepts it only if the result is an HTTPS URL.
fn redirect_target(base string, location string) !string {
	b := urllib.parse(base)!
	l := urllib.parse(location)!
	target := b.resolve_reference(l)!.str()
	parse_https_url(target)!
	return target
}

fn bootstrap_cache_file(config Config) string {
	if config.cache_file != '' {
		return config.cache_file
	}
	name := if config.bootstrap_url == default_bootstrap_url {
		'rdap-dns.json'
	} else {
		'rdap-${sha256.hexhash(config.bootstrap_url)[..16]}.json'
	}
	return os.join_path(os.cache_dir(), 'vwhois', name)
}

fn read_fresh_bootstrap_cache(config Config) !string {
	path := bootstrap_cache_file(config)
	if !os.exists(path) {
		return error('bootstrap cache does not exist')
	}
	mtime := os.file_last_mod_unix(path)
	now := time.now().unix()
	ttl := if config.cache_ttl_seconds > 0 {
		config.cache_ttl_seconds
	} else {
		default_cache_ttl_seconds
	}
	if mtime <= 0 || now - mtime > ttl {
		return error('bootstrap cache is stale')
	}
	return read_bounded(path)
}

fn read_bootstrap_cache(config Config) !string {
	path := bootstrap_cache_file(config)
	if !os.exists(path) {
		return error('bootstrap cache does not exist')
	}
	return read_bounded(path)
}

// read_bounded reads at most `max_rdap_body_bytes` from `path`, and fails if the
// file is longer.
fn read_bounded(path string) !string {
	mut f := os.open(path)!
	defer {
		f.close()
	}
	mut buf := []u8{len: max_rdap_body_bytes + 1}
	mut total := 0
	for total < buf.len {
		n := f.read(mut buf[total..]) or {
			if err is os.Eof {
				break
			}
			return err
		}
		if n <= 0 {
			break
		}
		total += n
	}
	if total > max_rdap_body_bytes {
		return error('bootstrap cache exceeds ${max_rdap_body_bytes} bytes')
	}
	return buf[..total].bytestr()
}

// write_bootstrap_cache writes the new copy to a file of its own next to the
// cache, then renames it over the cache, which replaces it atomically. On
// Windows, where a rename cannot replace a file, the old copy is removed first,
// so readers may briefly find no cache and download the bootstrap themselves.
fn write_bootstrap_cache(config Config, body string) ! {
	path := bootstrap_cache_file(config)
	dir := os.dir(path)
	if dir != '' {
		os.mkdir_all(dir)!
	}
	tmp := '${path}.${os.getpid()}-${rand.u64():x}.tmp'
	os.write_file(tmp, body)!
	os.rename(tmp, path) or {
		$if windows {
			os.rm(path) or {}
			if _ := os.rename(tmp, path) {
				return
			}
		}
		os.rm(tmp) or {}
		return err
	}
}
