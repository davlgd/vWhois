module vwhois

// default_bootstrap_url is the IANA RDAP bootstrap for domain names (RFC 9224).
pub const default_bootstrap_url = 'https://data.iana.org/rdap/dns.json'
// version is the version of this module.
pub const version = '0.1.0'
// default_user_agent identifies the requests of this module.
pub const default_user_agent = 'vwhois/${version}'
// max_rdap_body_bytes bounds an RDAP response, and the RDAP bootstrap.
pub const max_rdap_body_bytes = 512 * 1024
// max_whois_body_bytes bounds a WHOIS response.
pub const max_whois_body_bytes = 512 * 1024
// default_cache_ttl_seconds is how long a cached RDAP bootstrap is used before
// it is refreshed.
pub const default_cache_ttl_seconds = 24 * 60 * 60

const whois_port = 43
const whois_timeout_seconds = 10
const max_redirects = 5

// Config sets how lookups are made.
pub struct Config {
pub:
	// bootstrap_url is the RDAP bootstrap to read; it must use HTTPS.
	bootstrap_url string = default_bootstrap_url
	// user_agent is sent with every HTTP request.
	user_agent string = default_user_agent
	// cache_enabled keeps the RDAP bootstrap on disk between lookups.
	cache_enabled bool = true
	// cache_ttl_seconds is how long the cached bootstrap is used before it is
	// refreshed; a previous copy is used when the refresh fails.
	cache_ttl_seconds int = default_cache_ttl_seconds
	// refresh_cache refreshes the cached bootstrap before the lookups.
	refresh_cache bool
	// cache_file is the path of the cached bootstrap; by default a file named
	// after the bootstrap URL in `os.cache_dir()/vwhois`.
	cache_file string
	// whois_only queries WHOIS for every domain, and skips RDAP.
	whois_only bool
}

// LookupResult is the outcome of one lookup.
//
// `status` is one of:
// - `registered`: the registry returned data for the domain;
// - `not_found`: the registry has no data for it (RDAP 404, or a WHOIS response
//   that only says so), which does not by itself mean it can be registered;
// - `unknown`: the WHOIS response could not be classified;
// - `throttled`: the RDAP server rate-limited the request (HTTP 429);
// - `error`: the lookup failed, and `error` says why.
pub struct LookupResult {
pub:
	query       string
	protocol    string // `rdap` or `whois`
	server      string // the RDAP base URL, or the WHOIS `host:port`
	status      string
	http_status int @[json: 'http_status']
	error       string
	rdap        RdapSummary
	raw         string // the WHOIS response
}

// RdapSummary holds the public fields of an RDAP domain response.
pub struct RdapSummary {
pub:
	object_class_name string   @[json: 'object_class_name']
	ldh_name          string   @[json: 'ldh_name']
	statuses          []string @[json: 'statuses']
	nameservers       []string
	events            []RdapEventSummary
	entities          []RdapEntitySummary
}

// RdapEventSummary is one event of an RDAP response, such as `registration`.
pub struct RdapEventSummary {
pub:
	action string
	date   string
}

// RdapEntitySummary is one entity of an RDAP response, with its roles.
pub struct RdapEntitySummary {
pub:
	roles  []string
	handle string
}

struct BootstrapFile {
	services [][][]string
}

struct RdapResponse {
	object_class_name string   @[json: 'objectClassName']
	ldh_name          string   @[json: 'ldhName']
	statuses          []string @[json: 'status']
	nameservers       []RdapNameserver
	events            []RdapEvent
	entities          []RdapEntity
}

struct RdapNameserver {
	ldh_name string @[json: 'ldhName']
}

struct RdapEvent {
	event_action string @[json: 'eventAction']
	event_date   string @[json: 'eventDate']
}

struct RdapEntity {
	roles  []string
	handle string
}
