module main

import os
import vwhois

struct CliOptions {
	config vwhois.Config
	json   bool
	help   bool
	args   []string
}

fn main() {
	options := parse_args(os.args[1..]) or {
		eprintln('vwhois: ${err.msg()}')
		eprintln(usage())
		exit(2)
	}
	if options.help {
		println(usage())
		return
	}
	if options.args.len == 0 {
		eprintln('vwhois: missing domain name')
		eprintln(usage())
		exit(2)
	}
	results := vwhois.lookup_many(options.args, options.config)
	if options.json {
		println(vwhois.format_json(results))
	} else {
		println(vwhois.format_text(results))
	}
	for result in results {
		if result.status in ['error', 'throttled'] {
			exit(1)
		}
	}
}

fn parse_args(args []string) !CliOptions {
	mut json_output := false
	mut help := false
	mut whois_only := false
	mut cache_enabled := true
	mut refresh_cache := false
	mut queries := []string{}
	for arg in args {
		match arg {
			'-h', '--help' {
				help = true
			}
			'-j', '--json' {
				json_output = true
			}
			'--whois' {
				whois_only = true
			}
			'--no-cache' {
				cache_enabled = false
			}
			'--refresh-cache' {
				refresh_cache = true
			}
			else {
				if arg.starts_with('-') {
					return error('unknown option: ${arg}')
				}
				queries << arg
			}
		}
	}
	return CliOptions{
		config: vwhois.Config{
			whois_only:    whois_only
			cache_enabled: cache_enabled
			refresh_cache: refresh_cache
		}
		json:   json_output
		help:   help
		args:   queries
	}
}

fn usage() string {
	return 'Usage: vwhois [options] domain ...\n\nOptions:\n  --whois           query WHOIS instead of RDAP\n  -j, --json        print JSON\n  --no-cache        fetch the RDAP bootstrap for this run only\n  --refresh-cache   refresh the cached RDAP bootstrap before the lookup\n  -h, --help        show this help\n\nExit status: 0 when every lookup got an answer, 1 on errors or throttling,\n2 on invalid arguments.'
}
