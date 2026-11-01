# vwhois

`vwhois` is an RDAP-first WHOIS client, as a V module and a command-line tool.

For each domain, it finds the RDAP server of its top-level domain in the IANA RDAP bootstrap, and
queries it. When the top-level domain has no RDAP server, it queries WHOIS on port 43 instead,
on the server that `whois.iana.org` designates; WHOIS can also be chosen directly.

## Installation

```sh
v install --git https://github.com/davlgd/vWhois
```

The module is then imported as `vwhois`. To build the command-line tool, clone it in a
directory named after the module:

```sh
git clone https://github.com/davlgd/vWhois.git vwhois
cd vwhois
v -prod -o vwhois cmd/whois
./vwhois example.com
```

## Command line

```sh
vwhois davlgd.fr
vwhois -j davlgd.fr
vwhois --whois davlgd.com
```

Options:

- `--whois`: query WHOIS instead of RDAP
- `-j`, `--json`: print JSON
- `--no-cache`: fetch the RDAP bootstrap for this run only
- `--refresh-cache`: refresh the cached RDAP bootstrap before the lookup
- `-h`, `--help`: show the help

The exit status is 0 when every lookup got an answer, 1 when one failed or was throttled, and 2
on invalid arguments.

With `-j`, each result is an object (abridged here):

```sh
$ vwhois -j example.com
[{"query":"example.com","protocol":"rdap","status":"registered","http_status":200,"rdap":{...}}]
```

## Library

```v oksyntax
import vwhois

result := vwhois.lookup('davlgd.fr', vwhois.Config{})
println(vwhois.format_text([result]))
```

`lookup_many` looks up several domains and loads the RDAP bootstrap once per call, `lookup_whois`
queries WHOIS directly, and `format_json` renders results as JSON. `examples/basic.v` performs a
real lookup:

```sh
v run examples/basic.v
```

## Results

Each `LookupResult` has a `status`:

- `registered`: the registry returned data for the domain, summarized in `rdap` for RDAP and
  kept in `raw` for WHOIS;
- `not_found`: the registry has no data for the domain (RDAP 404, or a WHOIS response that says
  so); reserved or blocked names can be in this case too;
- `unknown`: the WHOIS response could not be classified;
- `throttled`: the RDAP server rate-limited the request (HTTP 429);
- `error`: the lookup failed, and `error` says why.

WHOIS responses are classified from the lines they start with, such as `Domain Name:` or
`No match for`.

## Behaviour

Domains are trimmed, lowercased and validated before they are queried: at least two labels of
letters, digits and hyphens, within DNS length limits. Internationalized names must be in their
punycode form.

RDAP requests use HTTPS with certificate validation, and follow redirects to other HTTPS URLs.
An RDAP answer is accepted when it is a domain object whose name, when present, is the queried
one; otherwise the next server listed for the top-level domain is tried. RDAP responses are
requested uncompressed, and RDAP and WHOIS responses longer than 512 KiB are rejected. Reading a
WHOIS response has a 10-second budget.

The IANA RDAP bootstrap is validated, then cached on disk in `os.cache_dir()/vwhois`. A cached
copy is reused for 24 hours; after that it is refreshed, and the previous copy is still used if
the download fails or returns an invalid bootstrap. `vwhois.Config` sets another bootstrap URL,
cache path or lifetime, or disables the cache.

## Tests

```sh
v test .
```

The tests run offline.

## License

MIT, see [LICENSE](LICENSE).
