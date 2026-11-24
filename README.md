# rua-tool

Find domains whose **DMARC reporting addresses point at an expired (unregistered) domain**, then spider websites to surface more of them for responsible disclosure to the affected webmasters.

A single static Go binary — no runtime dependencies.

## The vulnerability

A DMARC record (published as a TXT record at `_dmarc.<domain>`) can ask mail
receivers to send reports to other addresses:

```
v=DMARC1; p=reject; rua=mailto:aggregate@reports.example.net; ruf=mailto:forensics@example.net
```

- **`rua`** — aggregate reports (who is sending mail as you, from where, and whether it passed SPF/DKIM/DMARC).
- **`ruf`** — forensic/failure reports (can include message samples).

If the **domain that receives those reports has expired**, anyone can register
it and immediately start receiving that organisation's DMARC reports. That leaks
sending infrastructure, mail volumes, and authentication failures — valuable
reconnaissance for targeted spoofing. It is a real, recurring hygiene problem,
especially after a provider or subsidiary domain is retired.

`rua-tool` detects exactly this: it reads the DMARC record, reduces every report
address to its **registrable domain** (via the Public Suffix List, so
`x@sub.example.co.uk` is checked as `example.co.uk`, not the sub-domain), and
asks whether that domain is still registered.

## How registration is checked

1. **RDAP** (the structured successor to WHOIS) via the `rdap.org` bootstrap
   router, which redirects to the authoritative registry.
   - `404` → not registered → **vulnerable** (high confidence).
   - `200` → registered; the expiry date is parsed and domains expiring within
     45 days (or in `pending delete` / `redemption period`) are flagged **at risk**.
2. **DNS fallback** when RDAP is inconclusive (rate limiting, a TLD without
   RDAP): a registrable domain that does not resolve (NXDOMAIN, no NS) is
   reported as likely unregistered at *medium* confidence — verify by WHOIS
   before disclosing.

A domain that reports only to itself is never flagged (nothing to take over).

## Build & install

Requires Go 1.22 or newer.

```bash
go build -o rua-tool .      # build the binary
go install ./...            # or install to $GOBIN
./rua-tool help
```

The only external module is `golang.org/x/net` (Public Suffix List + HTML
parser). Refresh the PSL snapshot with `go get -u golang.org/x/net`.

## Commands

```bash
# Check a single domain
./rua-tool check example.com
./rua-tool check example.com --json --save

# Spider a site: crawl within its own domain, harvest every referenced domain,
# and scan each one's DMARC. Findings are saved to the store by default.
./rua-tool spider https://example.com --max-pages=25 --max-depth=2 --delay=0.5

# Scan a list (one domain per line; blank lines and # comments ignored)
./rua-tool scan-list domains.txt

# Review what has been found
./rua-tool list
./rua-tool list --json

# Find a disclosure contact for a domain (security.txt → RDAP → role accounts)
./rua-tool contact example.com

# Generate reviewable disclosure e-mail drafts for stored findings
./rua-tool report --out=./reports --from="Your Name"
./rua-tool report --domain=example.com
```

### Options

| Option | Applies to | Meaning |
| --- | --- | --- |
| `--json` | check, spider, list | Machine-readable output |
| `--save` / `--no-save` | check / spider, scan-list | Persist findings (spider & scan-list save by default) |
| `--max-pages=N` | spider | Max pages to crawl (default 25; `0` = unlimited) |
| `--max-depth=N` | spider | Max link depth (default 2; `0` = unlimited) |
| `--delay=SEC` | spider | Politeness delay between requests (default 0.5) |
| `--domain=X` | report | Only build drafts for this scanned domain |
| `--out=DIR` | report | Output directory (default `./reports`) |
| `--from="Name"` | report | Sign-off name in the drafts |

Flags may appear before or after the positional argument.

### Environment

- `RUA_STORE` — path to the findings JSON store (default `./rua-findings.json`).
- `NO_COLOR` — disable coloured output.

Exit codes: `0` clean · `2` usage error · `3` finding(s) present · `1` runtime error.
(Exit `3` makes it easy to gate CI on "any vulnerable domain found".)

## Responsible use

This tool is for **defensive DMARC hygiene and good-faith disclosure**.

- The spider only follows links **within the seed's own registrable domain**,
  sends a descriptive User-Agent, and rate-limits itself.
- Registration checks are read-only lookups against public RDAP/DNS.
- **No mail is ever sent.** `report` writes drafts to disk for a human to
  review and send. Verify each finding (especially medium-confidence DNS-only
  ones) before contacting anyone, and disclose privately and proportionately.

Only scan domains you are authorised to assess, or operate within an accepted
vulnerability-disclosure norm.

## Layout

```
main.go                       CLI entry point
internal/
  fetch/    bounded HTTP client (timeout, UA, size cap)
  psl/      registrable-domain (eTLD+1) resolution
  dmarc/    read + parse the _dmarc TXT record
  domain/   RDAP + DNS registration / expiry checker
  scan/     orchestration: domain -> DMARC -> report domains -> findings
  spider/   bounded crawler / domain harvester
  report/   findings store, contact discovery, disclosure-draft builder
  cli/      command dispatch and output
```

## Tests

```bash
go test ./...
```

Unit tests cover PSL resolution, DMARC parsing, and the scan logic (vulnerable,
self-hosted-skip, and expiring-soon paths) using mocked DNS and registration, so
the suite runs offline.
