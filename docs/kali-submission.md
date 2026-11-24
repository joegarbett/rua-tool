# Kali "New Tool Request" — submission content

Kali accepts tool requests via their bug tracker, not a pull request. Follow
<https://www.kali.org/docs/tools/submitting-tools/>.

**You must file this yourself** at <https://bugs.kali.org/> (it needs a Kali bug
tracker account; it cannot be submitted via this repo). Use **Report issue** and
set:

| Field | Value |
| --- | --- |
| Category | **New Tool Requests** |
| Reproducibility | N/A |
| Severity | minor |
| Priority | normal |
| Summary | `rua-tool — find DMARC reports pointed at expired (takeover-able) domains` |

Paste the block below into **Description**.

---

```
[Name]
rua-tool

[Version]
0.1.0

[Homepage]
https://github.com/joegarbett/rua-tool

[Download]
https://github.com/joegarbett/rua-tool/releases/latest
(tagged release: https://github.com/joegarbett/rua-tool/releases/tag/v0.1.0)

[Author]
Joseph Garbett (https://github.com/joegarbett)

[Licence]
MIT

[Description]
rua-tool inspects the DMARC record at _dmarc.<domain> and checks the domains
that its aggregate (rua) and forensic (ruf) reports are sent to. Report
addresses are reduced to their registrable domain (eTLD+1) via the Public
Suffix List, then checked against RDAP (with a DNS/NXDOMAIN fallback). If a
report domain is unregistered or expiring, an attacker could register it and
begin receiving the victim's DMARC reports — leaking sending infrastructure,
volumes and authentication failures, and aiding targeted spoofing. The tool can
check one domain, spider a site to harvest and scan many domains, discover a
responsible-disclosure contact (security.txt -> RDAP -> role accounts), and
write disclosure drafts for the affected webmasters. All lookups are read-only
and it never sends mail.

[Dependencies]
Runtime: none — a single static binary, no runtime dependencies.
Build: Go toolchain (the module targets Go 1.26) and golang.org/x/net
(Public Suffix List + HTML parser); packaged in Debian as
golang-golang-x-net-dev.

[Similar tools]
No direct equivalent focused on expired DMARC report-domain takeover plus
spidering and disclosure. Adjacent tools assess DMARC/SPF posture but do not
flag report-domain takeover: checkdmarc, spoofcheck, mailspoof. dnstwist covers
look-alike domains, a different problem.

[Activity]
First public release November 2026; actively developed on GitHub. MIT-licensed,
with CI (vet/test/build) and automated releases.

[How to install]
It is written in Go. To compile from a tagged release:
  git clone https://github.com/joegarbett/rua-tool
  cd rua-tool && git checkout v0.1.0
  go build -o rua-tool .
Upstream also ships a debian/ directory (dh-sequence-golang) for Debian-style
packaging, and prebuilt .deb/.rpm/archives are attached to each GitHub release.

[How to use]
  rua-tool check example.com                 # scan one domain's DMARC
  rua-tool spider https://example.com        # crawl a site, scan every domain found
  rua-tool scan-list domains.txt             # scan a list of domains
  rua-tool list                              # review stored findings
  rua-tool contact example.com               # find a disclosure contact
  rua-tool report --from="Your Name"         # write disclosure drafts
  rua-tool version
Exit codes: 0 clean, 2 usage, 3 finding(s) present, 1 error.

[Packaged]
Not yet in Debian. The upstream repository contains a debian/ directory using
the dh golang buildsystem (builds against golang-golang-x-net-dev), plus a man
page (rua-tool.1). A tagged release (v0.1.0) is available as required.
```

---

## Notes for packaging (for the Kali maintainer / before an sbuild)

- The `debian/` directory in this repo is an initial, syntactically-validated
  starting point (`dpkg-parsechangelog` and `Dpkg::Control` parse cleanly). It
  has **not** been through a full `sbuild`/`lintian` run — please validate on a
  Kali builder.
- The module's `go.mod` targets **Go 1.26** (required by the current, CVE-free
  `golang.org/x/net` v0.63.0). The `debian/rules` uses the dh golang buildsystem
  so the build takes `x/net` from `golang-golang-x-net-dev` rather than the
  network; confirm the builder's Go and that package satisfy it.
- A tagged upstream release (`v0.1.0`) exists, so no git-HEAD/`git clone`
  acquisition is needed (per the submission guidelines).
