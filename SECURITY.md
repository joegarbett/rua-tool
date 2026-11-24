# Security Policy

## Reporting a vulnerability in rua-tool

If you find a security issue in **rua-tool itself** (for example, a way the
crawler or RDAP/HTTP handling could be abused), please report it privately —
do not open a public issue.

- Preferred: use GitHub's **private vulnerability reporting** — the
  **Security → Report a vulnerability** button on this repository.
- Alternatively, email the maintainer: `joseph@garbott.co.uk`.

Please include steps to reproduce and the version (`rua-tool version`). You can
expect an acknowledgement within a few days. Coordinated disclosure is
appreciated.

## Supported versions

This is an early-stage project; fixes land on `main` and in the next tagged
release. Please test against the [latest release](https://github.com/joegarbett/rua-tool/releases/latest)
before reporting.

## Responsible use of this tool

rua-tool is built for **defensive DMARC hygiene and good-faith disclosure**.

- Only scan domains you are authorised to assess, or operate within an accepted
  vulnerability-disclosure norm.
- All lookups are read-only (DNS, RDAP, and HTTP GETs). The crawler stays within
  the seed's own registrable domain, identifies itself, and rate-limits.
- The tool **never sends mail**. `report` writes drafts for a human to review
  and send. Verify every finding — especially medium-confidence DNS-only ones —
  before contacting anyone, and disclose privately and proportionately.

Using this tool to harvest reports, target people, or contact operators in bad
faith is outside its intended purpose and is your responsibility, not the
project's.
