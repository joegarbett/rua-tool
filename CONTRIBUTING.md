# Contributing

Thanks for your interest in rua-tool! Contributions — bug reports, fixes,
features, and docs — are welcome.

## Getting started

Requires Go 1.26 or newer (older toolchains with the default `GOTOOLCHAIN=auto`
fetch it automatically). The only external module is `golang.org/x/net`.

```bash
git clone https://github.com/joegarbett/rua-tool
cd rua-tool
go build -o rua-tool .
go test ./...
```

## Before you open a pull request

Please make sure the checks that CI runs pass locally:

```bash
gofmt -l .        # should print nothing
go vet ./...
go test -race ./...
go build ./...
```

- Keep changes focused; one logical change per PR.
- Add or update tests for behaviour changes. The suite runs offline (DNS, RDAP
  and HTTP are mocked), so please keep new unit tests network-free.
- Match the existing style: small packages under `internal/`, standard library
  first, clear doc comments.

## Project layout

```
main.go           CLI entry point (version stamping)
internal/
  fetch/   bounded HTTP client
  psl/     registrable-domain (eTLD+1) resolution
  dmarc/   read + parse the _dmarc TXT record
  domain/  RDAP + DNS registration / expiry checker
  scan/    orchestration -> findings
  spider/  bounded crawler / domain harvester
  report/  store, contact discovery, disclosure-draft builder
  cli/     command dispatch and output
```

## Reporting bugs

Open an issue with the command you ran, the `rua-tool version`, and what you
expected versus what happened. For **security** issues, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Releases

Releases are automated with GoReleaser. Maintainers cut one by pushing a semver
tag (`git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0`), which builds the
binaries and Linux packages and publishes a GitHub Release.

## Licence

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
