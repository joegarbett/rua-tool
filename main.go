// Command rua-tool finds domains whose DMARC rua/ruf reporting addresses point
// at an expired (unregistered) domain, spiders sites to surface more of them,
// and drafts responsible-disclosure notices for the affected webmasters.
package main

import (
	"os"

	"github.com/joegarbett/rua-tool/internal/cli"
)

// Stamped at build time via -ldflags (GoReleaser sets these).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.Build = cli.BuildInfo{Version: version, Commit: commit, Date: date}
	os.Exit(cli.Run(os.Args))
}
