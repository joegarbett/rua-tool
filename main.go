// Command rua-tool finds domains whose DMARC rua/ruf reporting addresses point
// at an expired (unregistered) domain, spiders sites to surface more of them,
// and drafts responsible-disclosure notices for the affected webmasters.
package main

import (
	"os"

	"github.com/garbott/rua-tool/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args))
}
