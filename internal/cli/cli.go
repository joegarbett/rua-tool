// Package cli is the command-line front end for rua-tool.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/garbott/rua-tool/internal/report"
	"github.com/garbott/rua-tool/internal/scan"
	"github.com/garbott/rua-tool/internal/spider"
)

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitFindings = 3
)

// parseFlags parses flags that may appear before, after, or interspersed with
// positional arguments (Go's flag package stops at the first positional), and
// returns the collected positionals. A parse error returns ok=false.
func parseFlags(fs *flag.FlagSet, args []string) (positional []string, ok bool) {
	for {
		if err := fs.Parse(args); err != nil {
			return nil, false
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, true
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func argAt(pos []string, i int) string {
	if i < len(pos) {
		return pos[i]
	}
	return ""
}

type app struct {
	out     *Output
	scanner *scan.Scanner
	store   *report.Store
}

func newApp() *app {
	storePath := os.Getenv("RUA_STORE")
	if storePath == "" {
		wd, _ := os.Getwd()
		storePath = filepath.Join(wd, "rua-findings.json")
	}
	return &app{
		out:     NewOutput(),
		scanner: scan.NewScanner(),
		store:   report.NewStore(storePath),
	}
}

// Run dispatches a command and returns a process exit code. args is os.Args.
func Run(args []string) int {
	a := newApp()
	cmd := "help"
	if len(args) > 1 {
		cmd = args[1]
	}
	rest := args[2:]

	switch cmd {
	case "check":
		return a.check(rest)
	case "spider":
		return a.spider(rest)
	case "scan-list":
		return a.scanList(rest)
	case "list":
		return a.list(rest)
	case "contact":
		return a.contact(rest)
	case "report":
		return a.report(rest)
	case "help", "-h", "--help":
		return a.help()
	default:
		a.out.Errln("Unknown command: " + cmd)
		a.help()
		return exitUsage
	}
}

func (a *app) check(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	save := fs.Bool("save", false, "persist findings to the store")
	pos, ok := parseFlags(fs, args)
	if !ok {
		return exitUsage
	}
	domain := argAt(pos, 0)
	if domain == "" {
		a.out.Errln("Usage: rua-tool check <domain> [--json] [--save]")
		return exitUsage
	}

	result := a.scanner.Scan(domain, "")

	if *asJSON {
		a.printJSON(resultEnvelope(result))
	} else {
		a.printResult(result)
	}
	if *save {
		if _, err := a.saveFindings(result.Findings); err != nil {
			a.out.Errln("save failed: " + err.Error())
			return exitError
		}
	}
	if result.IsVulnerable() {
		return exitFindings
	}
	return exitOK
}

func (a *app) spider(args []string) int {
	fs := flag.NewFlagSet("spider", flag.ContinueOnError)
	maxPages := fs.Int("max-pages", 25, "max pages to crawl (0 = unlimited)")
	maxDepth := fs.Int("max-depth", 2, "max link depth (0 = unlimited)")
	delay := fs.Float64("delay", 0.5, "politeness delay between requests, seconds")
	asJSON := fs.Bool("json", false, "machine-readable output")
	noSave := fs.Bool("no-save", false, "do not persist findings")
	pos, ok := parseFlags(fs, args)
	if !ok {
		return exitUsage
	}
	seed := argAt(pos, 0)
	if seed == "" {
		a.out.Errln("Usage: rua-tool spider <url> [--max-pages=N|0] [--max-depth=N|0] [--delay=SEC] [--json] [--no-save]")
		return exitUsage
	}

	opts := spider.Options{
		MaxPages: *maxPages,
		MaxDepth: *maxDepth,
		Delay:    time.Duration(*delay * float64(time.Second)),
	}
	if !*asJSON {
		opts.OnPage = func(u string) { a.out.Line(a.out.Dim("  crawling " + u)) }
		a.out.Line(a.out.Bold("Spidering " + seed + " …"))
	}

	crawl := spider.New(opts).Crawl(seed)
	if !*asJSON {
		a.out.Line(fmt.Sprintf("Crawled %d page(s); found %d referenced domain(s). Scanning DMARC …\n",
			crawl.PagesCrawled, len(crawl.Domains)))
	}

	var all []scan.Finding
	for _, d := range crawl.Domains {
		result := a.scanner.Scan(d, seed)
		all = append(all, result.Findings...)
		if !*asJSON && result.IsVulnerable() {
			a.printResult(result)
		}
	}

	saved := 0
	if !*noSave {
		n, err := a.saveFindings(all)
		if err != nil {
			a.out.Errln("save failed: " + err.Error())
			return exitError
		}
		saved = n
	}

	if *asJSON {
		if all == nil {
			all = []scan.Finding{}
		}
		a.printJSON(map[string]any{"seed": seed, "crawl": crawl, "findings": all})
	} else {
		a.out.Line("")
		a.out.Line(a.out.Bold(fmt.Sprintf("Done. %d vulnerable/at-risk finding(s) across %d domain(s); %d new saved.",
			len(all), len(crawl.Domains), saved)))
		if len(all) > 0 {
			a.out.Line(a.out.Dim("Generate disclosure drafts with:  rua-tool report"))
		}
	}
	if len(all) > 0 {
		return exitFindings
	}
	return exitOK
}

func (a *app) scanList(args []string) int {
	fs := flag.NewFlagSet("scan-list", flag.ContinueOnError)
	noSave := fs.Bool("no-save", false, "do not persist findings")
	pos, ok := parseFlags(fs, args)
	if !ok {
		return exitUsage
	}
	file := argAt(pos, 0)
	if file == "" {
		a.out.Errln("Usage: rua-tool scan-list <file-with-one-domain-per-line>")
		return exitUsage
	}
	data, err := os.ReadFile(file)
	if err != nil {
		a.out.Errln("cannot read file: " + err.Error())
		return exitUsage
	}

	var all []scan.Finding
	for _, line := range strings.Split(string(data), "\n") {
		domain := strings.TrimSpace(line)
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		result := a.scanner.Scan(domain, "")
		if result.IsVulnerable() {
			a.printResult(result)
			all = append(all, result.Findings...)
		} else {
			note := result.Note
			if note == "" {
				note = "no expired report domains"
			}
			a.out.Line(a.out.Dim("  ok  " + domain + " — " + note))
		}
	}

	saved := 0
	if !*noSave {
		if saved, err = a.saveFindings(all); err != nil {
			a.out.Errln("save failed: " + err.Error())
			return exitError
		}
	}
	a.out.Line("")
	a.out.Line(a.out.Bold(fmt.Sprintf("%d finding(s); %d new saved.", len(all), saved)))
	if len(all) > 0 {
		return exitFindings
	}
	return exitOK
}

func (a *app) list(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if _, ok := parseFlags(fs, args); !ok {
		return exitUsage
	}
	all, err := a.store.All()
	if err != nil {
		a.out.Errln("cannot read store: " + err.Error())
		return exitError
	}
	if len(all) == 0 {
		a.out.Line("No findings stored yet.")
		return exitOK
	}
	if *asJSON {
		findings := make([]scan.Finding, 0, len(all))
		for _, f := range all {
			findings = append(findings, f)
		}
		a.printJSON(findings)
		return exitOK
	}
	a.out.Line(a.out.Bold(fmt.Sprintf("%d stored finding(s):", len(all))))
	for _, f := range all {
		sev := a.out.Warn("MED ")
		if f.Severity() == scan.SeverityHigh {
			sev = a.out.Danger("HIGH")
		}
		a.out.Line(fmt.Sprintf("  [%s] %s → reports to %s (%s)",
			sev, a.out.Bold(f.ScannedDomain), a.out.Cyan(f.ReportDomain), f.Status.State))
	}
	return exitOK
}

func (a *app) contact(args []string) int {
	if len(args) == 0 || args[0] == "" {
		a.out.Errln("Usage: rua-tool contact <domain>")
		return exitUsage
	}
	c := report.NewContactFinder().Find(args[0])
	a.out.Line(a.out.Bold("Disclosure contacts for " + args[0] + ":"))
	for _, contact := range c.Contacts {
		a.out.Line("  " + contact)
	}
	a.out.Line(a.out.Dim("  sources: " + strings.Join(c.Sources, ", ")))
	return exitOK
}

func (a *app) report(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	filterDomain := fs.String("domain", "", "only build drafts for this scanned domain")
	outDir := fs.String("out", "", "output directory (default ./reports)")
	fromName := fs.String("from", "", "sign-off name in drafts")
	if _, ok := parseFlags(fs, args); !ok {
		return exitUsage
	}
	dir := *outDir
	if dir == "" {
		wd, _ := os.Getwd()
		dir = filepath.Join(wd, "reports")
	}

	all, err := a.store.All()
	if err != nil {
		a.out.Errln("cannot read store: " + err.Error())
		return exitError
	}
	if err := os.MkdirAll(dir, 0o775); err != nil {
		a.out.Errln("cannot create output directory: " + err.Error())
		return exitError
	}

	finder := report.NewContactFinder()
	written := 0
	for _, f := range all {
		if *filterDomain != "" && f.ScannedDomain != *filterDomain {
			continue
		}
		contact := finder.Find(f.ScannedDomain)
		draft := report.Build(f, contact, *fromName)
		path := filepath.Join(dir, draft.Filename)
		content := "To: " + strings.Join(draft.Recipients, ", ") + "\n" +
			"Subject: " + draft.Subject + "\n\n" + draft.Body + "\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			a.out.Errln("cannot write " + path + ": " + err.Error())
			return exitError
		}
		written++
		a.out.Line(a.out.Ok("  wrote ") + path)
		preview := draft.Recipients
		if len(preview) > 3 {
			preview = preview[:3]
		}
		a.out.Line(a.out.Dim("    to: " + strings.Join(preview, ", ") + " …"))
	}

	a.out.Line("")
	a.out.Line(a.out.Bold(fmt.Sprintf("%d disclosure draft(s) written to %s.", written, dir)))
	a.out.Line(a.out.Dim("Review each draft, then send it yourself. This tool does not send mail."))
	return exitOK
}

// ---- helpers -------------------------------------------------------------

func (a *app) printResult(r *scan.Result) {
	if !r.HasDMARC() {
		note := r.Note
		if note == "" {
			note = "no DMARC"
		}
		a.out.Line(a.out.Dim("  " + r.Domain + ": " + note))
		return
	}
	if !r.IsVulnerable() {
		a.out.Line(fmt.Sprintf("  %s %s — DMARC ok (%d report domain(s) checked, all registered)",
			a.out.Ok("✓"), a.out.Bold(r.Domain), len(r.Checked)))
		return
	}
	for _, f := range r.Findings {
		badge := a.out.Warn(" AT RISK ")
		if f.Severity() == scan.SeverityHigh {
			badge = a.out.Danger(" VULNERABLE ")
		}
		a.out.Line("")
		a.out.Line(badge + " " + a.out.Bold(f.ScannedDomain))
		a.out.Line("  DMARC reports go to : " + a.out.Cyan(f.ReportDomain) + " (" + f.Tag + ")")
		a.out.Line("  addresses           : " + strings.Join(f.Addresses, ", "))
		a.out.Line("  report domain state : " + a.out.Bold(string(f.Status.State)) +
			" [" + f.Status.Method + ", " + f.Status.Confidence + " confidence]")
		if f.Status.Detail != "" {
			a.out.Line("  detail              : " + f.Status.Detail)
		}
		a.out.Line(a.out.Dim("  DMARC record        : " + f.DMARCRaw))
	}
}

func (a *app) saveFindings(findings []scan.Finding) (int, error) {
	n := 0
	for _, f := range findings {
		isNew, err := a.store.Add(f)
		if err != nil {
			return n, err
		}
		if isNew {
			n++
		}
	}
	return n, nil
}

func (a *app) printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		a.out.Errln("json error: " + err.Error())
		return
	}
	a.out.Line(string(data))
}

func resultEnvelope(r *scan.Result) map[string]any {
	var raw string
	if r.DMARC != nil {
		raw = r.DMARC.Raw
	}
	findings := r.Findings
	if findings == nil {
		findings = []scan.Finding{}
	}
	return map[string]any{
		"domain":   r.Domain,
		"hasDmarc": r.HasDMARC(),
		"dmarc":    raw,
		"note":     r.Note,
		"checked":  r.Checked,
		"findings": findings,
	}
}

func (a *app) help() int {
	b := a.out.Bold
	a.out.Line(b("rua-tool") + " — find DMARC reports pointed at expired domains, and disclose them.")
	a.out.Line("")
	a.out.Line(b("USAGE"))
	a.out.Line("  rua-tool <command> [args] [options]")
	a.out.Line("")
	a.out.Line(b("COMMANDS"))
	a.out.Line("  check <domain>        Look up a domain's DMARC and check its rua/ruf report domains.")
	a.out.Line("  spider <url>          Crawl a site, harvest referenced domains, and scan each.")
	a.out.Line("  scan-list <file>      Scan a newline-delimited list of domains.")
	a.out.Line("  list                  Show stored findings.")
	a.out.Line("  contact <domain>      Discover a responsible-disclosure contact.")
	a.out.Line("  report                Write disclosure e-mail drafts for stored findings.")
	a.out.Line("")
	a.out.Line(b("OPTIONS"))
	a.out.Line("  --json                Machine-readable output (check/spider/list).")
	a.out.Line("  --save / --no-save    Persist (or skip persisting) findings to the store.")
	a.out.Line("  --max-pages=N         Spider: max pages to crawl (default 25; 0 = unlimited).")
	a.out.Line("  --max-depth=N         Spider: max link depth (default 2; 0 = unlimited).")
	a.out.Line("  --delay=SEC           Spider: politeness delay between requests (default 0.5).")
	a.out.Line("  --domain=X            report: only build drafts for this scanned domain.")
	a.out.Line("  --out=DIR             report: output directory (default ./reports).")
	a.out.Line("  --from=\"Name\"         report: sign-off name in drafts.")
	a.out.Line("")
	a.out.Line(b("ENV"))
	a.out.Line("  RUA_STORE             Path to the findings JSON store (default ./rua-findings.json).")
	a.out.Line("  NO_COLOR              Disable coloured output.")
	a.out.Line("")
	a.out.Line(a.out.Dim("Exit codes: 0 ok · 2 usage · 3 finding(s) present · 1 error"))
	return exitOK
}
