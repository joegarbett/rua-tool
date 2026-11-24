package cli

import (
	"fmt"
	"io"
	"os"
)

// Output writes human-facing text with optional ANSI colour.
type Output struct {
	w     io.Writer
	errW  io.Writer
	color bool
}

// NewOutput enables colour only when stdout is a terminal and NO_COLOR is unset.
func NewOutput() *Output {
	return &Output{w: os.Stdout, errW: os.Stderr, color: colorEnabled()}
}

func colorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (o *Output) Line(s string)  { fmt.Fprintln(o.w, s) }
func (o *Output) Errln(s string) { fmt.Fprintln(o.errW, o.paint(s, "31")) }

func (o *Output) Ok(s string) string     { return o.paint(s, "32") }
func (o *Output) Warn(s string) string   { return o.paint(s, "33") }
func (o *Output) Danger(s string) string { return o.paint(s, "31;1") }
func (o *Output) Dim(s string) string    { return o.paint(s, "2") }
func (o *Output) Bold(s string) string   { return o.paint(s, "1") }
func (o *Output) Cyan(s string) string   { return o.paint(s, "36") }

func (o *Output) paint(s, code string) string {
	if !o.color {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}
