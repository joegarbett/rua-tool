package psl

import "testing"

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"reports.example.co.uk": "example.co.uk",
		"a.b.example.com":       "example.com",
		"google.com":            "google.com",
		"bbc.co.uk":             "bbc.co.uk",
		"foo.github.io":         "foo.github.io", // github.io is a public suffix
		"EXAMPLE.COM":           "example.com",
		"localhost":             "",
		"":                      "",
	}
	for host, want := range cases {
		if got := RegistrableDomain(host); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}
