// Package report persists findings and builds responsible-disclosure notices.
package report

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/joegarbett/rua-tool/internal/scan"
)

// Store is an append-only JSON store of findings, keyed so the same issue is
// never duplicated across runs.
type Store struct {
	Path string
}

// NewStore returns a Store at the given path.
func NewStore(path string) *Store { return &Store{Path: path} }

// All returns every stored finding keyed by Finding.Key().
func (s *Store) All() (map[string]scan.Finding, error) {
	out := map[string]scan.Finding{}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Add stores a finding, preserving the original discovery time for an existing
// one. It reports whether the finding was new.
func (s *Store) Add(f scan.Finding) (bool, error) {
	all, err := s.All()
	if err != nil {
		return false, err
	}
	prev, existed := all[f.Key()]
	if existed && prev.DiscoveredAt != "" {
		f.DiscoveredAt = prev.DiscoveredAt
	}
	all[f.Key()] = f
	return !existed, s.persist(all)
}

func (s *Store) persist(all map[string]scan.Finding) error {
	if dir := filepath.Dir(s.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o775); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, data, 0o644)
}
