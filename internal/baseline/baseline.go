// Package baseline guarda hallazgos aceptados (falsos positivos o secretos ya rotados) para que no
// vuelvan a frenar el CI. Solo guarda huellas: nunca el secreto.
package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/ulisespignatelli/secretguard/internal/finding"
)

// Entry es un hallazgo aceptado.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	Note        string `json:"note,omitempty"`
}

// File es el formato del archivo de linea base.
type File struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Load lee una linea base. Si el archivo no existe devuelve una vacia.
func Load(path string) (File, error) {
	var b File
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return File{Version: 1}, nil
	}
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	return b, nil
}

// Filter quita los hallazgos aceptados y devuelve cuantos se omitieron.
func (b File) Filter(fs []finding.Finding) ([]finding.Finding, int) {
	ok := map[string]bool{}
	for _, e := range b.Entries {
		ok[e.Fingerprint] = true
	}
	var out []finding.Finding
	for _, f := range fs {
		if !ok[f.Fingerprint] {
			out = append(out, f)
		}
	}
	return out, len(fs) - len(out)
}

// FromFindings arma una linea base con todos los hallazgos actuales.
func FromFindings(fs []finding.Finding) File {
	seen := map[string]bool{}
	b := File{Version: 1}
	for _, f := range fs {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		b.Entries = append(b.Entries, Entry{Fingerprint: f.Fingerprint, RuleID: f.RuleID, File: f.File,
			Note: "aceptado al crear la línea base: revisá y rotá si es real"})
	}
	sort.Slice(b.Entries, func(i, j int) bool {
		return b.Entries[i].File+b.Entries[i].Fingerprint < b.Entries[j].File+b.Entries[j].Fingerprint
	})
	return b
}

// Save escribe la linea base con permisos restrictivos.
func (b File) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
