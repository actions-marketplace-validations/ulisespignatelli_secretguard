// Package source obtiene el texto a escanear: archivos del disco o cambios de git.
package source

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ulisespignatelli/secretguard/internal/detect"
	"github.com/ulisespignatelli/secretguard/internal/finding"
)

// SkipDirs son carpetas de dependencias o generadas: escanearlas es lento y casi nunca aporta.
var SkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".venv": true, "venv": true,
	"__pycache__": true, "target": true, ".next": true, ".terraform": true, ".idea": true, ".pytest_cache": true,
}

var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".pdf": true, ".zip": true,
	".gz": true, ".tar": true, ".7z": true, ".mp4": true, ".mp3": true, ".woff": true, ".woff2": true, ".ttf": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".class": true, ".jar": true, ".pyc": true, ".db": true,
	".sqlite": true,
}

// Options controla el recorrido de archivos.
type Options struct {
	MaxBytes int64    // archivos mas grandes se saltean
	Exclude  []string // patrones glob sobre la ruta relativa o el nombre
	Workers  int
}

// Excluded indica si una ruta relativa coincide con algun patron de exclusion.
func Excluded(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(p, filepath.Base(rel)); ok {
			return true
		}
		if strings.HasSuffix(p, "/**") && strings.HasPrefix(rel, strings.TrimSuffix(p, "**")) {
			return true
		}
	}
	return false
}

// IsBinary mira los primeros bytes: un NUL casi siempre significa archivo binario.
func IsBinary(b []byte) bool {
	n := min(len(b), 8000)
	return bytes.IndexByte(b[:n], 0) >= 0
}

// ScanFiles recorre root y escanea los archivos en paralelo. Devuelve los hallazgos ordenados y
// cuantos archivos se revisaron.
func ScanFiles(root string, det *detect.Detector, opt Options) ([]finding.Finding, int, error) {
	if opt.Workers <= 0 {
		opt.Workers = 8
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 2 << 20
	}
	info, statErr := os.Stat(root)
	base := root // las rutas del informe son relativas a base
	if statErr == nil && !info.IsDir() {
		base = filepath.Dir(root)
	}
	paths := make(chan string, 256)
	var (
		mu      sync.Mutex
		results []finding.Finding
		scanned int
		wg      sync.WaitGroup
	)
	for range opt.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				data, err := os.ReadFile(p)
				if err != nil || IsBinary(data) {
					continue
				}
				rel, _ := filepath.Rel(base, p)
				fs := det.Scan(data, filepath.ToSlash(rel))
				mu.Lock()
				results = append(results, fs...)
				scanned++
				mu.Unlock()
			}
		}()
	}
	var walkErr error
	switch {
	case statErr != nil:
		walkErr = statErr
	case !info.IsDir():
		paths <- root // un solo archivo: en el informe figura su nombre
	default:
		walkErr = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // un permiso denegado no frena el escaneo
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() {
				if p != root && (SkipDirs[d.Name()] || Excluded(rel, opt.Exclude)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || skipExt[strings.ToLower(filepath.Ext(p))] || Excluded(rel, opt.Exclude) {
				return nil
			}
			if fi, err := d.Info(); err != nil || fi.Size() > opt.MaxBytes {
				return nil
			}
			paths <- p
			return nil
		})
	}
	close(paths)
	wg.Wait()
	Sort(results)
	return results, scanned, walkErr
}

// Sort deja los hallazgos en un orden estable: archivo, linea, columna.
func Sort(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
}
