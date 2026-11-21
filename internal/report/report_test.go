package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ulisespignatelli/secretguard/internal/detect"
	"github.com/ulisespignatelli/secretguard/internal/finding"
	. "github.com/ulisespignatelli/secretguard/internal/testutil"
)

func sample() ([]finding.Finding, string) {
	tok := J("sk", "_live_", Rand(28, Alnum, 1))
	fs := detect.New(nil).ScanLine("k='"+tok+"'", "src/pay.js", 3)
	for i := range fs {
		detect.Score(&fs[i])
	}
	return fs, tok
}

func TestOutputsNeverLeakSecret(t *testing.T) {
	fs, tok := sample()
	for name, fn := range map[string]func(*bytes.Buffer){
		"text":  func(b *bytes.Buffer) { Text(b, fs, Summary{Version: "t"}, false) },
		"json":  func(b *bytes.Buffer) { _ = JSON(b, fs, Summary{}) },
		"sarif": func(b *bytes.Buffer) { _ = SARIF(b, fs, Summary{}) },
	} {
		var b bytes.Buffer
		fn(&b)
		if strings.Contains(b.String(), tok) || strings.Contains(b.String(), tok[10:]) {
			t.Errorf("%s: el informe contiene el secreto", name)
		}
	}
}

func TestSARIFShape(t *testing.T) {
	fs, _ := sample()
	var b bytes.Buffer
	if err := SARIF(&b, fs, Summary{Version: "v0"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					Physical struct {
						Region struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Runs[0].Results
	if doc.Version != "2.1.0" || len(r) != 1 || r[0].RuleID != "stripe-secret-key" || r[0].Locations[0].Physical.Region.StartLine != 3 {
		t.Fatalf("SARIF inesperado: %s", b.String())
	}
}

func TestTextClean(t *testing.T) {
	var b bytes.Buffer
	Text(&b, nil, Summary{Version: "t", Files: 4}, false)
	if !strings.Contains(b.String(), "No se encontraron secretos") {
		t.Fatal(b.String())
	}
}
