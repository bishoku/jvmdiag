// Package quality describes the scope and evidence behind diagnostic results.
package quality

import (
	"fmt"
	"strings"
)

type Evidence struct {
	Source   string `json:"source"`
	Location string `json:"location"`
	Metric   string `json:"metric"`
	Value    string `json:"value"`
	Unit     string `json:"unit,omitempty"`
}

type Finding struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Kind        string     `json:"kind"`       // observation or hypothesis
	Confidence  string     `json:"confidence"` // high, medium or low; not a probability
	Evidence    []Evidence `json:"evidence"`
	Limitations []string   `json:"limitations,omitempty"`
	NextStep    string     `json:"nextStep"`
}

type Assessment struct {
	Status      string    `json:"status"` // complete within scope, limited, or metadata-only
	Scope       string    `json:"scope"`
	Source      string    `json:"source"`
	Limitations []string  `json:"limitations"`
	Warnings    []string  `json:"warnings,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
}

func (a *Assessment) Warn(message string) {
	for _, existing := range a.Warnings {
		if existing == message {
			return
		}
	}
	a.Warnings = append(a.Warnings, message)
	if a.Status != "metadata-only" {
		a.Status = "limited"
	}
}

func (a Assessment) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Analysis status: %s\nScope: %s\nEvidence source: %s\n", a.Status, a.Scope, a.Source)
	for _, s := range a.Limitations {
		fmt.Fprintf(&b, "Limitation: %s\n", s)
	}
	for _, s := range a.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", s)
	}
	for _, f := range a.Findings {
		fmt.Fprintf(&b, "\n[%s; confidence=%s] %s\n", f.Kind, f.Confidence, f.Title)
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "  Evidence: %s @ %s: %s=%s %s\n", e.Source, e.Location, e.Metric, e.Value, e.Unit)
		}
		for _, s := range f.Limitations {
			fmt.Fprintf(&b, "  Limitation: %s\n", s)
		}
		fmt.Fprintf(&b, "  Verify next: %s\n", f.NextStep)
	}
	return b.String()
}

func (a Assessment) ContextReport() string { a.Findings = nil; return a.Report() }
