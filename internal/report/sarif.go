package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

// SARIF 2.1.0, the format GitHub Code Scanning ingests.
//
// The structs below cover exactly the subset of the (very large) schema that
// envleak emits. Hand-writing them rather than pulling in a SARIF library
// keeps the dependency list short and the output predictable; the shape is
// pinned by TestSARIFValidatesAgainstSchema, which validates real output
// against the official 2.1.0 JSON schema.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifHelpURI = "https://github.com/dotMuny/EnvLeak#rules"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	ShortDescription     sarifText               `json:"shortDescription"`
	FullDescription      sarifText               `json:"fullDescription"`
	Help                 sarifText               `json:"help"`
	HelpURI              string                  `json:"helpUri,omitempty"`
	Properties           map[string]any          `json:"properties,omitempty"`
	DefaultConfiguration *sarifRuleConfiguration `json:"defaultConfiguration,omitempty"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifFormatter struct{}

// sarifLevel maps envleak severities onto the three levels GitHub renders.
// "low" becomes note rather than warning so that informational entropy hits do
// not drown the Security tab.
func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func (sarifFormatter) Format(w io.Writer, r Report, o Options) error {
	ruleIndex := map[string]int{}
	var sarifRules []sarifRule

	// The driver's rule list is built from the findings themselves, so a
	// synthetic rule such as generic-high-entropy is described exactly like a
	// catalogue rule without needing a catalogue entry.
	ordered := append([]detect.Finding(nil), r.Findings...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].RuleID < ordered[j].RuleID })
	for _, f := range ordered {
		if _, ok := ruleIndex[f.RuleID]; ok {
			continue
		}
		ruleIndex[f.RuleID] = len(sarifRules)
		sarifRules = append(sarifRules, sarifRule{
			ID:               f.RuleID,
			Name:             f.RuleID,
			ShortDescription: sarifText{Text: f.Description},
			FullDescription:  sarifText{Text: f.Description},
			Help: sarifText{Text: fmt.Sprintf(
				"%s. Rotate the credential first, then remove it from the working tree and from Git history.",
				f.Description)},
			HelpURI:              sarifHelpURI,
			DefaultConfiguration: &sarifRuleConfiguration{Level: sarifLevel(f.Severity)},
			Properties: map[string]any{
				"severity": string(f.Severity),
				"tags":     append([]string{"security", "secret"}, f.Tags...),
			},
		})
	}
	if sarifRules == nil {
		sarifRules = []sarifRule{}
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		msg := fmt.Sprintf("%s detected (%s confidence): %s", f.Description, f.Confidence, secretOf(f, o))
		if f.Commit != "" {
			state := "removed from HEAD but still in history"
			if f.InHEAD != nil && *f.InHEAD {
				state = "still present in HEAD"
			}
			msg += fmt.Sprintf(" — introduced in commit %s (%s)", shortHash(f.Commit), state)
		}
		res := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Path},
					Region: sarifRegion{
						StartLine:   maxInt(f.Line, 1),
						StartColumn: maxInt(f.StartCol, 1),
						EndColumn:   maxInt(f.EndCol, 1),
					},
				},
			}},
			PartialFingerprints: map[string]string{
				"envleakFingerprint/v1": f.Fingerprint,
				"secretHash/v1":         f.SecretHash,
			},
			Properties: map[string]any{
				"confidence": string(f.Confidence),
				"engines":    f.Engines,
				"validated":  f.Validated,
			},
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "envleak",
				InformationURI: "https://github.com/dotMuny/EnvLeak",
				Version:        r.ToolVersion,
				Rules:          sarifRules,
			}},
			Results:     results,
			Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
