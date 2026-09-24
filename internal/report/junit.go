package report

import (
	"encoding/xml"
	"fmt"
	"io"
)

// junitFormatter renders findings as failed test cases, so CI systems that
// only know how to draw a JUnit report (Jenkins, GitLab, Bamboo) can show each
// leaked secret as a failure with a file and line.
type junitFormatter struct{}

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

func (junitFormatter) Format(w io.Writer, r Report, o Options) error {
	paths, groups := byFile(r.Findings)

	out := junitTestsuites{
		Name: "envleak",
		Time: fmt.Sprintf("%.3f", r.DurationSeconds),
	}

	if len(r.Findings) == 0 {
		// A JUnit report with no test cases at all renders as "no results" in
		// most CI systems, which is indistinguishable from a broken job. Emit
		// one passing case instead.
		out.Suites = append(out.Suites, junitTestsuite{
			Name:  "envleak",
			Tests: 1,
			Cases: []junitTestcase{{Name: "no secrets detected", Classname: "envleak"}},
		})
		out.Tests = 1
	}

	for _, path := range paths {
		findings := groups[path]
		suite := junitTestsuite{
			Name:     path,
			Tests:    len(findings),
			Failures: len(findings),
		}
		for _, f := range findings {
			body := fmt.Sprintf(
				"%s\n\nfile:       %s:%d:%d\nrule:       %s\nseverity:   %s\nconfidence: %s\nengines:    %v\nsecret:     %s\nfingerprint:%s",
				f.Description, f.Path, f.Line, f.StartCol,
				f.RuleID, f.Severity, f.Confidence, f.Engines,
				secretOf(f, o), f.Fingerprint)
			if f.Commit != "" {
				state := "removed from HEAD"
				if f.InHEAD != nil && *f.InHEAD {
					state = "still in HEAD"
				}
				body += fmt.Sprintf("\ncommit:     %s by %s on %s (%s)", f.Commit, f.Author, f.Date, state)
			}
			suite.Cases = append(suite.Cases, junitTestcase{
				Name:      fmt.Sprintf("%s at line %d", f.RuleID, f.Line),
				Classname: path,
				Failure: &junitFailure{
					Message: fmt.Sprintf("%s (%s, %s confidence)", f.Description, f.Severity, f.Confidence),
					Type:    f.RuleID,
					Body:    body,
				},
			})
		}
		out.Suites = append(out.Suites, suite)
		out.Tests += suite.Tests
		out.Failures += suite.Failures
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return wrapWrite(err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode junit: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return wrapWrite(err)
	}
	return nil
}
