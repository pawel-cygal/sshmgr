package access

import "testing"

func TestNormalizeFailOnSeverity(t *testing.T) {
	for input, want := range map[string]string{
		"": "", " none ": "", "CRITICAL": SeverityCritical, " high ": SeverityHigh,
		"medium": SeverityMedium, "low": SeverityLow, "info": SeverityInfo,
	} {
		got, err := NormalizeFailOnSeverity(input)
		if err != nil || got != want {
			t.Fatalf("NormalizeFailOnSeverity(%q)=%q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeFailOnSeverity("warning"); err == nil {
		t.Fatal("unsupported severity was accepted")
	}
}

func TestCountFindingsAtOrAboveUsesInclusiveThreshold(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical}, {Severity: SeverityHigh}, {Severity: SeverityMedium},
		{Severity: SeverityLow}, {Severity: SeverityInfo},
	}
	for threshold, want := range map[string]int{
		"none": 0, SeverityCritical: 1, SeverityHigh: 2, SeverityMedium: 3,
		SeverityLow: 4, SeverityInfo: 5,
	} {
		got, err := CountFindingsAtOrAbove(findings, threshold)
		if err != nil || got != want {
			t.Fatalf("CountFindingsAtOrAbove(%q)=%d, %v; want %d", threshold, got, err, want)
		}
	}
	if _, err := CountFindingsAtOrAbove([]Finding{{Severity: "warning"}}, SeverityInfo); err == nil {
		t.Fatal("invalid finding severity was accepted")
	}
}
