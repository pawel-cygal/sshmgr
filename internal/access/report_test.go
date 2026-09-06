package access

import (
	"strings"
	"testing"
)

func TestFingerprintAndHostLookups(t *testing.T) {
	snapshot := fixtureSnapshot()
	locations := LocationsForFingerprint(snapshot, "fixture")
	if len(locations) != 1 || locations[0].Alias != "web-01" || locations[0].Account != "deploy" {
		t.Fatalf("unexpected locations: %+v", locations)
	}
	text := RenderFingerprintText(snapshot, "sha256:fixture")
	if !strings.Contains(text, "deploy@web-01") {
		t.Fatalf("fingerprint report missing edge: %s", text)
	}
	hostText, found := RenderHostAccessText(snapshot, "web-01")
	if !found || !strings.Contains(hostText, "SHA256:fixture") {
		t.Fatalf("host report missing edge: found=%v report=%s", found, hostText)
	}
	if _, found := RenderHostAccessText(snapshot, "missing"); found {
		t.Fatal("missing host reported as present")
	}
}

func TestHTMLReportEscapesUntrustedFields(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Alias = `<script>alert("x")</script>`
	snapshot.Hosts[0].Limitations = []string{`<img src=x onerror=alert(1)>`}
	html, err := RenderHTML(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	if strings.Contains(text, "<script>alert") || strings.Contains(text, "<img src=x") {
		t.Fatalf("untrusted HTML was not escaped: %s", text)
	}
	if !strings.Contains(text, "&lt;script&gt;") || !strings.Contains(text, "&lt;img") {
		t.Fatalf("escaped values missing: %s", text)
	}
}

func TestHostReportLabelsUninspectedSystemSources(t *testing.T) {
	uid := uint64(0)
	snapshot := &Snapshot{Hosts: []HostSnapshot{{
		Alias: "server", Coverage: CoveragePartial,
		Accounts: []AccountSnapshot{{
			Username: "root", UID: &uid, Home: "/root",
			Auth:    &AccountAuthSnapshot{EffectiveConfig: true},
			Sources: []KeySource{{Path: "/root/.ssh/authorized_keys"}},
		}},
	}}}
	report, found := RenderHostAccessText(snapshot, "server")
	if !found || !strings.Contains(report, "configured source (not inspected): /root/.ssh/authorized_keys") {
		t.Fatalf("configured system source not labelled honestly: %s", report)
	}
	if !strings.Contains(report, "Observed access edges: 0") {
		t.Fatalf("uninspected source was treated as an access edge: %s", report)
	}
}
