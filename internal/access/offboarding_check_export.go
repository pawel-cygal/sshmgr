package access

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"strconv"
	"strings"
)

var offboardingCheckCSVHeader = []string{
	"check_id", "identity", "outcome", "before_scan_id", "after_scan_id",
	"classification", "fingerprint", "host", "account", "source", "line",
	"coverage", "authorized_key_options", "reason_codes", "comparable",
	"fresh_after_snapshot", "claims_unchanged", "report_only", "executable",
}

func RenderOffboardingCheckCSV(check *OffboardingCheck) ([]byte, error) {
	if err := ValidateOffboardingCheck(check); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write(offboardingCheckCSVHeader); err != nil {
		return nil, err
	}
	reasonCodes := make([]string, 0, len(check.Reasons))
	for _, reason := range check.Reasons {
		reasonCodes = append(reasonCodes, reason.Code)
	}
	type classifiedEdges struct {
		classification string
		edges          []OffboardingCheckEdge
	}
	groups := []classifiedEdges{
		{classification: "still_observed", edges: check.StillObserved},
		{classification: "not_observed", edges: check.NotObserved},
		{classification: "newly_observed", edges: check.NewlyObserved},
	}
	rows := 0
	for _, group := range groups {
		for _, edge := range group.edges {
			for _, evidence := range edge.Evidence {
				line := ""
				if evidence.Line > 0 {
					line = strconv.Itoa(evidence.Line)
				}
				row := []string{
					check.CheckID, check.Identity.ID, check.Outcome, check.BeforeScanID, check.AfterScanID,
					group.classification, edge.Fingerprint, edge.Host, edge.Account, evidence.Source, line,
					evidence.Coverage, strings.Join(evidence.Options, ";"), strings.Join(reasonCodes, ";"),
					strconv.FormatBool(check.Comparison.Comparable), strconv.FormatBool(check.Comparison.FreshAfterSnapshot),
					strconv.FormatBool(check.Comparison.ClaimsUnchanged), "true", "false",
				}
				for index := range row {
					row[index] = spreadsheetSafeCSVCell(row[index])
				}
				if err := writer.Write(row); err != nil {
					return nil, err
				}
				rows++
			}
		}
	}
	if rows == 0 {
		row := []string{
			check.CheckID, check.Identity.ID, check.Outcome, check.BeforeScanID, check.AfterScanID,
			"none", "", "", "", "", "", "", "", strings.Join(reasonCodes, ";"),
			strconv.FormatBool(check.Comparison.Comparable), strconv.FormatBool(check.Comparison.FreshAfterSnapshot),
			strconv.FormatBool(check.Comparison.ClaimsUnchanged), "true", "false",
		}
		for index := range row {
			row[index] = spreadsheetSafeCSVCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	if output.Len() > maxOffboardingCheckBytes {
		return nil, fmt.Errorf("offboarding check CSV is %d bytes; limit is %d", output.Len(), maxOffboardingCheckBytes)
	}
	return output.Bytes(), nil
}

func WriteOffboardingCheckCSV(path string, check *OffboardingCheck) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("offboarding check CSV output path is empty")
	}
	data, err := RenderOffboardingCheckCSV(check)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

var offboardingCheckTemplate = template.Must(template.New("offboarding-check").Funcs(template.FuncMap{
	"join": strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>SSH Offboarding Check · {{.Identity.ID}}</title><style>
:root{color-scheme:dark;--bg:#070b14;--panel:#111a2a;--text:#e7edf8;--muted:#94a3b8;--line:#293750;--bad:#ff6b7d;--warn:#ffd166;--ok:#71d9ad;--blue:#81c7ff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}main{max-width:1400px;margin:auto;padding:28px 22px 60px}h1,h2{font-family:system-ui,sans-serif}.eyebrow{color:var(--blue);font-weight:700;letter-spacing:.12em}.muted{color:var(--muted)}.outcome{font:700 28px system-ui,sans-serif;text-transform:uppercase}.complete{color:var(--ok)}.still_present{color:var(--bad)}.inconclusive{color:var(--warn)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}.card,.notice{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.number{font:700 25px/1 system-ui,sans-serif;margin-bottom:8px}.notice{border-left:4px solid var(--warn);margin:14px 0}.danger{border-left-color:var(--bad)}.success{border-left-color:var(--ok)}table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:12px 0 24px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}th{color:var(--muted);background:#0c1422}tr:last-child td{border-bottom:0}code{color:#c8dcff;overflow-wrap:anywhere}@media(max-width:700px){main{padding:16px 10px}th,td{font-size:12px;padding:7px}}
</style></head><body><main><div class="eyebrow">sshmgr · read-only post-scan verification</div><h1>{{.Identity.ID}}</h1>{{if .Identity.DisplayName}}<div>{{.Identity.DisplayName}}</div>{{end}}<div class="outcome {{.Outcome}}">{{.Outcome}}</div><p class="muted">check <code>{{.CheckID}}</code> · before <code>{{.BeforeScanID}}</code> · after <code>{{.AfterScanID}}</code></p>
<div class="notice"><strong>No remote change was performed.</strong> A complete result means mapped static access was not observed under the strict comparison conditions shown here. It does not cover unscanned external policy.</div>
<div class="cards"><div class="card"><div class="number">{{.Summary.BaselineAccess}}</div>baseline edges</div><div class="card"><div class="number">{{.Summary.StillObserved}}</div>still observed</div><div class="card"><div class="number">{{.Summary.NotObserved}}</div>not observed</div><div class="card"><div class="number">{{.Summary.NewlyObserved}}</div>new</div><div class="card"><div class="number">{{.Summary.BlockingReasons}}</div>blocking reasons</div></div>
<h2>Decision evidence</h2>{{range .Reasons}}<div class="notice"><code>{{.Code}}</code><br>{{.Message}}</div>{{end}}
<h2>Comparison guards</h2><table><tbody><tr><th>Comparable scope</th><td>{{.Comparison.Comparable}}{{if .Comparison.IncomparableReason}} · {{.Comparison.IncomparableReason}}{{end}}</td></tr><tr><th>Fresh after scan</th><td>{{.Comparison.FreshAfterSnapshot}}</td></tr><tr><th>Ownership claims unchanged</th><td>{{.Comparison.ClaimsUnchanged}}</td></tr><tr><th>Identity remains offboarded</th><td>{{.Comparison.IdentityOffboarded}}</td></tr><tr><th>Unsafe hosts</th><td>{{join .Comparison.UnsafeHosts ", "}}</td></tr><tr><th>Dynamic / CA hosts</th><td>{{join .Comparison.DynamicSourceHosts ", "}}</td></tr></tbody></table>
<h2>Still observed</h2><table><thead><tr><th>Fingerprint</th><th>Account</th><th>Host</th><th>Evidence</th></tr></thead><tbody>{{range $edge := .StillObserved}}<tr><td><code>{{$edge.Fingerprint}}</code></td><td><code>{{$edge.Account}}</code></td><td><code>{{$edge.Host}}</code></td><td>{{range $e := $edge.Evidence}}<code>{{$e.Source}}:{{$e.Line}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</tbody></table>
<h2>Not observed after rescan</h2><table><thead><tr><th>Fingerprint</th><th>Account</th><th>Host</th><th>Baseline evidence</th></tr></thead><tbody>{{range $edge := .NotObserved}}<tr><td><code>{{$edge.Fingerprint}}</code></td><td><code>{{$edge.Account}}</code></td><td><code>{{$edge.Host}}</code></td><td>{{range $e := $edge.Evidence}}<code>{{$e.Source}}:{{$e.Line}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</tbody></table>
<h2>Newly observed</h2><table><thead><tr><th>Fingerprint</th><th>Account</th><th>Host</th><th>Evidence</th></tr></thead><tbody>{{range $edge := .NewlyObserved}}<tr><td><code>{{$edge.Fingerprint}}</code></td><td><code>{{$edge.Account}}</code></td><td><code>{{$edge.Host}}</code></td><td>{{range $e := $edge.Evidence}}<code>{{$e.Source}}:{{$e.Line}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</tbody></table>
<footer class="muted">Generated locally from strict v1 artifacts. No SSH, HTTPS, DNS, keyring, private key, password, remote asset, or remote change is used by this export.</footer></main></body></html>`))

func RenderOffboardingCheckHTML(check *OffboardingCheck) ([]byte, error) {
	if err := ValidateOffboardingCheck(check); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := offboardingCheckTemplate.Execute(&output, check); err != nil {
		return nil, fmt.Errorf("render offboarding check HTML: %w", err)
	}
	if output.Len() > maxOffboardingCheckBytes {
		return nil, fmt.Errorf("offboarding check HTML is %d bytes; limit is %d", output.Len(), maxOffboardingCheckBytes)
	}
	return output.Bytes(), nil
}

func WriteOffboardingCheckHTML(path string, check *OffboardingCheck) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("offboarding check HTML output path is empty")
	}
	data, err := RenderOffboardingCheckHTML(check)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}
