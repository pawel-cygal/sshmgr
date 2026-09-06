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

var offboardingCSVHeader = []string{
	"report_id", "scan_id", "review_id", "identity", "identity_status",
	"fingerprint", "claim_verification", "shared_key", "other_claims",
	"observed", "host", "account", "source", "line", "coverage",
	"authorized_key_options", "warning_codes", "hosts_full", "hosts_partial",
	"hosts_failed", "dynamic_source_hosts", "report_only", "executable",
	"source_digest_included",
}

func RenderOffboardingReportCSV(report *OffboardingReport) ([]byte, error) {
	if err := ValidateOffboardingReport(report); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write(offboardingCSVHeader); err != nil {
		return nil, err
	}
	warningCodes := make([]string, 0, len(report.Warnings))
	for _, warning := range report.Warnings {
		warningCodes = append(warningCodes, warning.Code)
	}
	keys := report.Keys
	if len(keys) == 0 {
		keys = []OffboardingKey{{}}
	}
	for _, key := range keys {
		otherClaims := make([]string, 0, len(key.OtherClaims))
		for _, claim := range key.OtherClaims {
			otherClaims = append(otherClaims, claim.IdentityID+":"+claim.IdentityStatus+":"+claim.Verification)
		}
		access := key.Access
		if len(access) == 0 {
			access = []OffboardingAccess{{}}
		}
		for _, edge := range access {
			line := ""
			if edge.Line > 0 {
				line = strconv.Itoa(edge.Line)
			}
			row := []string{
				report.ReportID, report.ScanID, report.ReviewID, report.Identity.ID, report.Identity.Status,
				key.Fingerprint, key.SelectedClaim.Verification, strconv.FormatBool(key.Shared), strings.Join(otherClaims, ";"),
				strconv.FormatBool(key.Observed), edge.Host, edge.Account, edge.Source, line, edge.Coverage,
				strings.Join(edge.Options, ";"), strings.Join(warningCodes, ";"),
				strconv.Itoa(report.Coverage.HostsFull), strconv.Itoa(report.Coverage.HostsPartial),
				strconv.Itoa(report.Coverage.HostsFailed), strings.Join(report.Coverage.DynamicSourceHosts, ";"),
				"true", "false", "false",
			}
			for index := range row {
				row[index] = spreadsheetSafeCSVCell(row[index])
			}
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	if output.Len() > maxOffboardingReportBytes {
		return nil, fmt.Errorf("offboarding report CSV is %d bytes; limit is %d", output.Len(), maxOffboardingReportBytes)
	}
	return output.Bytes(), nil
}

func WriteOffboardingReportCSV(path string, report *OffboardingReport) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("offboarding report CSV output path is empty")
	}
	data, err := RenderOffboardingReportCSV(report)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

var offboardingReportTemplate = template.Must(template.New("offboarding-report").Funcs(template.FuncMap{
	"join": strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>SSH Offboarding Report · {{.Identity.ID}}</title><style>
:root{color-scheme:dark;--bg:#070b14;--panel:#111a2a;--text:#e7edf8;--muted:#94a3b8;--line:#293750;--high:#ff6b7d;--medium:#ffd166;--info:#71d9ad;--blue:#81c7ff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}main{max-width:1400px;margin:auto;padding:28px 22px 60px}h1,h2,h3{font-family:system-ui,sans-serif}h1{font-size:32px;margin:4px 0}.eyebrow{color:var(--info);font-weight:700;letter-spacing:.12em}.muted,.detail{color:var(--muted)}.detail{font-size:12px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}.card,.notice,.key{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.number{font:700 26px/1 system-ui,sans-serif;margin-bottom:8px}.notice{border-left:4px solid var(--high);margin:18px 0}.warning{border-left-color:var(--medium)}table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:12px 0 24px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}th{color:var(--muted);background:#0c1422}tr:last-child td{border-bottom:0}code{color:#c8dcff;overflow-wrap:anywhere}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;margin:2px}.high{color:var(--high);font-weight:700}.medium{color:var(--medium);font-weight:700}.info,.full{color:var(--info)}.partial{color:var(--medium)}.failed{color:var(--high)}.key{margin:14px 0}.key h3{font:600 14px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.shared{color:var(--medium);font-weight:700}@media(max-width:700px){main{padding:16px 10px}th,td{font-size:12px;padding:7px}}
</style></head><body><main><div class="eyebrow">sshmgr · read-only offboarding evidence</div><h1>{{.Identity.ID}}</h1>{{if .Identity.DisplayName}}<div>{{.Identity.DisplayName}}</div>{{end}}<p class="muted">Lifecycle: <strong>{{.Identity.Status}}</strong> · report <code>{{.ReportID}}</code> · scan <code>{{.ScanID}}</code></p>
<div class="notice"><strong>Not an executable removal plan.</strong> This report performs no remote change and contains no source-file digest precondition. Re-scan and review exact current file state before any remediation.</div>
<div class="cards"><div class="card"><div class="number">{{.Summary.ClaimedKeys}}</div>claimed keys</div><div class="card"><div class="number">{{.Summary.ObservedKeys}}</div>observed keys</div><div class="card"><div class="number">{{.Summary.AccessEdges}}</div>access edges</div><div class="card"><div class="number">{{.Summary.Hosts}}</div>hosts</div><div class="card"><div class="number">{{.Summary.Accounts}}</div>OS accounts</div><div class="card"><div class="number shared">{{.Summary.SharedKeys}}</div>shared keys</div></div>
<h2>Coverage boundary</h2><div class="cards"><div class="card"><div class="number full">{{.Coverage.HostsFull}}</div>full</div><div class="card"><div class="number partial">{{.Coverage.HostsPartial}}</div>partial</div><div class="card"><div class="number failed">{{.Coverage.HostsFailed}}</div>failed</div><div class="card"><div class="number">{{len .Coverage.DynamicSourceHosts}}</div>dynamic/certificate source hosts</div></div>{{if .Coverage.Caveat}}<div class="notice warning">{{.Coverage.Caveat}}</div>{{end}}
<h2>Warnings</h2><table><thead><tr><th>Severity</th><th>Code</th><th>Fingerprint / hosts</th><th>Evidence</th><th>Required review</th></tr></thead><tbody>{{range .Warnings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td><code>{{.Code}}</code></td><td>{{if .Fingerprint}}<code>{{.Fingerprint}}</code>{{end}}{{if .Hosts}}<div>{{join .Hosts ", "}}</div>{{end}}</td><td>{{.Message}}</td><td>{{.Action}}</td></tr>{{else}}<tr><td colspan="5">No derived warning.</td></tr>{{end}}</tbody></table>
<h2>Observed evidence</h2>{{range .Keys}}<div class="key"><h3>{{.Fingerprint}}</h3><div>Selected claim: <code>{{.SelectedClaim.IdentityID}}</code> · {{.SelectedClaim.Verification}}{{if .Shared}} · <span class="shared">shared claim</span>{{end}}</div>{{if .OtherClaims}}<div class="detail">Other claims: {{range .OtherClaims}}<span class="pill">{{.IdentityID}} · {{.IdentityStatus}} · {{.Verification}}</span>{{end}}</div>{{end}}{{if .Access}}<table><thead><tr><th>OS account</th><th>Host</th><th>Source evidence</th><th>Coverage</th><th>authorized_keys options</th></tr></thead><tbody>{{range .Access}}<tr><td><code>{{.Account}}</code></td><td><code>{{.Host}}</code></td><td><code>{{.Source}}:{{.Line}}</code></td><td class="{{.Coverage}}">{{.Coverage}}</td><td>{{join .Options ", "}}</td></tr>{{end}}</tbody></table>{{else}}<div class="notice warning">Mapped key not observed in this snapshot. This is not proof of absent access.</div>{{end}}</div>{{else}}<div class="notice warning">No key is claimed by this identity in the attached ownership review.</div>{{end}}
<footer class="muted">Generated locally from validated snapshot and ownership-review v1 artifacts. No SSH, HTTPS, DNS, keyring, private key, password, remote asset, or remote change is used by this export.</footer></main></body></html>`))

func RenderOffboardingReportHTML(report *OffboardingReport) ([]byte, error) {
	if err := ValidateOffboardingReport(report); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := offboardingReportTemplate.Execute(&output, report); err != nil {
		return nil, fmt.Errorf("render offboarding report HTML: %w", err)
	}
	if output.Len() > maxOffboardingReportBytes {
		return nil, fmt.Errorf("offboarding report HTML is %d bytes; limit is %d", output.Len(), maxOffboardingReportBytes)
	}
	return output.Bytes(), nil
}

func WriteOffboardingReportHTML(path string, report *OffboardingReport) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("offboarding report HTML output path is empty")
	}
	data, err := RenderOffboardingReportHTML(report)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}
