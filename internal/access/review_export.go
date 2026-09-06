package access

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html/template"
	"strconv"
	"strings"
)

var ownershipCSVHeader = []string{
	"review_id", "scan_id", "fingerprint", "observed", "identity_map_entry", "ownership_status",
	"offboarded_access", "possession_verified", "occurrences", "hosts",
	"accounts", "identity_hints_unverified", "identities", "identity_statuses",
	"claim_verification", "claim_sources",
}

func RenderOwnershipReviewCSV(review *OwnershipReview) ([]byte, error) {
	if err := ValidateOwnershipReview(review); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write(ownershipCSVHeader); err != nil {
		return nil, err
	}
	for _, key := range review.Keys {
		identities, statuses, verifications, sources := ownershipClaimColumns(key.Claims)
		row := []string{
			review.ReviewID, review.ScanID, key.Fingerprint, strconv.FormatBool(key.Observed), strconv.FormatBool(key.IdentityMapEntry),
			key.OwnershipStatus, strconv.FormatBool(key.OffboardedAccess),
			strconv.FormatBool(key.PossessionVerified), strconv.Itoa(key.Occurrences),
			strings.Join(key.Hosts, ";"), strings.Join(key.Accounts, ";"),
			strings.Join(key.IdentityHints, ";"), strings.Join(identities, ";"),
			strings.Join(statuses, ";"), strings.Join(verifications, ";"), strings.Join(sources, ";"),
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
	return output.Bytes(), nil
}

func WriteOwnershipReviewCSV(path string, review *OwnershipReview) error {
	data, err := RenderOwnershipReviewCSV(review)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ownershipClaimColumns(claims []ResolvedOwnershipClaim) (identities, statuses, verifications, sources []string) {
	for _, claim := range claims {
		label := claim.IdentityID
		if claim.DisplayName != "" {
			label += " (" + claim.DisplayName + ")"
		}
		identities = append(identities, label)
		statuses = append(statuses, claim.IdentityStatus)
		verifications = append(verifications, claim.Verification)
		sources = append(sources, claim.Source)
	}
	return identities, statuses, verifications, sources
}

var ownershipReviewTemplate = template.Must(template.New("ownership-review").Funcs(template.FuncMap{
	"join": strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSH Ownership Review</title>
<style>
:root{color-scheme:light dark;--bg:#0b1020;--panel:#141b2d;--text:#e8edf7;--muted:#9da9bd;--line:#2b3851;--high:#ff6b6b;--medium:#ffd166;--ok:#5ee1a2}
*{box-sizing:border-box}body{margin:0;padding:28px;background:var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}main{max-width:1300px;margin:auto}h1,h2{font-family:system-ui,sans-serif}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:14px}.number{font-size:26px;font-weight:700}table{width:100%;border-collapse:collapse;background:var(--panel);margin:14px 0 28px}th,td{text-align:left;vertical-align:top;padding:9px;border:1px solid var(--line)}th{color:var(--muted)}code{overflow-wrap:anywhere}.high,.offboarded{color:var(--high);font-weight:700}.medium,.unknown,.shared{color:var(--medium);font-weight:700}.owned{color:var(--ok)}.detail{color:var(--muted);font-size:12px}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 7px;margin:1px}
</style></head><body><main>
<h1>SSH Ownership Review</h1>
<p><code>{{.ReviewID}}</code> · scan <code>{{.ScanID}}</code></p>
<p class="detail">Identity map <code>{{.IdentityMapDigest}}</code>. authorized_keys comments remain unverified hints.</p>
<div class="cards">
<div class="card"><div class="number">{{.Summary.ObservedKeys}}</div>observed keys</div>
<div class="card"><div class="number">{{.Summary.OwnedKeys}}</div>assigned keys</div>
<div class="card"><div class="number">{{.Summary.UnknownKeys}}</div>unknown keys</div>
<div class="card"><div class="number">{{.Summary.SharedKeys}}</div>shared claims</div>
<div class="card"><div class="number">{{.Summary.OffboardedAccessKeys}}</div>offboarded access</div>
<div class="card"><div class="number">{{.Summary.PossessionVerifiedKeys}}</div>possession verified</div>
</div>
<h2>Ownership findings</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Fingerprint</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>
{{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td><code>{{.RuleID}}</code></td><td><code>{{.Fingerprint}}</code></td><td>{{.Title}}</td><td>{{range .Evidence}}<div>{{.}}</div>{{end}}{{if .CoverageCaveat}}<div class="detail">{{.CoverageCaveat}}</div>{{end}}</td></tr>{{end}}
</tbody></table>
<h2>Keys</h2>
<table><thead><tr><th>Fingerprint</th><th>Observed access</th><th>Ownership</th><th>Claims</th><th>Unverified hints</th></tr></thead><tbody>
{{range .Keys}}<tr><td><code>{{.Fingerprint}}</code>{{if .Algorithm}}<div class="detail">{{.Algorithm}}{{if .Bits}} / {{.Bits}} bits{{end}}</div>{{end}}</td><td>{{if .Observed}}{{.Occurrences}} edge(s)<div class="detail">{{join .Hosts ", "}}</div>{{else}}not observed{{end}}</td><td class="{{.OwnershipStatus}}">{{.OwnershipStatus}}{{if .OffboardedAccess}}<div class="offboarded">OFFBOARDED</div>{{end}}{{if .PossessionVerified}}<div class="owned">possession verified</div>{{end}}</td><td>{{range .Claims}}<div class="pill">{{.IdentityID}}{{if .DisplayName}} ({{.DisplayName}}){{end}} · {{.IdentityStatus}} · {{.Verification}}</div>{{end}}</td><td class="detail">{{join .IdentityHints ", "}}</td></tr>{{end}}
</tbody></table>
</main></body></html>`))

func RenderOwnershipReviewHTML(review *OwnershipReview) ([]byte, error) {
	if err := ValidateOwnershipReview(review); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := ownershipReviewTemplate.Execute(&output, review); err != nil {
		return nil, fmt.Errorf("render ownership review HTML: %w", err)
	}
	return output.Bytes(), nil
}

func WriteOwnershipReviewHTML(path string, review *OwnershipReview) error {
	data, err := RenderOwnershipReviewHTML(review)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}
