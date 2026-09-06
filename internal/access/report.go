package access

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
)

type KeyLocation struct {
	Alias     string
	Account   string
	Source    string
	Line      int
	Comment   string
	Algorithm string
	Bits      int
}

// LocationsForFingerprint returns every observed access edge for fingerprint.
func LocationsForFingerprint(snapshot *Snapshot, fingerprint string) []KeyLocation {
	wanted := normalizeFingerprint(fingerprint)
	var locations []KeyLocation
	if snapshot == nil || wanted == "" {
		return locations
	}
	for _, host := range snapshot.Hosts {
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					if normalizeFingerprint(entry.Fingerprint) != wanted {
						continue
					}
					locations = append(locations, KeyLocation{
						Alias:     host.Alias,
						Account:   account.Username,
						Source:    source.Path,
						Line:      entry.Line,
						Comment:   entry.Comment,
						Algorithm: entry.Algorithm,
						Bits:      entry.Bits,
					})
				}
			}
		}
	}
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Alias != locations[j].Alias {
			return locations[i].Alias < locations[j].Alias
		}
		if locations[i].Account != locations[j].Account {
			return locations[i].Account < locations[j].Account
		}
		if locations[i].Source != locations[j].Source {
			return locations[i].Source < locations[j].Source
		}
		return locations[i].Line < locations[j].Line
	})
	return locations
}

func normalizeFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > len("SHA256:") && strings.EqualFold(value[:len("SHA256:")], "SHA256:") {
		return "SHA256:" + value[len("SHA256:"):]
	}
	return "SHA256:" + value
}

func RenderText(snapshot *Snapshot) string {
	if snapshot == nil {
		return ""
	}
	summary := snapshot.Summary
	var output strings.Builder
	fmt.Fprintf(&output, "SSH Access Audit  %s\n\n", snapshot.ScanID)
	fmt.Fprintf(&output, "Coverage\n")
	fmt.Fprintf(&output, "  Hosts requested:               %d\n", summary.HostsRequested)
	fmt.Fprintf(&output, "  Fully scanned:                 %d\n", summary.HostsFull)
	fmt.Fprintf(&output, "  Partially scanned:             %d\n", summary.HostsPartial)
	fmt.Fprintf(&output, "  Failed:                        %d\n", summary.HostsFailed)
	fmt.Fprintf(&output, "\nObserved access\n")
	fmt.Fprintf(&output, "  Accounts observed:             %d\n", summary.AccountsObserved)
	fmt.Fprintf(&output, "  Key files found:               %d\n", summary.KeySourcesFound)
	fmt.Fprintf(&output, "  Authorized key entries:        %d\n", summary.AuthorizedKeyEntries)
	fmt.Fprintf(&output, "  Unique fingerprints:           %d\n", summary.UniqueFingerprints)
	fmt.Fprintf(&output, "  Malformed entries:             %d\n", summary.MalformedEntries)
	fmt.Fprintf(&output, "  Key bytes inspected:           %d\n", summary.KeyBytesInspected)
	fmt.Fprintf(&output, "\nFindings\n")
	fmt.Fprintf(&output, "  Total:                         %d\n", summary.FindingsTotal)
	fmt.Fprintf(&output, "  Critical / high / medium:      %d / %d / %d\n", summary.FindingsCritical, summary.FindingsHigh, summary.FindingsMedium)
	fmt.Fprintf(&output, "  Low / info:                    %d / %d\n", summary.FindingsLow, summary.FindingsInfo)
	for _, finding := range snapshot.Findings {
		ref := finding.Host
		if ref != "" && finding.Account != "" {
			ref += "/" + finding.Account
		}
		if ref == "" {
			ref = finding.Fingerprint
		}
		fmt.Fprintf(&output, "  [%s] %s: %s", finding.Severity, finding.RuleID, finding.Title)
		if ref != "" {
			fmt.Fprintf(&output, " (%s)", ref)
		}
		fmt.Fprintln(&output)
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(&output, "    evidence: %s\n", evidence)
		}
	}

	fmt.Fprintf(&output, "\nHosts\n")
	for _, host := range snapshot.Hosts {
		entries := 0
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				entries += len(source.Entries)
			}
		}
		fmt.Fprintf(&output, "  %-28s  %-7s  %d account(s), %d entry/entries\n",
			host.Alias, host.Coverage, len(host.Accounts), entries)
		if host.System != nil {
			fmt.Fprintf(&output, "    system: privilege=%s root=%t account-db=%s sshd=%t config-valid=%t effective=%t\n",
				host.System.PrivilegeMode, host.System.Root, host.System.AccountDatabase,
				host.System.SSHD.Present, host.System.SSHD.ConfigValid, host.System.SSHD.EffectiveConfig)
			fmt.Fprintf(&output, "    accounts: mode=%s enumerated=%t observed=%d truncated=%t limit=%d\n",
				host.System.AccountMode, host.System.AccountsEnumerated, len(host.Accounts), host.System.AccountsTruncated, host.System.AccountLimit)
			if host.System.SourcesRequested > 0 {
				fmt.Fprintf(&output, "    sources: requested=%d inspected=%d bytes=%d truncated=%t budget-hit=%t\n",
					host.System.SourcesRequested, host.System.SourcesInspected, host.System.SourceBytesRead,
					host.System.SourcesTruncated, host.System.ContentBudgetHit)
			}
			if len(host.System.MissingAccounts) > 0 {
				fmt.Fprintf(&output, "    missing explicit accounts: %s\n", strings.Join(host.System.MissingAccounts, ", "))
			}
			if len(host.System.SSHD.AuthorizedKeysFiles) > 0 {
				fmt.Fprintf(&output, "    AuthorizedKeysFile: %s\n", strings.Join(host.System.SSHD.AuthorizedKeysFiles, ", "))
			}
			if enabledSSHDSource(host.System.SSHD.AuthorizedKeysCommand) {
				fmt.Fprintf(&output, "    AuthorizedKeysCommand: %s (user=%s)\n", host.System.SSHD.AuthorizedKeysCommand, host.System.SSHD.AuthorizedKeysCommandUser)
			}
			if enabledSSHDSource(host.System.SSHD.TrustedUserCAKeys) {
				fmt.Fprintf(&output, "    TrustedUserCAKeys: %s\n", host.System.SSHD.TrustedUserCAKeys)
			}
		}
		for _, scanError := range host.Errors {
			fmt.Fprintf(&output, "    error[%s]: %s\n", scanError.Stage, scanError.Message)
		}
		for _, limitation := range host.Limitations {
			fmt.Fprintf(&output, "    limitation: %s\n", limitation)
		}
	}
	return output.String()
}

func RenderFingerprintText(snapshot *Snapshot, fingerprint string) string {
	normalized := normalizeFingerprint(fingerprint)
	locations := LocationsForFingerprint(snapshot, normalized)
	var output strings.Builder
	fmt.Fprintf(&output, "Fingerprint: %s\n", normalized)
	fmt.Fprintf(&output, "Observed on: %d access edge(s)\n", len(locations))
	if len(locations) == 0 {
		return output.String()
	}
	fmt.Fprintln(&output)
	for _, location := range locations {
		fmt.Fprintf(&output, "  %s@%s  %s:%d", location.Account, location.Alias, location.Source, location.Line)
		if location.Comment != "" {
			fmt.Fprintf(&output, "  comment=%q", location.Comment)
		}
		fmt.Fprintln(&output)
	}
	return output.String()
}

// RenderHostAccessText lists the observed account/key edges for one host.
func RenderHostAccessText(snapshot *Snapshot, alias string) (string, bool) {
	if snapshot == nil {
		return "", false
	}
	for _, host := range snapshot.Hosts {
		if host.Alias != alias {
			continue
		}
		var output strings.Builder
		fmt.Fprintf(&output, "Host: %s\n", host.Alias)
		fmt.Fprintf(&output, "Coverage: %s\n", host.Coverage)
		edges := 0
		for _, account := range host.Accounts {
			if account.Auth != nil {
				fmt.Fprintf(&output, "  account %s", account.Username)
				if account.UID != nil {
					fmt.Fprintf(&output, " uid=%d", *account.UID)
				}
				if account.Home != "" {
					fmt.Fprintf(&output, " home=%s", account.Home)
				}
				fmt.Fprintf(&output, " effective-sshd=%t\n", account.Auth.EffectiveConfig)
				for _, source := range account.Sources {
					if !source.ContentInspected {
						fmt.Fprintf(&output, "    configured source (not inspected): %s", source.Path)
						if source.Error != "" {
							fmt.Fprintf(&output, "  error=%q", source.Error)
						}
						fmt.Fprintln(&output)
					}
				}
			}
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					if entry.Fingerprint == "" {
						continue
					}
					edges++
					fmt.Fprintf(&output, "  %s  %s  %s:%d", account.Username, entry.Fingerprint, source.Path, entry.Line)
					if entry.Comment != "" {
						fmt.Fprintf(&output, "  comment=%q", entry.Comment)
					}
					fmt.Fprintln(&output)
				}
			}
		}
		fmt.Fprintf(&output, "Observed access edges: %d\n", edges)
		return output.String(), true
	}
	return "", false
}

type htmlReportData struct {
	Snapshot *Snapshot
	Rows     []htmlHostRow
}

type htmlHostRow struct {
	Alias       string
	Coverage    string
	Accounts    int
	Sources     int
	Entries     int
	Errors      []ScanError
	Limitations []string
	System      []string
}

var reportTemplate = template.Must(template.New("access-report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Access Audit {{.Snapshot.ScanID}}</title>
<style>
body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;max-width:1100px;margin:40px auto;padding:0 20px;color:#17202a;background:#f7f9fb}
h1,h2{color:#0b5269}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.card{background:white;border:1px solid #d8e1e8;border-radius:8px;padding:14px}.number{font-size:1.8rem;font-weight:700}table{width:100%;border-collapse:collapse;background:white}th,td{text-align:left;padding:9px;border-bottom:1px solid #e2e8ed;vertical-align:top}.full,.info{color:#087830}.partial,.low,.medium{color:#996400}.failed,.high,.critical{color:#b42318}.detail{font-size:.85rem;color:#596773;margin-top:4px}code{word-break:break-word}</style>
</head>
<body>
<h1>SSH Access Audit</h1>
<p><code>{{.Snapshot.ScanID}}</code> · {{.Snapshot.StartedAt}} · scope {{.Snapshot.Scope.Mode}}</p>
<h2>Overview</h2>
<div class="cards">
<div class="card"><div class="number">{{.Snapshot.Summary.HostsRequested}}</div>hosts requested</div>
<div class="card"><div class="number">{{.Snapshot.Summary.HostsPartial}}</div>partial scans</div>
<div class="card"><div class="number">{{.Snapshot.Summary.HostsFailed}}</div>failed scans</div>
<div class="card"><div class="number">{{.Snapshot.Summary.AuthorizedKeyEntries}}</div>key entries</div>
<div class="card"><div class="number">{{.Snapshot.Summary.UniqueFingerprints}}</div>unique keys</div>
<div class="card"><div class="number">{{.Snapshot.Summary.MalformedEntries}}</div>malformed entries</div>
<div class="card"><div class="number">{{.Snapshot.Summary.KeyBytesInspected}}</div>key bytes inspected</div>
<div class="card"><div class="number">{{.Snapshot.Summary.FindingsTotal}}</div>findings</div>
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>
{{range .Snapshot.Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td><code>{{.RuleID}}</code></td><td><code>{{if .Host}}{{.Host}}{{if .Account}}/{{.Account}}{{end}}{{else}}{{.Fingerprint}}{{end}}</code></td><td>{{.Title}}</td><td>{{range .Evidence}}<div class="detail">{{.}}</div>{{end}}{{if .CoverageCaveat}}<div class="detail">caveat: {{.CoverageCaveat}}</div>{{end}}</td></tr>{{end}}
</tbody></table>
<h2>Hosts</h2>
<table><thead><tr><th>Host</th><th>Coverage</th><th>Accounts</th><th>Configured sources</th><th>Entries</th><th>Details</th></tr></thead><tbody>
{{range .Rows}}<tr><td><code>{{.Alias}}</code></td><td class="{{.Coverage}}">{{.Coverage}}</td><td>{{.Accounts}}</td><td>{{.Sources}}</td><td>{{.Entries}}</td><td>{{range .System}}<div class="detail">system: {{.}}</div>{{end}}{{range .Errors}}<div class="detail">error[{{.Stage}}]: {{.Message}}</div>{{end}}{{range .Limitations}}<div class="detail">limitation: {{.}}</div>{{end}}</td></tr>{{end}}
</tbody></table>
</body></html>`))

func RenderHTML(snapshot *Snapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("snapshot is nil")
	}
	data := htmlReportData{Snapshot: snapshot}
	for _, host := range snapshot.Hosts {
		row := htmlHostRow{
			Alias:       host.Alias,
			Coverage:    host.Coverage,
			Accounts:    len(host.Accounts),
			Errors:      host.Errors,
			Limitations: host.Limitations,
		}
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				row.Sources++
				row.Entries += len(source.Entries)
			}
		}
		if host.System != nil {
			row.System = append(row.System,
				fmt.Sprintf("privilege=%s; root=%t; account-db=%s", host.System.PrivilegeMode, host.System.Root, host.System.AccountDatabase),
				fmt.Sprintf("accounts mode=%s; enumerated=%t; observed=%d; truncated=%t; limit=%d", host.System.AccountMode, host.System.AccountsEnumerated, len(host.Accounts), host.System.AccountsTruncated, host.System.AccountLimit),
				fmt.Sprintf("sshd present=%t; config-valid=%t; effective=%t", host.System.SSHD.Present, host.System.SSHD.ConfigValid, host.System.SSHD.EffectiveConfig),
			)
			if host.System.SourcesRequested > 0 {
				row.System = append(row.System, fmt.Sprintf("sources requested=%d; inspected=%d; bytes=%d; truncated=%t; budget-hit=%t",
					host.System.SourcesRequested, host.System.SourcesInspected, host.System.SourceBytesRead,
					host.System.SourcesTruncated, host.System.ContentBudgetHit))
			}
			if len(host.System.SSHD.AuthorizedKeysFiles) > 0 {
				row.System = append(row.System, "AuthorizedKeysFile="+strings.Join(host.System.SSHD.AuthorizedKeysFiles, ", "))
			}
		}
		data.Rows = append(data.Rows, row)
	}
	var output bytes.Buffer
	if err := reportTemplate.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("render HTML access report: %w", err)
	}
	return output.Bytes(), nil
}

func WriteHTMLReport(path string, snapshot *Snapshot) error {
	data, err := RenderHTML(snapshot)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}
