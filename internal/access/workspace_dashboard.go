package access

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"reflect"
	"sort"
	"strings"
)

const maxWorkspaceDashboardBytes = 256 << 20

type workspaceDashboardData struct {
	History            *WorkspaceHistory
	Latest             *Snapshot
	Graph              *AccessGraph
	Ownership          *OwnershipReview
	OwnershipHistory   *WorkspaceOwnershipHistory
	OffboardingHistory *WorkspaceOffboardingHistory
	OffboardingLatest  []WorkspaceOffboardingLatest
	Coverage           []workspaceDashboardHost
	Keys               []workspaceDashboardKey
	Offboarding        []workspaceDashboardOffboarding
	Timeline           []workspaceDashboardTimeline
}

type workspaceDashboardHost struct {
	Alias    string
	Coverage string
	Accounts int
	Entries  int
}

type workspaceDashboardKey struct {
	Fingerprint        string
	Algorithm          string
	Bits               int
	Hints              []string
	OwnershipStatus    string
	OffboardedAccess   bool
	PossessionVerified bool
	Claims             []ResolvedOwnershipClaim
	Access             []workspaceDashboardAccess
}

type workspaceDashboardAccess struct {
	Account  string
	Host     string
	Coverage string
	Source   string
	Line     int
}

type workspaceDashboardTimeline struct {
	Artifact          WorkspaceArtifact
	Latest            bool
	Transition        *WorkspaceTransition
	OwnershipReview   *OwnershipReview
	OwnershipChange   *WorkspaceOwnershipTransition
	OffboardingChecks []OffboardingCheck
}

type workspaceDashboardOffboarding struct {
	Fingerprint string
	Claims      []ResolvedOwnershipClaim
	Access      []workspaceDashboardAccess
}

var workspaceDashboardTemplate = template.Must(template.New("workspace-dashboard").Funcs(template.FuncMap{
	"join": strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>sshmgr Cloud · {{.History.Workspace}}</title>
<style>
:root{color-scheme:dark;--bg:#070b14;--panel:#101827;--panel2:#151f32;--text:#e7edf8;--muted:#94a3b8;--line:#26354d;--brand:#66e3c4;--brand2:#7bb7ff;--critical:#ff5c7a;--high:#ff8066;--medium:#ffd166;--low:#81c7ff;--info:#7fe0aa;--full:#54d69b;--partial:#ffd166;--failed:#ff6b7d}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:linear-gradient(145deg,#070b14 0%,#0b1321 45%,#07131a 100%);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}main{max-width:1440px;margin:auto;padding:28px 24px 64px}header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:24px}.eyebrow{color:var(--brand);font-weight:700;letter-spacing:.12em;text-transform:uppercase}.subtitle,.muted{color:var(--muted)}h1,h2,h3{font-family:system-ui,sans-serif}h1{font-size:34px;margin:4px 0 8px}h2{font-size:22px;margin:36px 0 14px}nav{position:sticky;top:0;z-index:2;background:#070b14e8;border:1px solid var(--line);border-radius:10px;padding:10px 14px;backdrop-filter:blur(9px)}nav a{color:var(--brand2);text-decoration:none;margin-right:18px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}.card,.notice{background:linear-gradient(145deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:10px;padding:15px}.number{font:700 27px/1 system-ui,sans-serif;margin-bottom:7px}.notice{border-left:4px solid var(--medium);margin:12px 0}.ok{border-left-color:var(--full)}table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:12px 0 24px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}th{color:var(--muted);background:#0d1523}tr:last-child td{border-bottom:0}code{color:#c8dcff;overflow-wrap:anywhere}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;margin:2px 3px 2px 0;font-size:12px}.critical{color:var(--critical);font-weight:700}.high{color:var(--high);font-weight:700}.medium,.inconclusive{color:var(--medium);font-weight:700}.low{color:var(--low)}.info,.full,.complete,.active,.owned,.possession_verified{color:var(--info)}.partial,.unknown,.shared{color:var(--partial)}.failed,.still_present,.offboarded{color:var(--failed);font-weight:700}.detail{font-size:12px;color:var(--muted);margin-top:3px}.key{margin:12px 0;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.key h3{font:600 14px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;margin:0 0 8px;overflow-wrap:anywhere}.timeline{border-left:2px solid var(--line);margin-left:8px;padding-left:20px}.event{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;margin:0 0 14px}.event:before{content:"";position:absolute;width:10px;height:10px;border-radius:50%;background:var(--brand2);left:-26px;top:20px}.event.latest:before{background:var(--brand);box-shadow:0 0 0 4px #66e3c426}.delta{font-size:15px;font-weight:700;margin-top:8px}.plus{color:var(--full)}.minus{color:var(--high)}footer{color:var(--muted);margin-top:36px;font-size:12px}@media(max-width:700px){header{display:block}main{padding:18px 12px}nav a{display:inline-block;margin:3px 12px 3px 0}th,td{padding:7px;font-size:12px}}
</style></head><body><main>
<header><div><div class="eyebrow">sshmgr Cloud · local preview</div><h1>{{.History.Workspace}}</h1><div class="subtitle">Agentless SSH access audit · latest scan <code>{{.History.LatestScanID}}</code></div></div><div class="card"><div class="muted">History artifact</div><code>{{.History.HistoryID}}</code><div class="detail">Network activity: none</div></div></header>
<nav><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#ownership">Ownership &amp; Offboarding</a><a href="#graph">Access Graph</a><a href="#timeline">Timeline</a></nav>

<section id="overview"><h2>Overview</h2><div class="cards">
<div class="card"><div class="number">{{.Latest.Summary.HostsRequested}}</div>hosts requested</div>
<div class="card"><div class="number full">{{.Latest.Summary.HostsFull}}</div>full coverage</div>
<div class="card"><div class="number partial">{{.Latest.Summary.HostsPartial}}</div>partial coverage</div>
<div class="card"><div class="number failed">{{.Latest.Summary.HostsFailed}}</div>failed hosts</div>
<div class="card"><div class="number">{{.Latest.Summary.AccountsObserved}}</div>OS accounts</div>
<div class="card"><div class="number">{{.Latest.Summary.AuthorizedKeyEntries}}</div>key entries</div>
<div class="card"><div class="number">{{.Latest.Summary.UniqueFingerprints}}</div>unique fingerprints</div>
<div class="card"><div class="number">{{.Latest.Summary.FindingsTotal}}</div>findings</div>
</div>
{{if or .Latest.Summary.HostsPartial .Latest.Summary.HostsFailed}}<div class="notice"><strong>Coverage boundary:</strong> partial or failed hosts exist. Absence of an observed key is not proof that access is absent.</div>{{else}}<div class="notice ok"><strong>Coverage:</strong> every requested host reports full coverage for this scan policy.</div>{{end}}
{{with .OwnershipHistory}}<h3>Ownership review coverage</h3><div class="cards"><div class="card"><div class="number">{{.Summary.ReviewedScans}}</div>reviewed scans</div><div class="card"><div class="number medium">{{.Summary.MissingScans}}</div>missing reviews</div><div class="card"><div class="number {{if .Latest.Current}}full{{else}}medium{{end}}">{{if .Latest.Current}}current{{else}}STALE{{end}}</div>latest ownership evidence</div><div class="card"><div class="number">{{len .Transitions}}</div>review transitions</div></div>{{if not .Latest.Current}}<div class="notice"><strong>Ownership evidence is stale.</strong> The latest ownership review does not target the workspace's current scan.</div>{{end}}{{if .Summary.MissingScans}}<div class="notice"><strong>Ownership review gaps exist.</strong> Missing scan reviews remain explicit and are not interpolated.</div>{{end}}{{end}}
{{with .OffboardingHistory}}<h3>Current offboarding outcomes</h3><div class="cards"><div class="card"><div class="number full">{{.Summary.CurrentComplete}}</div>complete</div><div class="card"><div class="number failed">{{.Summary.CurrentStillPresent}}</div>still present</div><div class="card"><div class="number medium">{{.Summary.CurrentInconclusive}}</div>inconclusive</div><div class="card"><div class="number medium">{{.Summary.Stale}}</div>stale identities</div></div>{{if .Summary.CurrentStillPresent}}<div class="notice"><strong>Access is still present.</strong> One or more current identity checks retain observed SSH access edges.</div>{{end}}{{if .Summary.CurrentInconclusive}}<div class="notice"><strong>Current evidence is inconclusive.</strong> Review blocking reasons before drawing an offboarding conclusion.</div>{{end}}{{if .Summary.Stale}}<div class="notice"><strong>Stale evidence exists.</strong> A previous complete result is not presented as current until a check targets the latest workspace scan.</div>{{end}}{{end}}
<h3>Latest host coverage</h3><table><thead><tr><th>Host</th><th>Coverage</th><th>Accounts</th><th>Observed entries</th></tr></thead><tbody>{{range .Coverage}}<tr><td><code>{{.Alias}}</code></td><td class="{{.Coverage}}">{{.Coverage}}</td><td>{{.Accounts}}</td><td>{{.Entries}}</td></tr>{{end}}</tbody></table></section>

<section id="findings"><h2>Findings</h2><div class="cards">
<div class="card"><div class="number critical">{{.Latest.Summary.FindingsCritical}}</div>critical</div><div class="card"><div class="number high">{{.Latest.Summary.FindingsHigh}}</div>high</div><div class="card"><div class="number medium">{{.Latest.Summary.FindingsMedium}}</div>medium</div><div class="card"><div class="number low">{{.Latest.Summary.FindingsLow}}</div>low</div><div class="card"><div class="number info">{{.Latest.Summary.FindingsInfo}}</div>info</div>
</div><table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Finding</th><th>Evidence and action</th></tr></thead><tbody>
{{range .Latest.Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td><code>{{.RuleID}}</code></td><td><code>{{if .Host}}{{.Host}}{{if .Account}}/{{.Account}}{{end}}{{else}}{{.Fingerprint}}{{end}}</code></td><td>{{.Title}}</td><td>{{range .Evidence}}<div>{{.}}</div>{{end}}{{if .CoverageCaveat}}<div class="detail">caveat: {{.CoverageCaveat}}</div>{{end}}{{if .RecommendedAction}}<div class="detail">action: {{.RecommendedAction}}</div>{{end}}</td></tr>{{else}}<tr><td colspan="5">No findings in the latest snapshot.</td></tr>{{end}}
</tbody></table></section>

<section id="ownership"><h2>Ownership &amp; Offboarding</h2>{{with .Ownership}}<p class="muted">Validated ownership review <code>{{.ReviewID}}</code> is bound to the latest scan. Claims are explicit assignments; possession-verified claims are shown separately.</p><div class="cards">
<div class="card"><div class="number">{{.Summary.ActiveIdentities}}</div>active identities</div><div class="card"><div class="number offboarded">{{.Summary.OffboardedIdentities}}</div>offboarded identities</div><div class="card"><div class="number owned">{{.Summary.OwnedKeys}}</div>assigned keys</div><div class="card"><div class="number unknown">{{.Summary.UnknownKeys}}</div>unknown keys</div><div class="card"><div class="number shared">{{.Summary.SharedKeys}}</div>shared keys</div><div class="card"><div class="number offboarded">{{.Summary.OffboardedAccessKeys}}</div>offboarded access keys</div><div class="card"><div class="number possession_verified">{{.Summary.PossessionVerifiedKeys}}</div>possession verified</div>
</div><h3>Ownership findings</h3><table><thead><tr><th>Severity</th><th>Rule</th><th>Fingerprint</th><th>Finding</th><th>Evidence and action</th></tr></thead><tbody>{{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td><code>{{.RuleID}}</code></td><td><code>{{.Fingerprint}}</code></td><td>{{.Title}}</td><td>{{range .Evidence}}<div>{{.}}</div>{{end}}{{if .CoverageCaveat}}<div class="detail">caveat: {{.CoverageCaveat}}</div>{{end}}{{if .RecommendedAction}}<div class="detail">action: {{.RecommendedAction}}</div>{{end}}</td></tr>{{else}}<tr><td colspan="5">No ownership findings.</td></tr>{{end}}</tbody></table><h3>Identity ownership</h3><table><thead><tr><th>Fingerprint</th><th>Observed</th><th>Ownership</th><th>Identity claims</th></tr></thead><tbody>{{range .Keys}}<tr><td><code>{{.Fingerprint}}</code></td><td>{{if .Observed}}{{.Occurrences}} edge(s) · {{len .Hosts}} host(s){{else}}mapped only{{end}}</td><td class="{{.OwnershipStatus}}">{{.OwnershipStatus}}{{if .OffboardedAccess}}<div class="offboarded">offboarded access</div>{{end}}{{if .PossessionVerified}}<div class="possession_verified">possession verified</div>{{end}}</td><td>{{range .Claims}}<div><code>{{.IdentityID}}</code>{{if .DisplayName}} · {{.DisplayName}}{{end}} · <span class="{{.IdentityStatus}}">{{.IdentityStatus}}</span> · <span class="{{.Verification}}">{{.Verification}}</span></div>{{else}}unassigned{{end}}</td></tr>{{end}}</tbody></table>
<h3>Offboarding evidence</h3>{{if $.Offboarding}}<div class="notice"><strong>Read-only evidence:</strong> these entries are an observed removal-plan input. No remote access has been changed.</div>{{range $.Offboarding}}<div class="key"><h3>{{.Fingerprint}}</h3><div>{{range .Claims}}<span class="pill offboarded"><code>{{.IdentityID}}</code>{{if .DisplayName}} ({{.DisplayName}}){{end}} · {{.Verification}}</span>{{end}}</div><table><thead><tr><th>OS account</th><th>Host</th><th>Evidence</th><th>Coverage</th></tr></thead><tbody>{{range .Access}}<tr><td><code>{{.Account}}</code></td><td><code>{{.Host}}</code></td><td><code>{{.Source}}:{{.Line}}</code></td><td class="{{.Coverage}}">{{.Coverage}}</td></tr>{{end}}</tbody></table></div>{{end}}{{else}}<div class="notice ok">No observed latest-snapshot access edge is assigned to an offboarded identity.</div>{{end}}{{else}}<div class="notice"><strong>Ownership not attached.</strong> Render again with <code>--ownership-review review.json</code> to add explicit identities and offboarding evidence. authorized_keys comments remain unverified hints.</div>{{end}}
{{with .OwnershipHistory}}<h3>Ownership review history</h3><p class="muted">Validated companion <code>{{.OwnershipHistoryID}}</code> is bound to this workspace. Unverified authorized_keys comments are removed from the artifact.</p><table><thead><tr><th>Scan</th><th>Review</th><th>Freshness</th><th>Identities</th><th>Key ownership</th><th>Findings</th></tr></thead><tbody>{{range .Reviews}}<tr><td><code>{{.ScanID}}</code></td><td><code>{{.ReviewID}}</code></td><td>{{if eq .ScanID $.History.LatestScanID}}<span class="full">current</span>{{else}}historical{{end}}</td><td>{{.Summary.ActiveIdentities}} active · {{.Summary.OffboardedIdentities}} offboarded</td><td>{{.Summary.OwnedKeys}} owned · {{.Summary.UnknownKeys}} unknown · {{.Summary.SharedKeys}} shared</td><td>{{.Summary.FindingsHigh}} high · {{.Summary.FindingsMedium}} medium</td></tr>{{end}}</tbody></table><h3>Ownership changes</h3>{{range .Transitions}}<div class="key"><h3><code>{{.BeforeScanID}}</code> → <code>{{.AfterScanID}}</code></h3><div class="detail"><code>{{.BeforeReviewID}}</code> → <code>{{.AfterReviewID}}</code></div><div class="delta">{{len .IdentityChanges}} identity · {{len .ClaimChanges}} claim · {{len .KeyChanges}} key-state changes</div>{{if .IdentityChanges}}<table><thead><tr><th>Action</th><th>Identity</th><th>Before</th><th>After</th></tr></thead><tbody>{{range .IdentityChanges}}<tr><td>{{.Action}}</td><td><code>{{.IdentityID}}</code></td><td>{{with .Before}}{{.Kind}} · {{.Status}}{{if .DisplayName}} · {{.DisplayName}}{{end}}{{else}}—{{end}}</td><td>{{with .After}}{{.Kind}} · {{.Status}}{{if .DisplayName}} · {{.DisplayName}}{{end}}{{else}}—{{end}}</td></tr>{{end}}</tbody></table>{{end}}{{if .ClaimChanges}}<table><thead><tr><th>Action</th><th>Fingerprint</th><th>Identity</th><th>Before</th><th>After</th></tr></thead><tbody>{{range .ClaimChanges}}<tr><td>{{.Action}}</td><td><code>{{.Fingerprint}}</code></td><td><code>{{.IdentityID}}</code></td><td>{{with .Before}}{{.Claim.Verification}} · {{.Claim.IdentityStatus}} · {{.Claim.Source}}{{else}}—{{end}}</td><td>{{with .After}}{{.Claim.Verification}} · {{.Claim.IdentityStatus}} · {{.Claim.Source}}{{else}}—{{end}}</td></tr>{{end}}</tbody></table>{{end}}{{if .KeyChanges}}<table><thead><tr><th>Action</th><th>Fingerprint</th><th>Before</th><th>After</th></tr></thead><tbody>{{range .KeyChanges}}<tr><td>{{.Action}}</td><td><code>{{.Fingerprint}}</code></td><td>{{with .Before}}{{.OwnershipStatus}} · {{.Occurrences}} edges{{if .OffboardedAccess}} · offboarded{{end}}{{else}}—{{end}}</td><td>{{with .After}}{{.OwnershipStatus}} · {{.Occurrences}} edges{{if .OffboardedAccess}} · offboarded{{end}}{{else}}—{{end}}</td></tr>{{end}}</tbody></table>{{end}}</div>{{else}}<div class="notice ok">Only one ownership review is attached; no review-to-review transition exists yet.</div>{{end}}{{end}}
{{with .OffboardingHistory}}<h3>Offboarding outcome history</h3><p class="muted">Validated companion <code>{{.OffboardingHistoryID}}</code> is bound to this workspace timeline. Complete means mapped static access was not observed under the check's strict boundary; it is not universal proof of removal.</p><table><thead><tr><th>Identity</th><th>Latest outcome</th><th>Freshness</th><th>Checked scan / time</th><th>Edges</th><th>Decision reasons</th></tr></thead><tbody>{{range $.OffboardingLatest}}<tr><td><code>{{.Identity.ID}}</code>{{if .Identity.DisplayName}}<div>{{.Identity.DisplayName}}</div>{{end}}</td><td class="{{.Outcome}}">{{.Outcome}}</td><td>{{if .Current}}current{{else}}<span class="medium">STALE</span>{{end}}</td><td><code>{{.AfterScanID}}</code><div class="detail">{{.AfterCompletedAt}}</div><div class="detail"><code>{{.CheckID}}</code></div></td><td>{{.BaselineAccess}} baseline · {{.StillObserved}} still · {{.NotObserved}} not observed · {{.NewlyObserved}} new</td><td>{{range .ReasonCodes}}<code>{{.}}</code><br>{{end}}{{if .BlockingReasons}}<span class="medium">{{.BlockingReasons}} blocking</span>{{end}}</td></tr>{{end}}</tbody></table>
<h3>Outcome event evidence</h3>{{range .Checks}}<div class="key"><h3><code>{{.Identity.ID}}</code> · <span class="{{.Outcome}}">{{.Outcome}}</span> · <code>{{.AfterScanID}}</code></h3><div class="detail"><code>{{.CheckID}}</code></div>{{range .Reasons}}<div class="detail"><code>{{.Code}}</code>: {{.Message}}</div>{{end}}<h3>Still observed</h3><table><thead><tr><th>Fingerprint</th><th>OS account</th><th>Host</th><th>Evidence</th></tr></thead><tbody>{{range .StillObserved}}<tr><td><code>{{.Fingerprint}}</code></td><td><code>{{.Account}}</code></td><td><code>{{.Host}}</code></td><td>{{range .Evidence}}<code>{{.Source}}:{{.Line}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</tbody></table><h3>Not observed after rescan</h3><table><thead><tr><th>Fingerprint</th><th>OS account</th><th>Host</th><th>Baseline evidence</th></tr></thead><tbody>{{range .NotObserved}}<tr><td><code>{{.Fingerprint}}</code></td><td><code>{{.Account}}</code></td><td><code>{{.Host}}</code></td><td>{{range .Evidence}}<code>{{.Source}}:{{.Line}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</tbody></table><h3>Newly observed</h3><table><thead><tr><th>Fingerprint</th><th>OS account</th><th>Host</th><th>Evidence</th></tr></thead><tbody>{{range .NewlyObserved}}<tr><td><code>{{.Fingerprint}}</code></td><td><code>{{.Account}}</code></td><td><code>{{.Host}}</code></td><td>{{range .Evidence}}<code>{{.Source}}:{{.Line}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</tbody></table></div>{{end}}{{end}}</section>

<section id="graph"><h2>Access Graph</h2><p class="muted">{{if .Ownership}}Explicit path: identity → SSH fingerprint → OS account → host.{{else}}Observed path: SSH fingerprint → OS account → host.{{end}} authorized_keys comments, when explicitly retained, remain unverified hints and are never ownership proof.</p><div class="cards"><div class="card"><div class="number">{{.Graph.Summary.Keys}}</div>keys</div><div class="card"><div class="number">{{.Graph.Summary.Accounts}}</div>account nodes</div><div class="card"><div class="number">{{.Graph.Summary.AccessEdges}}</div>access edges</div><div class="card"><div class="number">{{.Graph.Summary.IdentityHints}}</div>unverified hints</div></div>
{{range .Keys}}<div class="key"><h3>{{.Fingerprint}}</h3><div class="detail">{{.Algorithm}}{{if .Bits}} · {{.Bits}} bits{{end}}{{if .OwnershipStatus}} · ownership: <span class="{{.OwnershipStatus}}">{{.OwnershipStatus}}</span>{{end}}</div>{{if .Claims}}<div>{{range .Claims}}<span class="pill {{.IdentityStatus}}">identity: {{.IdentityID}}{{if .DisplayName}} ({{.DisplayName}}){{end}} · {{.Verification}}</span>{{end}}</div>{{end}}{{if .Hints}}<div>{{range .Hints}}<span class="pill">unverified hint: {{.}}</span>{{end}}</div>{{end}}<table><thead><tr><th>OS account</th><th>Host</th><th>Coverage</th><th>Source</th></tr></thead><tbody>{{range .Access}}<tr><td><code>{{.Account}}</code></td><td><code>{{.Host}}</code></td><td class="{{.Coverage}}">{{.Coverage}}</td><td><code>{{.Source}}:{{.Line}}</code></td></tr>{{end}}</tbody></table></div>{{else}}<div class="notice">No parsed SSH fingerprints were observed in the latest snapshot.</div>{{end}}</section>

<section id="timeline"><h2>Timeline</h2><div class="timeline">{{range .Timeline}}<div class="event{{if .Latest}} latest{{end}}"><strong>{{.Artifact.CompletedAt}}</strong>{{if .Latest}} <span class="pill">latest</span>{{end}}<div><code>{{.Artifact.ScanID}}</code> · {{.Artifact.Preview.Hosts}} hosts · {{.Artifact.Preview.Findings}} findings</div>{{with .OwnershipReview}}<div class="delta">ownership review: <code>{{.ReviewID}}</code></div><div class="detail">{{.Summary.OwnedKeys}} owned · {{.Summary.UnknownKeys}} unknown · {{.Summary.SharedKeys}} shared · {{.Summary.OffboardedAccessKeys}} offboarded access</div>{{end}}{{with .OwnershipChange}}<div class="detail">ownership delta: {{len .IdentityChanges}} identity · {{len .ClaimChanges}} claim · {{len .KeyChanges}} key-state changes</div>{{end}}{{range .OffboardingChecks}}<div class="delta {{if eq .Outcome "complete"}}full{{else if eq .Outcome "still_present"}}failed{{else}}medium{{end}}">offboarding: <code>{{.Identity.ID}}</code> · {{.Outcome}}</div><div class="detail">{{.Summary.StillObserved}} still observed · {{.Summary.NewlyObserved}} new · {{.Summary.BlockingReasons}} blocking reasons</div>{{end}}{{with .Transition}}{{if .Comparable}}<div class="delta"><span class="plus">+{{len .Added}}</span> / <span class="minus">−{{len .Removed}}</span> access edges · {{len .CoverageChanges}} coverage changes</div>{{else}}<div class="delta medium">not comparable</div><div class="detail">{{.Reason}}</div>{{end}}{{if .ExcludedHosts}}<div class="detail">diff excluded incomplete hosts: {{join .ExcludedHosts ", "}}</div>{{end}}{{if .CoverageCaveat}}<div class="detail">caveat: {{.CoverageCaveat}}</div>{{end}}{{if .Added}}<details><summary>Added access</summary>{{range .Added}}<div class="plus"><code>{{.Account}}@{{.Host}}</code> · {{.Fingerprint}}</div>{{end}}</details>{{end}}{{if .Removed}}<details><summary>Removed access</summary>{{range .Removed}}<div class="minus"><code>{{.Account}}@{{.Host}}</code> · {{.Fingerprint}}</div>{{end}}</details>{{end}}{{end}}</div>{{end}}</div></section>
<footer>Generated locally from a validated workspace-history v1 artifact. No agent, bastion, CA migration, private key, password, keyring value, remote asset, or network request is used by this report.</footer>
</main></body></html>`))

// RenderWorkspaceDashboardHTML creates a self-contained read-only projection
// of a validated workspace history. The latest snapshot drives current state;
// older plans are used only for the validated timeline.
func RenderWorkspaceDashboardHTML(history *WorkspaceHistory) ([]byte, error) {
	return RenderWorkspaceDashboardHTMLWithAuditEvidence(history, nil, nil, nil)
}

// RenderWorkspaceDashboardHTMLWithOwnership optionally joins an ownership
// review that strictly reconciles with the latest history snapshot.
func RenderWorkspaceDashboardHTMLWithOwnership(history *WorkspaceHistory, ownership *OwnershipReview) ([]byte, error) {
	return RenderWorkspaceDashboardHTMLWithAuditEvidence(history, ownership, nil, nil)
}

// RenderWorkspaceDashboardHTMLWithEvidence optionally joins the latest
// ownership review and a workspace-bound offboarding outcome history.
func RenderWorkspaceDashboardHTMLWithEvidence(history *WorkspaceHistory, ownership *OwnershipReview, offboardingHistory *WorkspaceOffboardingHistory) ([]byte, error) {
	return RenderWorkspaceDashboardHTMLWithAuditEvidence(history, ownership, nil, offboardingHistory)
}

// RenderWorkspaceDashboardHTMLWithAuditEvidence joins optional current
// ownership, ownership history, and offboarding history artifacts. Every
// companion is reconciled before any untrusted value reaches the template.
func RenderWorkspaceDashboardHTMLWithAuditEvidence(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) ([]byte, error) {
	data, err := buildWorkspaceDashboardData(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := workspaceDashboardTemplate.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("render workspace dashboard HTML: %w", err)
	}
	if output.Len() > maxWorkspaceDashboardBytes {
		return nil, fmt.Errorf("workspace dashboard is %d bytes; limit is %d", output.Len(), maxWorkspaceDashboardBytes)
	}
	return output.Bytes(), nil
}

func buildWorkspaceDashboardData(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) (*workspaceDashboardData, error) {
	if err := ValidateWorkspaceHistory(history); err != nil {
		return nil, err
	}
	if len(history.Plans) == 0 {
		return nil, errors.New("workspace history contains no plans")
	}
	latest := &history.Plans[len(history.Plans)-1].Snapshot
	if ownership != nil {
		if err := ValidateOwnershipReviewAgainstSnapshot(ownership, latest); err != nil {
			return nil, fmt.Errorf("attach ownership review: %w", err)
		}
	}
	if ownershipHistory != nil {
		if err := ValidateWorkspaceOwnershipHistoryAgainstWorkspace(ownershipHistory, history); err != nil {
			return nil, fmt.Errorf("attach ownership history: %w", err)
		}
	}
	if offboardingHistory != nil {
		if err := ValidateWorkspaceOffboardingHistoryAgainstWorkspace(offboardingHistory, history); err != nil {
			return nil, fmt.Errorf("attach offboarding history: %w", err)
		}
		if ownership != nil {
			ownershipDigest, err := offboardingDigest(ownership)
			if err != nil {
				return nil, fmt.Errorf("digest ownership review: %w", err)
			}
			for _, check := range offboardingHistory.Checks {
				if check.AfterScanID == history.LatestScanID && (check.AfterReviewID != ownership.ReviewID || check.AfterReviewSHA256 != ownershipDigest) {
					return nil, errors.New("latest offboarding check does not match the attached ownership review")
				}
			}
		}
	}
	if err := validateWorkspaceDashboardAuditJoin(ownership, ownershipHistory, offboardingHistory, history.LatestScanID); err != nil {
		return nil, err
	}
	graph, err := BuildAccessGraph(latest)
	if err != nil {
		return nil, fmt.Errorf("build workspace dashboard graph: %w", err)
	}
	data := workspaceDashboardData{History: history, Latest: latest, Graph: graph, Ownership: ownership, OwnershipHistory: ownershipHistory, OffboardingHistory: offboardingHistory}
	if offboardingHistory != nil {
		data.OffboardingLatest = offboardingHistory.Latest
	}
	data.Coverage = workspaceDashboardCoverage(latest)
	data.Keys = workspaceDashboardKeys(graph)
	if ownership != nil {
		data.Keys, data.Offboarding = workspaceDashboardOwnership(data.Keys, ownership)
	}
	for index, artifact := range history.Artifacts {
		row := workspaceDashboardTimeline{Artifact: artifact, Latest: index == len(history.Artifacts)-1}
		if index > 0 {
			row.Transition = &history.Transitions[index-1]
		}
		if offboardingHistory != nil {
			for checkIndex := range offboardingHistory.Checks {
				if offboardingHistory.Checks[checkIndex].AfterScanID == artifact.ScanID {
					row.OffboardingChecks = append(row.OffboardingChecks, offboardingHistory.Checks[checkIndex])
				}
			}
		}
		if ownershipHistory != nil {
			for reviewIndex := range ownershipHistory.Reviews {
				if ownershipHistory.Reviews[reviewIndex].ScanID == artifact.ScanID {
					row.OwnershipReview = &ownershipHistory.Reviews[reviewIndex]
					break
				}
			}
			for transitionIndex := range ownershipHistory.Transitions {
				if ownershipHistory.Transitions[transitionIndex].AfterScanID == artifact.ScanID {
					row.OwnershipChange = &ownershipHistory.Transitions[transitionIndex]
					break
				}
			}
		}
		data.Timeline = append(data.Timeline, row)
	}
	return &data, nil
}

func WriteWorkspaceDashboardHTML(path string, history *WorkspaceHistory) error {
	return WriteWorkspaceDashboardHTMLWithOwnership(path, history, nil)
}

func WriteWorkspaceDashboardHTMLWithOwnership(path string, history *WorkspaceHistory, ownership *OwnershipReview) error {
	return WriteWorkspaceDashboardHTMLWithEvidence(path, history, ownership, nil)
}

func WriteWorkspaceDashboardHTMLWithEvidence(path string, history *WorkspaceHistory, ownership *OwnershipReview, offboardingHistory *WorkspaceOffboardingHistory) error {
	return WriteWorkspaceDashboardHTMLWithAuditEvidence(path, history, ownership, nil, offboardingHistory)
}

func WriteWorkspaceDashboardHTMLWithAuditEvidence(path string, history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("workspace dashboard output path is empty")
	}
	data, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func RenderWorkspaceDashboardText(history *WorkspaceHistory, outputPath string) string {
	return RenderWorkspaceDashboardTextWithOwnership(history, nil, outputPath)
}

func RenderWorkspaceDashboardTextWithOwnership(history *WorkspaceHistory, ownership *OwnershipReview, outputPath string) string {
	return RenderWorkspaceDashboardTextWithEvidence(history, ownership, nil, outputPath)
}

func RenderWorkspaceDashboardTextWithEvidence(history *WorkspaceHistory, ownership *OwnershipReview, offboardingHistory *WorkspaceOffboardingHistory, outputPath string) string {
	return RenderWorkspaceDashboardTextWithAuditEvidence(history, ownership, nil, offboardingHistory, outputPath)
}

func RenderWorkspaceDashboardTextWithAuditEvidence(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory, outputPath string) string {
	return RenderWorkspaceDashboardExportTextWithAuditEvidence(history, ownership, ownershipHistory, offboardingHistory, outputPath, "")
}

func RenderWorkspaceDashboardExportTextWithAuditEvidence(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory, htmlPath, csvPath string) string {
	if history == nil || len(history.Plans) == 0 {
		return ""
	}
	latest := history.Plans[len(history.Plans)-1].Snapshot
	ownershipText := "not attached"
	if ownership != nil {
		ownershipText = fmt.Sprintf("%s (%d unknown, %d offboarded access)", ownership.ReviewID, ownership.Summary.UnknownKeys, ownership.Summary.OffboardedAccessKeys)
	}
	offboardingText := "not attached"
	if offboardingHistory != nil {
		offboardingText = fmt.Sprintf("%s (%d current, %d stale)", offboardingHistory.OffboardingHistoryID, offboardingHistory.Summary.CurrentComplete+offboardingHistory.Summary.CurrentStillPresent+offboardingHistory.Summary.CurrentInconclusive, offboardingHistory.Summary.Stale)
	}
	ownershipHistoryText := "not attached"
	if ownershipHistory != nil {
		freshness := "current"
		if !ownershipHistory.Latest.Current {
			freshness = "STALE"
		}
		ownershipHistoryText = fmt.Sprintf("%s (%d reviewed, %d missing, %s)", ownershipHistory.OwnershipHistoryID, ownershipHistory.Summary.ReviewedScans, ownershipHistory.Summary.MissingScans, freshness)
	}
	if htmlPath == "" {
		htmlPath = "not requested"
	}
	if csvPath == "" {
		csvPath = "not requested"
	}
	return fmt.Sprintf("Offline Cloud workspace dashboard\n\nWorkspace:        %s\nHistory:          %s\nLatest scan:      %s\nHosts / findings: %d / %d\nOwnership:        %s\nOwnership history: %s\nOffboarding:      %s\nHTML output:      %s\nCSV output:       %s\nNetwork activity: none\n", history.Workspace, history.HistoryID, history.LatestScanID, latest.Summary.HostsRequested, latest.Summary.FindingsTotal, ownershipText, ownershipHistoryText, offboardingText, htmlPath, csvPath)
}

func validateWorkspaceDashboardAuditJoin(ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory, latestScanID string) error {
	if ownershipHistory == nil {
		return nil
	}
	scans := make(map[string]WorkspaceOwnershipScan, len(ownershipHistory.Scans))
	reviews := make(map[string]*OwnershipReview, len(ownershipHistory.Reviews))
	for _, scan := range ownershipHistory.Scans {
		scans[scan.ScanID] = scan
	}
	for index := range ownershipHistory.Reviews {
		reviews[ownershipHistory.Reviews[index].ScanID] = &ownershipHistory.Reviews[index]
	}
	if ownership != nil {
		embedded := reviews[latestScanID]
		scan := scans[latestScanID]
		if embedded == nil || !scan.Reviewed {
			return errors.New("attached ownership history does not contain the latest ownership review")
		}
		normalized, err := privacyNormalizeWorkspaceOwnershipReview(ownership)
		if err != nil {
			return fmt.Errorf("normalize attached ownership review: %w", err)
		}
		digest, err := offboardingDigest(ownership)
		if err != nil {
			return fmt.Errorf("digest attached ownership review: %w", err)
		}
		if !reflect.DeepEqual(normalized, embedded) || scan.ReviewID != ownership.ReviewID || scan.ReviewSHA256 != digest {
			return errors.New("latest ownership review does not match the attached ownership history")
		}
	}
	if offboardingHistory == nil {
		return nil
	}
	for _, check := range offboardingHistory.Checks {
		before, beforeOK := scans[check.BeforeScanID]
		after, afterOK := scans[check.AfterScanID]
		if !beforeOK || !afterOK || !before.Reviewed || !after.Reviewed ||
			before.ReviewID != check.BeforeReviewID || before.ReviewSHA256 != check.BeforeReviewSHA256 ||
			after.ReviewID != check.AfterReviewID || after.ReviewSHA256 != check.AfterReviewSHA256 {
			return fmt.Errorf("offboarding check %q does not match the attached ownership history", check.CheckID)
		}
	}
	return nil
}

func workspaceDashboardCoverage(snapshot *Snapshot) []workspaceDashboardHost {
	rows := make([]workspaceDashboardHost, 0, len(snapshot.Hosts))
	for _, host := range snapshot.Hosts {
		row := workspaceDashboardHost{Alias: host.Alias, Coverage: host.Coverage, Accounts: len(host.Accounts)}
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				row.Entries += len(source.Entries)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func workspaceDashboardKeys(graph *AccessGraph) []workspaceDashboardKey {
	nodes := make(map[string]AccessGraphNode, len(graph.Nodes))
	rows := make(map[string]*workspaceDashboardKey)
	accountCoverage := make(map[string]string)
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
		if node.Kind == GraphNodeKey {
			rows[node.ID] = &workspaceDashboardKey{Fingerprint: node.Fingerprint, Algorithm: node.Algorithm, Bits: node.Bits}
		}
	}
	for _, edge := range graph.Edges {
		if edge.Kind == GraphEdgeOnHost {
			accountCoverage[edge.From] = nodes[edge.To].Coverage
		}
	}
	for _, edge := range graph.Edges {
		row := rows[edge.From]
		switch edge.Kind {
		case GraphEdgeClaims:
			if target := rows[edge.To]; target != nil {
				target.Hints = append(target.Hints, nodes[edge.From].Label)
			}
		case GraphEdgeAuthorizes:
			if row == nil {
				continue
			}
			account := nodes[edge.To]
			row.Access = append(row.Access, workspaceDashboardAccess{
				Account: account.Account, Host: account.Host,
				Coverage: accountCoverage[edge.To], Source: edge.Source, Line: edge.Line,
			})
		}
	}
	keys := make([]workspaceDashboardKey, 0, len(rows))
	for _, row := range rows {
		sort.Strings(row.Hints)
		sort.Slice(row.Access, func(i, j int) bool {
			left, right := row.Access[i], row.Access[j]
			if left.Host != right.Host {
				return left.Host < right.Host
			}
			if left.Account != right.Account {
				return left.Account < right.Account
			}
			if left.Source != right.Source {
				return left.Source < right.Source
			}
			return left.Line < right.Line
		})
		keys = append(keys, *row)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Fingerprint < keys[j].Fingerprint })
	return keys
}

func workspaceDashboardOwnership(keys []workspaceDashboardKey, review *OwnershipReview) ([]workspaceDashboardKey, []workspaceDashboardOffboarding) {
	reviewed := make(map[string]ReviewedKey, len(review.Keys))
	for _, key := range review.Keys {
		reviewed[key.Fingerprint] = key
	}
	var offboarding []workspaceDashboardOffboarding
	for index := range keys {
		reviewedKey := reviewed[keys[index].Fingerprint]
		keys[index].OwnershipStatus = reviewedKey.OwnershipStatus
		keys[index].OffboardedAccess = reviewedKey.OffboardedAccess
		keys[index].PossessionVerified = reviewedKey.PossessionVerified
		keys[index].Claims = append([]ResolvedOwnershipClaim(nil), reviewedKey.Claims...)
		if !reviewedKey.OffboardedAccess {
			continue
		}
		row := workspaceDashboardOffboarding{
			Fingerprint: keys[index].Fingerprint,
			Access:      append([]workspaceDashboardAccess(nil), keys[index].Access...),
		}
		for _, claim := range reviewedKey.Claims {
			if claim.IdentityStatus != IdentityStatusOffboarded {
				continue
			}
			row.Claims = append(row.Claims, claim)
		}
		offboarding = append(offboarding, row)
	}
	return keys, offboarding
}
