// Package provision applies validated access plans through a fixed, bounded
// SSH protocol. Cloud is never involved in SSH and receives no credentials.
package provision

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/accessplan"
	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/sshc"
)

const maxAuthorizedKeysBytes = 16 << 20

type Receipt struct {
	SchemaVersion string          `json:"schema_version"`
	PlanID        string          `json:"plan_id"`
	PlanDigest    string          `json:"plan_digest"`
	StartedAt     string          `json:"started_at"`
	CompletedAt   string          `json:"completed_at"`
	Status        string          `json:"status"`
	Changes       []ChangeReceipt `json:"changes"`
	PostScanID    string          `json:"post_scan_id,omitempty"`
}

type ChangeReceipt struct {
	Host         string `json:"host"`
	Account      string `json:"account"`
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
	BackupPath   string `json:"backup_path,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

type remoteFile struct {
	content []byte
	mode    string
	uid     uint64
	gid     uint64
	exists  bool
}

type preparedChange struct {
	change       accessplan.FileChange
	before       remoteFile
	after        []byte
	receiptIndex int
}

type appliedChange struct {
	prepared preparedChange
	backup   string
}

func Apply(ctx context.Context, cfg *config.Config, plan *accessplan.Plan) (*Receipt, error) {
	if err := accessplan.Validate(plan, time.Now()); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("provisioning config is nil")
	}
	started := time.Now().UTC()
	receipt := &Receipt{SchemaVersion: "1", PlanID: plan.PlanID, PlanDigest: plan.Digest,
		StartedAt: started.Format(time.RFC3339Nano), Status: "failed", Changes: make([]ChangeReceipt, len(plan.Changes))}
	prepared := make([]preparedChange, 0, len(plan.Changes))
	// Refresh every exact file precondition before the first mutation. One stale
	// target rejects the whole plan without creating partial state.
	for index, change := range plan.Changes {
		receipt.Changes[index] = ChangeReceipt{Host: change.Host, Account: change.Account, Path: change.Path,
			BeforeSHA256: change.PreconditionSHA256, Status: "pending"}
		host, ok := cfg.ResolveHost(change.Host)
		if !ok || host.External {
			err := fmt.Errorf("host %s is missing or uses the external SSH backend", change.Host)
			receipt.Changes[index].Status, receipt.Changes[index].Error = "failed", err.Error()
			finishReceipt(receipt)
			return receipt, err
		}
		file, err := readRemoteFile(ctx, cfg, change)
		if err != nil {
			receipt.Changes[index].Status, receipt.Changes[index].Error = "failed", err.Error()
			finishReceipt(receipt)
			return receipt, err
		}
		if access.ContentDigest(file.content) != change.PreconditionSHA256 || file.exists != change.Exists {
			err := fmt.Errorf("stale plan: %s:%s changed after baseline %s", change.Host, change.Path, plan.BaselineScanID)
			receipt.Changes[index].Status, receipt.Changes[index].Error = "stale", err.Error()
			finishReceipt(receipt)
			return receipt, err
		}
		after, err := accessplan.ApplyContent(file.content, change)
		if err != nil {
			receipt.Changes[index].Status, receipt.Changes[index].Error = "failed", err.Error()
			finishReceipt(receipt)
			return receipt, err
		}
		prepared = append(prepared, preparedChange{change: change, before: file, after: after, receiptIndex: index})
	}
	applied := []appliedChange{}
	for _, item := range prepared {
		index := item.receiptIndex
		backup, afterDigest, err := writeRemoteFile(ctx, cfg, plan.PlanID, item.change, item.before, item.after)
		if err != nil {
			receipt.Changes[index].Status, receipt.Changes[index].Error = "failed", err.Error()
			rollbackApplied(ctx, cfg, applied, receipt)
			finishReceipt(receipt)
			return receipt, err
		}
		receipt.Changes[index].Status = "applied"
		receipt.Changes[index].AfterSHA256 = afterDigest
		receipt.Changes[index].BackupPath = backup
		applied = append(applied, appliedChange{prepared: item, backup: backup})
	}
	receipt.Status = "applied"
	finishReceipt(receipt)
	return receipt, nil
}

func finishReceipt(receipt *Receipt) { receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano) }

func rollbackApplied(ctx context.Context, cfg *config.Config, applied []appliedChange, receipt *Receipt) {
	for index := len(applied) - 1; index >= 0; index-- {
		item := applied[index]
		receiptIndex := item.prepared.receiptIndex
		afterDigest := access.ContentDigest(item.prepared.after)
		if err := restoreRemoteFile(ctx, cfg, item.prepared.change, item.backup, afterDigest, item.prepared.before.exists); err != nil {
			receipt.Changes[receiptIndex].Status = "rollback_failed"
			receipt.Changes[receiptIndex].Error = err.Error()
		} else {
			receipt.Changes[receiptIndex].Status = "rolled_back"
		}
	}
}

func readRemoteFile(ctx context.Context, cfg *config.Config, change accessplan.FileChange) (remoteFile, error) {
	output, err := runFixed(ctx, cfg, change.Host, readScriptCommand(), encodeLines(change.Path), maxAuthorizedKeysBytes*2)
	if err != nil {
		return remoteFile{}, fmt.Errorf("read %s:%s: %w", change.Host, change.Path, err)
	}
	lineEnd := bytes.IndexByte(output, '\n')
	if lineEnd < 0 {
		return remoteFile{}, errors.New("invalid provisioning read response")
	}
	fields := strings.Split(string(output[:lineEnd]), "\t")
	if len(fields) != 6 || fields[0] != "FILE" || fields[1] != "0" && fields[1] != "1" {
		return remoteFile{}, errors.New("invalid provisioning read metadata")
	}
	result := remoteFile{exists: fields[1] == "1", mode: fields[2]}
	result.uid, err = strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return remoteFile{}, errors.New("invalid provisioning owner UID")
	}
	result.gid, err = strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return remoteFile{}, errors.New("invalid provisioning owner GID")
	}
	size, err := strconv.Atoi(fields[5])
	if err != nil || size < 0 || size > maxAuthorizedKeysBytes {
		return remoteFile{}, errors.New("invalid provisioning file size")
	}
	encoded := strings.TrimSpace(string(output[lineEnd+1:]))
	if encoded == "" && size == 0 {
		return result, nil
	}
	result.content, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(result.content) != size {
		return remoteFile{}, errors.New("invalid provisioning file content")
	}
	return result, nil
}

func writeRemoteFile(ctx context.Context, cfg *config.Config, planID string, change accessplan.FileChange, before remoteFile, after []byte) (string, string, error) {
	mode := before.mode
	if mode == "" || mode == "-" {
		mode = change.Mode
	}
	if mode == "" {
		mode = "0600"
	}
	uid, gid := before.uid, before.gid
	if !before.exists {
		if change.OwnerUID == nil || change.OwnerGID == nil {
			return "", "", errors.New("cannot create authorized_keys without baseline owner UID/GID")
		}
		uid, gid = *change.OwnerUID, *change.OwnerGID
	}
	afterDigest := access.ContentDigest(after)
	input := encodeLines(change.Path, change.PreconditionSHA256, afterDigest, mode,
		strconv.FormatUint(uid, 10), strconv.FormatUint(gid, 10), planID, string(after))
	output, err := runFixed(ctx, cfg, change.Host, writeScriptCommand(), input, 4096)
	if err != nil {
		return "", "", fmt.Errorf("write %s:%s: %w", change.Host, change.Path, err)
	}
	fields := strings.Split(strings.TrimSpace(string(output)), "\t")
	if len(fields) != 3 || fields[0] != "OK" || fields[2] != afterDigest {
		return "", "", errors.New("remote write did not reconcile with the planned content")
	}
	backupBytes, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", "", errors.New("invalid remote backup receipt")
	}
	return string(backupBytes), afterDigest, nil
}

func restoreRemoteFile(ctx context.Context, cfg *config.Config, change accessplan.FileChange, backup, afterDigest string, existed bool) error {
	existedValue := "0"
	if existed {
		existedValue = "1"
	}
	_, err := runFixed(ctx, cfg, change.Host, restoreScriptCommand(), encodeLines(change.Path, backup, afterDigest, existedValue), 1024)
	return err
}

func runFixed(ctx context.Context, cfg *config.Config, alias, command, input string, limit int64) ([]byte, error) {
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		return nil, err
	}
	defer sshc.CloseChain(client)
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	session.Stdin = strings.NewReader(input)
	if err := session.Start(command); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	waitErr := session.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(data)) > limit {
		return nil, errors.New("remote provisioning response exceeds safety limit")
	}
	if waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = waitErr.Error()
		}
		return nil, errors.New(message)
	}
	return data, nil
}

func encodeLines(values ...string) string {
	var output strings.Builder
	for _, value := range values {
		output.WriteString(base64.StdEncoding.EncodeToString([]byte(value)))
		output.WriteByte('\n')
	}
	return output.String()
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func readScriptCommand() string    { return "sudo -n sh -c " + shellQuote(readScript) }
func writeScriptCommand() string   { return "sudo -n sh -c " + shellQuote(writeScript) }
func restoreScriptCommand() string { return "sudo -n sh -c " + shellQuote(restoreScript) }

const commonScript = `decode() { printf '%s' "$1" | base64 -d; }
safe_path() { case "$1" in /*) ;; *) return 1;; esac; case "$1" in *"\n"*|*"\r"*) return 1;; esac; }
hash_file() { if [ -f "$1" ]; then if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print "SHA256:"$1}'; else shasum -a 256 "$1" | awk '{print "SHA256:"$1}'; fi; else printf 'SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; fi; }
check_path() { walk=$1; while [ "$walk" != / ]; do if [ -L "$walk" ]; then return 1; fi; walk=${walk%/*}; [ -n "$walk" ] || walk=/; done; }
`

const readScript = commonScript + `set -eu
IFS= read -r p64; p=$(decode "$p64"); safe_path "$p"; check_path "$p"
if [ ! -e "$p" ]; then printf 'FILE\t0\t-\t0\t0\t0\n\n'; exit 0; fi
[ -f "$p" ] && [ ! -L "$p" ] && [ -r "$p" ]
meta=$(stat -c '%a %u %g %s' "$p" 2>/dev/null || stat -f '%Lp %u %g %z' "$p")
set -- $meta; [ "$4" -le 16777216 ]
printf 'FILE\t1\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; base64 < "$p" | tr -d '\n'; printf '\n'
`

const writeScript = commonScript + `set -eu
IFS= read -r p64; IFS= read -r before64; IFS= read -r after64; IFS= read -r mode64; IFS= read -r uid64; IFS= read -r gid64; IFS= read -r plan64; IFS= read -r content64
p=$(decode "$p64"); before=$(decode "$before64"); after=$(decode "$after64"); mode=$(decode "$mode64"); uid=$(decode "$uid64"); gid=$(decode "$gid64"); plan=$(decode "$plan64")
safe_path "$p"; check_path "$p"; [ "$(hash_file "$p")" = "$before" ]
parent=${p%/*}; [ -n "$parent" ] || parent=/; mkdir -p "$parent"; chmod 0700 "$parent"; chown "$uid:$gid" "$parent"
backup=-; if [ -e "$p" ]; then backup="$p.sshmgr-backup-$plan"; [ ! -e "$backup" ]; cp -p "$p" "$backup"; fi
tmp="$parent/.authorized_keys.sshmgr-$plan"; trap 'rm -f "$tmp"' EXIT HUP INT TERM
decode "$content64" > "$tmp"; chmod "$mode" "$tmp"; chown "$uid:$gid" "$tmp"; [ "$(hash_file "$tmp")" = "$after" ]
mv -f "$tmp" "$p"; trap - EXIT HUP INT TERM
if [ "$(hash_file "$p")" != "$after" ]; then if [ "$backup" = - ]; then rm -f "$p"; else mv -f "$backup" "$p"; fi; exit 74; fi
printf 'OK\t%s\t%s\n' "$(printf '%s' "$backup" | base64 | tr -d '\n')" "$after"
`

const restoreScript = commonScript + `set -eu
IFS= read -r p64; IFS= read -r backup64; IFS= read -r after64; IFS= read -r existed64
p=$(decode "$p64"); backup=$(decode "$backup64"); after=$(decode "$after64"); existed=$(decode "$existed64")
safe_path "$p"; check_path "$p"; [ "$(hash_file "$p")" = "$after" ]
if [ "$existed" = 1 ]; then [ "$backup" != - ] && [ -f "$backup" ]; mv -f "$backup" "$p"; else rm -f "$p"; fi
printf 'ROLLED_BACK\n'
`
