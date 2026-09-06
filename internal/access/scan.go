package access

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/external"
	"github.com/systeampl/sshmgr/internal/sshc"
	"golang.org/x/crypto/ssh"
)

const maxAuthorizedKeysFileBytes = 16 << 20

var defaultCurrentAccountSources = []string{
	".ssh/authorized_keys",
	".ssh/authorized_keys2",
}

type ScanOptions struct {
	Parallel          int
	Timeout           time.Duration
	IncludePublicKeys bool
	Preflight         bool
	ScannerVersion    string
	Selector          string
	HostExclusions    []string
	TagExclusions     []string
	ExcludedMatched   []string
	UseSudo           bool
	AccountMode       string
	Accounts          []string
	MaxAccounts       int
	MaxSourceBytes    int64
	MaxTotalBytes     int64
}

type hostCollector func(context.Context, *config.Config, string, ScanOptions) HostSnapshot

// ScanCurrent performs an agentless, read-only inspection of the SSH account
// already used by each sshmgr host profile. This first scanner deliberately
// checks only the default per-user OpenSSH paths and therefore reports partial
// coverage until effective sshd configuration discovery is implemented.
func ScanCurrent(ctx context.Context, cfg *config.Config, aliases []string, options ScanOptions) *Snapshot {
	return scanCurrentWith(ctx, cfg, aliases, options, collectCurrentHost)
}

func scanCurrentWith(ctx context.Context, cfg *config.Config, aliases []string, options ScanOptions, collect hostCollector) *Snapshot {
	return scanWith(ctx, cfg, aliases, "current", options, collect)
}

func scanWith(ctx context.Context, cfg *config.Config, aliases []string, mode string, options ScanOptions, collect hostCollector) *Snapshot {
	started := time.Now()
	snapshot := NewSnapshot(options.ScannerVersion, Scope{
		Mode:                 mode,
		Selector:             options.Selector,
		RequestedHosts:       len(aliases),
		AccountMode:          options.AccountMode,
		RequestedAccounts:    append([]string(nil), options.Accounts...),
		MaxAccounts:          options.MaxAccounts,
		MaxSourceBytes:       options.MaxSourceBytes,
		MaxTotalSourceBytes:  options.MaxTotalBytes,
		HostExclusions:       append([]string(nil), options.HostExclusions...),
		TagExclusions:        append([]string(nil), options.TagExclusions...),
		ExcludedMatchedHosts: append([]string(nil), options.ExcludedMatched...),
		Preflight:            options.Preflight,
		IncludePublicKeys:    options.IncludePublicKeys,
	}, started)

	parallel := options.Parallel
	if parallel <= 0 {
		parallel = 4
	}
	results := make([]HostSnapshot, len(aliases))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < parallel; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				alias := aliases[index]
				if err := ctx.Err(); err != nil {
					results[index] = failedHost(alias, nil, "cancelled", err, 0)
					continue
				}
				results[index] = collect(ctx, cfg, alias, options)
			}
		}()
	}
	for index := range aliases {
		jobs <- index
	}
	close(jobs)
	workers.Wait()

	snapshot.Hosts = results
	snapshot.Finalize(time.Now())
	return snapshot
}

func collectCurrentHost(parent context.Context, cfg *config.Config, alias string, options ScanOptions) HostSnapshot {
	started := time.Now()
	resolved, ok := cfg.ResolveHost(alias)
	if !ok {
		return failedHost(alias, nil, "resolve", errors.New("alias not found"), time.Since(started))
	}
	host := HostSnapshot{
		Alias:    alias,
		Groups:   append([]string(nil), resolved.Groups...),
		Tags:     append([]string(nil), resolved.Tags...),
		Coverage: CoveragePartial,
		Limitations: []string{
			"current-account scan checks default OpenSSH key files only; effective sshd configuration was not inspected",
		},
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if resolved.External {
		return collectCurrentExternalHost(ctx, resolved, host, options, started)
	}
	if unsafeAlias := proxyCommandInChain(cfg, alias, map[string]bool{}); unsafeAlias != "" {
		return failedHost(alias, &host, "backend", fmt.Errorf("batch access scan does not support proxy_command in connection chain at %s", unsafeAlias), time.Since(started))
	}

	scanConfig := batchConfig(cfg, timeout)
	client, err := sshc.ConnectAlias(scanConfig, alias)
	if err != nil {
		return failedHost(alias, &host, "connect", err, time.Since(started))
	}
	var closeOnce sync.Once
	closeClient := func() { closeOnce.Do(func() { sshc.CloseChain(client) }) }
	defer closeClient()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closeClient()
		case <-done:
		}
	}()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		host.Limitations = append(host.Limitations, "SFTP subsystem unavailable; attempted fixed read-only SSH command fallback")
		closeClient()
		fallbackClient, fallbackConnectErr := sshc.ConnectAlias(scanConfig, alias)
		if fallbackConnectErr != nil {
			host.Errors = append(host.Errors, ScanError{Stage: "sftp", Message: err.Error()})
			return failedHost(alias, &host, "fallback-connect", fallbackConnectErr, time.Since(started))
		}
		defer sshc.CloseChain(fallbackClient)
		fallbackDone := make(chan struct{})
		defer close(fallbackDone)
		go func() {
			select {
			case <-ctx.Done():
				sshc.CloseChain(fallbackClient)
			case <-fallbackDone:
			}
		}()
		account := AccountSnapshot{Username: resolvedUsername(resolved)}
		fallbackFailures := 0
		for _, path := range defaultCurrentAccountSources {
			source := readKeySourceFallback(fallbackClient, path, options.IncludePublicKeys, options.Preflight)
			if source.Error != "" {
				fallbackFailures++
				host.Limitations = append(host.Limitations, fmt.Sprintf("could not fully inspect %s", path))
			}
			account.Sources = append(account.Sources, source)
		}
		host.Accounts = []AccountSnapshot{account}
		if fallbackFailures == len(defaultCurrentAccountSources) {
			host.Errors = append(host.Errors, ScanError{Stage: "sftp", Message: err.Error()})
			return failedHost(alias, &host, collectorUnsupportedStage, errors.New("authenticated SSH target supports neither SFTP nor the fixed read-only Unix command collectors"), time.Since(started))
		}
		host.DurationMS = time.Since(started).Milliseconds()
		return host
	}
	defer sftpClient.Close()

	username := resolvedUsername(resolved)
	if resolved.User == "" {
		host.Limitations = append(host.Limitations, "resolved SSH username is empty")
	}
	account := AccountSnapshot{Username: username}
	if home, err := sftpClient.RealPath("."); err == nil {
		account.Home = home
	} else {
		host.Limitations = append(host.Limitations, "remote home directory could not be resolved")
	}

	for _, path := range defaultCurrentAccountSources {
		source := readKeySource(sftpClient, path, options.IncludePublicKeys, options.Preflight)
		if source.Error != "" {
			host.Limitations = append(host.Limitations, fmt.Sprintf("could not fully inspect %s", path))
		}
		account.Sources = append(account.Sources, source)
	}
	host.Accounts = []AccountSnapshot{account}
	if err := ctx.Err(); err != nil {
		host.Errors = append(host.Errors, ScanError{Stage: "timeout", Message: err.Error()})
		host.Limitations = append(host.Limitations, "scan timeout interrupted remote reads")
	}
	host.DurationMS = time.Since(started).Milliseconds()
	return host
}

func collectCurrentExternalHost(ctx context.Context, resolved config.HostConfig, host HostSnapshot, options ScanOptions, started time.Time) HostSnapshot {
	account := AccountSnapshot{Username: resolvedUsername(resolved)}
	sources, err := collectExternalCurrentSources(ctx, resolved, options.IncludePublicKeys, options.Preflight)
	if err != nil {
		return failedHost(host.Alias, &host, "external-command", err, time.Since(started))
	}
	account.Sources = sources
	failures := 0
	for _, source := range sources {
		if source.Error != "" {
			failures++
			host.Limitations = append(host.Limitations, fmt.Sprintf("could not fully inspect %s", source.Path))
		}
	}
	host.Accounts = []AccountSnapshot{account}
	if err := ctx.Err(); err != nil {
		return failedHost(host.Alias, &host, "timeout", err, time.Since(started))
	}
	if failures == len(sources) {
		return failedHost(host.Alias, &host, "external-command", errors.New("all fixed read-only OpenSSH sources failed"), time.Since(started))
	}
	host.DurationMS = time.Since(started).Milliseconds()
	return host
}

func resolvedUsername(host config.HostConfig) string {
	if host.User == "" {
		return "(ssh default)"
	}
	return host.User
}

func proxyCommandInChain(cfg *config.Config, alias string, visited map[string]bool) string {
	if visited[alias] {
		return ""
	}
	visited[alias] = true
	host, ok := cfg.ResolveHost(alias)
	if !ok {
		return ""
	}
	if host.ProxyCommand != "" {
		return alias
	}
	if host.ProxyJump != "" {
		return proxyCommandInChain(cfg, host.ProxyJump, visited)
	}
	return ""
}

func batchConfig(cfg *config.Config, timeout time.Duration) *config.Config {
	clone := cfg.Clone()
	seconds := int(math.Ceil(timeout.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	for alias, host := range clone.Hosts {
		host.BatchMode = true
		if host.ConnectTimeout == 0 || host.ConnectTimeout > seconds {
			host.ConnectTimeout = seconds
		}
		clone.Hosts[alias] = host
	}
	return clone
}

func readKeySource(client *sftp.Client, path string, includePublicKeys, preflight bool) KeySource {
	source := KeySource{Type: "authorized_keys_file", Path: path}
	info, err := client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return source
		}
		source.Error = err.Error()
		return source
	}
	source.Exists = true
	source.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	source.Size = info.Size()
	if !info.Mode().IsRegular() {
		source.Error = "key source is not a regular file"
		return source
	}
	if info.Size() > maxAuthorizedKeysFileBytes {
		source.Error = fmt.Sprintf("file is %d bytes; limit is %d", info.Size(), maxAuthorizedKeysFileBytes)
		return source
	}
	if preflight {
		return source
	}

	file, err := client.Open(path)
	if err != nil {
		source.Error = err.Error()
		return source
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAuthorizedKeysFileBytes+1))
	if err != nil {
		source.Error = err.Error()
		return source
	}
	if len(data) > maxAuthorizedKeysFileBytes {
		source.Error = fmt.Sprintf("file exceeds %d bytes", maxAuthorizedKeysFileBytes)
		return source
	}
	source.ContentInspected = true
	source.ContentSHA256 = ContentDigest(data)
	entries, err := ParseAuthorizedKeys(data, includePublicKeys)
	source.Entries = entries
	if err != nil {
		source.Error = err.Error()
	}
	return source
}

const fallbackProtocolOverhead = 4096

// readKeySourceFallback supports hosts without an SFTP subsystem. Only the two
// fixed paths in defaultCurrentAccountSources are accepted; no alias, account,
// path, comment, or key material is interpolated into the remote command.
func readKeySourceFallback(client *ssh.Client, path string, includePublicKeys, preflight bool) KeySource {
	source := KeySource{Type: "authorized_keys_file", Path: path}
	command, ok := fixedReadOnlySourceCommand(path, preflight)
	if !ok {
		source.Error = "unsupported fallback key source"
		return source
	}
	data, err := runBoundedSSHCommand(client, command, maxAuthorizedKeysFileBytes+fallbackProtocolOverhead)
	if err != nil {
		source.Error = err.Error()
		return source
	}
	return parseFallbackSource(path, data, includePublicKeys, preflight)
}

func fixedReadOnlySourceCommand(path string, preflight bool) (string, bool) {
	var quotedPath string
	switch path {
	case ".ssh/authorized_keys":
		quotedPath = "'.ssh/authorized_keys'"
	case ".ssh/authorized_keys2":
		quotedPath = "'.ssh/authorized_keys2'"
	default:
		return "", false
	}
	readContent := "cat \"$p\""
	if preflight {
		readContent = ":"
	}
	// The F header declares the original byte length. In a content scan it is
	// followed immediately by exactly that many bytes. Files beyond the local
	// cap are never emitted.
	return fmt.Sprintf(`LC_ALL=C
p=%s
if [ ! -e "$p" ]; then printf 'M\n'; exit 0; fi
if [ ! -f "$p" ]; then printf 'N\n'; exit 0; fi
if [ ! -r "$p" ]; then printf 'U\n'; exit 0; fi
mode=$(stat -c '%%a' "$p" 2>/dev/null || stat -f '%%Lp' "$p" 2>/dev/null || printf 'unknown')
size=$(wc -c < "$p" 2>/dev/null | tr -d '[:space:]')
case "$size" in ''|*[!0-9]*) printf 'E\n'; exit 0;; esac
printf 'F\t%%s\t%%s\n' "$mode" "$size"
if [ "$size" -gt %d ]; then exit 0; fi
%s`, quotedPath, maxAuthorizedKeysFileBytes, readContent), true
}

func parseFallbackSource(path string, data []byte, includePublicKeys, preflight bool) KeySource {
	source := KeySource{Type: "authorized_keys_file", Path: path}
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 || lineEnd > fallbackProtocolOverhead {
		source.Error = "invalid read-only fallback response header"
		return source
	}
	header := strings.Split(string(data[:lineEnd]), "\t")
	switch header[0] {
	case "M":
		return source
	case "N":
		source.Exists = true
		source.Error = "key source is not a regular file"
		return source
	case "U":
		source.Exists = true
		source.Error = "key source is not readable"
		return source
	case "E":
		source.Exists = true
		source.Error = "could not determine key source size"
		return source
	case "F":
		if len(header) != 3 {
			source.Error = "invalid read-only fallback file header"
			return source
		}
	default:
		source.Error = "unexpected read-only fallback response"
		return source
	}
	source.Exists = true
	if header[1] != "unknown" {
		mode, err := strconv.ParseUint(header[1], 8, 32)
		if err != nil {
			source.Error = "invalid key source mode in fallback response"
			return source
		}
		source.Mode = fmt.Sprintf("%04o", mode)
	}
	size, err := strconv.ParseInt(header[2], 10, 64)
	if err != nil || size < 0 {
		source.Error = "invalid key source size in fallback response"
		return source
	}
	source.Size = size
	if size > maxAuthorizedKeysFileBytes {
		source.Error = fmt.Sprintf("file is %d bytes; limit is %d", size, maxAuthorizedKeysFileBytes)
		return source
	}
	if preflight {
		return source
	}
	content := data[lineEnd+1:]
	if int64(len(content)) != size {
		source.Error = fmt.Sprintf("fallback returned %d content bytes; expected %d", len(content), size)
		return source
	}
	source.ContentInspected = true
	source.ContentSHA256 = ContentDigest(content)
	entries, err := ParseAuthorizedKeys(content, includePublicKeys)
	source.Entries = entries
	if err != nil {
		source.Error = err.Error()
	}
	return source
}

func runBoundedSSHCommand(client *ssh.Client, command string, limit int64) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open read-only fallback session: %w", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open fallback stdout: %w", err)
	}
	stderr := &cappedBuffer{limit: 8192}
	session.Stderr = stderr
	if err := session.Start(command); err != nil {
		// Some SSH servers embed the entire rejected command in this error.
		// Snapshot artifacts intentionally retain no executed command text.
		return nil, errors.New("remote server rejected the read-only exec request")
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(data)) > limit {
		_ = session.Close()
		_ = session.Wait()
		return nil, fmt.Errorf("read-only fallback output exceeds %d bytes", limit)
	}
	waitErr := session.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read fallback output: %w", readErr)
	}
	if waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("read-only fallback failed: %v: %s", waitErr, message)
		}
		return nil, fmt.Errorf("read-only fallback failed: %w", waitErr)
	}
	return data, nil
}

func runBoundedExternalInput(ctx context.Context, host config.HostConfig, command, input string, limit int64) ([]byte, error) {
	stdout, stderr, exitCode, err := external.RunCapturedInputContext(ctx, host, command, input, limit)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("run external OpenSSH collector: %w", err)
	}
	if exitCode != 0 {
		return nil, errors.New(classifyExternalSSHFailure(exitCode, stderr))
	}
	return stdout, nil
}

func classifyExternalSSHFailure(exitCode int, stderr string) string {
	message := strings.ToLower(stderr)
	category := ""
	switch {
	case strings.Contains(message, "remote host identification has changed"),
		strings.Contains(message, "host key verification failed"):
		category = "host-key verification failed"
	case strings.Contains(message, "too many authentication failures"),
		strings.Contains(message, "permission denied"):
		category = "authentication failed"
	case strings.Contains(message, "connection refused"):
		category = "connection refused"
	case strings.Contains(message, "connection timed out"),
		strings.Contains(message, "operation timed out"):
		category = "connection timed out"
	case strings.Contains(message, "no route to host"):
		category = "no route to host"
	case strings.Contains(message, "could not resolve hostname"),
		strings.Contains(message, "name or service not known"),
		strings.Contains(message, "temporary failure in name resolution"):
		category = "hostname resolution failed"
	case strings.Contains(message, "connection reset"),
		strings.Contains(message, "kex_exchange_identification"):
		category = "connection reset during SSH handshake"
	case strings.Contains(message, "connection closed"),
		strings.Contains(message, "closed by remote host"):
		category = "connection closed by remote host"
	case strings.Contains(message, "bad configuration option"),
		strings.Contains(message, "unsupported option"):
		category = "invalid OpenSSH configuration"
	}
	if category == "" {
		return fmt.Sprintf("external OpenSSH collector exited with status %d", exitCode)
	}
	return fmt.Sprintf("external OpenSSH collector failed: %s (status %d)", category, exitCode)
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *cappedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.limit - buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = buffer.Buffer.Write(data)
	}
	return written, nil
}

func failedHost(alias string, base *HostSnapshot, stage string, err error, duration time.Duration) HostSnapshot {
	host := HostSnapshot{Alias: alias}
	if base != nil {
		host = *base
	}
	host.Coverage = CoverageFailed
	host.DurationMS = duration.Milliseconds()
	host.Errors = append(host.Errors, ScanError{Stage: stage, Message: err.Error()})
	return host
}
