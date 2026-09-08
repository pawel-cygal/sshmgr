package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/humanclient"
	"github.com/systeampl/sshmgr/internal/secret"
	"golang.org/x/term"
)

type humanContext struct {
	ProfileName string
	Profile     cloudprofile.Profile
	TokenKey    string
}

func cmdHumanLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile supplying endpoint and project context")
	endpoint := fs.String("endpoint", "", "Cloud URL for a new profile (default https://sshmgr.systeam.pl)")
	organization := fs.String("organization", "", "organization to select after browser login")
	project := fs.String("project", "", "project to select after browser login")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum time to wait for browser approval")
	noBrowser := fs.Bool("no-browser", false, "print the verification URL without trying to open it")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 || *timeout <= 0 || *timeout > 15*time.Minute {
		fatal("usage: sshmgr login [--profile NAME] [--endpoint URL] [--organization ORG --project PROJECT] [--timeout 10m] [--no-browser]")
	}
	profiles, _, err := cloudprofile.Load()
	if err != nil {
		fatal(err.Error())
	}
	human, fresh, err := prepareHumanLogin(profiles, *profileName, *endpoint)
	if err != nil {
		fatal(err.Error())
	}
	if (*organization == "") != (*project == "") {
		fatal("provide --organization and --project together")
	}
	if !fresh && (*organization != "" || *project != "") {
		fatal("use `sshmgr cloud project set` to change an existing profile's project")
	}
	fmt.Printf("Signing in to %s (profile %s)\n", human.Profile.Endpoint, human.ProfileName)
	client := newHumanClient(human, "", *timeout)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	authorization, err := client.StartDeviceAuthorization(ctx)
	if err != nil {
		fatal("start human device login: " + err.Error())
	}
	fmt.Printf("Open %s\nand enter code: %s\n", authorization.VerificationURI, authorization.UserCode)
	if !*noBrowser {
		openBrowserBestEffort(authorization.VerificationURIComplete)
	}
	interval := time.Duration(authorization.Interval) * time.Second
	expires := time.NewTimer(time.Duration(authorization.ExpiresIn) * time.Second)
	defer expires.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fatal("human login timed out before approval")
		case <-expires.C:
			fatal("human device code expired; run `sshmgr login` again")
		case <-ticker.C:
			issue, err := client.ExchangeDeviceAuthorization(ctx, authorization.DeviceCode)
			if humanclient.IsCode(err, "authorization_pending") {
				continue
			}
			if err != nil {
				fatal("complete human device login: " + err.Error())
			}
			if fresh {
				selected, selectErr := chooseHumanLoginProject(issue.Session, *organization, *project, term.IsTerminal(int(os.Stdin.Fd())), os.Stdin, os.Stdout)
				if selectErr != nil {
					revokeFailedHumanLogin(human, issue.AccessToken)
					fatal(selectErr.Error())
				}
				human.Profile.Organization, human.Profile.Project = selected[0], selected[1]
			}
			if err := persistHumanLogin(human, fresh, issue.AccessToken); err != nil {
				revokeFailedHumanLogin(human, issue.AccessToken)
				fatal(err.Error())
			}
			fmt.Printf("Logged in as %s (%s). Human session stored in the OS keyring.\n", issue.Session.User.Email, issue.Session.User.DisplayName)
			printHumanProjectStatus(os.Stdout, human, issue.Session)
			fmt.Printf("Panel: %s/panel/\nNext: sshmgr whoami --profile %s\n", human.Profile.Endpoint, human.ProfileName)
			return
		}
	}
}

// Authentication and project authorization are separate. A valid human session
// remains useful for account commands even when the saved project is unavailable.
// Never silently switch the project: the profile can also be used by a runner.
func printHumanProjectStatus(output io.Writer, human humanContext, session cloudcontract.BrowserSession) {
	if !human.Profile.UsesProjectContext() {
		fmt.Fprintf(output, "Workspace: %s (legacy runner context)\n", human.Profile.Workspace)
		fmt.Fprintln(output, "Human access commands need an organization/project profile; account commands such as whoami still work.")
		printHumanSeparateProfileHint(output, human)
		return
	}
	fmt.Fprintf(output, "Project: %s/%s\n", human.Profile.Organization, human.Profile.Project)
	for _, org := range session.Organizations {
		if org.Slug != human.Profile.Organization {
			continue
		}
		for _, project := range org.Projects {
			if project.Slug == human.Profile.Project {
				fmt.Fprintln(output, "Project access: available to this account (individual actions depend on permissions).")
				return
			}
		}
	}
	fmt.Fprintln(output, "Warning: the saved project is not listed for this account. Login succeeded, but project commands may be denied.")
	fmt.Fprintln(output, "The saved project and runner credentials were not changed. Ask an administrator for access, or select an accessible project in a separate profile.")
	printHumanSeparateProfileHint(output, human)
}

func printHumanSeparateProfileHint(output io.Writer, human humanContext) {
	fmt.Fprintf(output, "Separate profile: sshmgr login --profile NEW-NAME --endpoint %s\n", human.Profile.Endpoint)
	fmt.Fprintln(output, "Replace NEW-NAME with an unused lowercase profile name; choose a project after browser approval.")
}

func revokeFailedHumanLogin(human humanContext, token string) {
	// Approval may already have exhausted the original login deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := newHumanClient(human, token, 10*time.Second).Logout(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: could not revoke the unused session; review sessions in the WebPanel.")
	}
}

func persistHumanLogin(human humanContext, fresh bool, token string) error {
	if !fresh {
		if err := secret.KeyringSet(human.TokenKey, token); err != nil {
			return fmt.Errorf("store human session in OS keyring: %w", err)
		}
		return nil
	}
	_, err := cloudprofile.UpdateWithRollback(func(cfg *cloudprofile.Config) error {
		if _, exists := cfg.Profiles[human.ProfileName]; exists {
			return errors.New("profile was created during login; retry with --profile")
		}
		return cloudprofile.Upsert(cfg, human.ProfileName, human.Profile, true)
	}, func() (func() error, error) {
		return stageHumanSession(human.TokenKey, token)
	})
	return err
}

func stageHumanSession(key, token string) (func() error, error) {
	previous, err := secret.KeyringGet(key)
	hadPrevious := err == nil
	if err != nil && !secret.IsKeyringNotFound(err) {
		return nil, fmt.Errorf("inspect human session in OS keyring: %w", err)
	}
	if err := secret.KeyringSet(key, token); err != nil {
		return nil, fmt.Errorf("store human session in OS keyring: %w", err)
	}
	return func() error {
		if hadPrevious {
			return secret.KeyringSet(key, previous)
		}
		err := secret.KeyringDelete(key)
		if secret.IsKeyringNotFound(err) {
			return nil
		}
		return err
	}, nil
}

// prepareHumanLogin never writes configuration or replaces an existing endpoint.
func prepareHumanLogin(cfg *cloudprofile.Config, name, endpoint string) (humanContext, bool, error) {
	name, endpoint = strings.TrimSpace(name), strings.TrimSpace(endpoint)
	if name == "" {
		name = cfg.ActiveProfile
	}
	if name == "" {
		name = "systeam"
	}
	if p, ok := cfg.Profiles[name]; ok {
		if endpoint != "" && endpoint != p.Endpoint {
			return humanContext{}, false, errors.New("endpoint differs from the existing profile; choose a new --profile name")
		}
		return humanContext{name, p, "sshmgr-human:" + name}, false, nil
	}
	if endpoint == "" {
		endpoint = "https://sshmgr.systeam.pl"
	}
	p := cloudprofile.Profile{Endpoint: endpoint, Organization: "pending", Project: "pending", TokenKeyring: cloudprofile.TokenKey(name)}
	if err := cloudprofile.Upsert(cloudprofile.NewConfig(), name, p, true); err != nil {
		return humanContext{}, false, err
	}
	p.Organization, p.Project = "", ""
	return humanContext{name, p, "sshmgr-human:" + name}, true, nil
}

func selectHumanLoginProject(session cloudcontract.BrowserSession, organization, project string) ([2]string, error) {
	var choices [][2]string
	var labels []string
	for _, org := range session.Organizations {
		for _, p := range org.Projects {
			labels = append(labels, org.Slug+"/"+p.Slug)
			if organization == "" || (org.Slug == organization && p.Slug == project) {
				choices = append(choices, [2]string{org.Slug, p.Slug})
			}
		}
	}
	if len(choices) == 1 {
		return choices[0], nil
	}
	if len(labels) == 0 {
		return [2]string{}, errors.New("no accessible projects; create a project in the WebPanel or ask your administrator for access, then run `sshmgr login` again")
	}
	return [2]string{}, fmt.Errorf("choose an accessible project with --organization ORG --project PROJECT and run login again; available: %s", strings.Join(labels, ", "))
}

// Only prompt on a terminal: scripts must choose their project explicitly.
func chooseHumanLoginProject(session cloudcontract.BrowserSession, organization, project string, interactive bool, input io.Reader, output io.Writer) ([2]string, error) {
	selected, err := selectHumanLoginProject(session, organization, project)
	if err == nil || !interactive || organization != "" || project != "" {
		return selected, err
	}
	var choices [][2]string
	for _, org := range session.Organizations {
		for _, p := range org.Projects {
			choices = append(choices, [2]string{org.Slug, p.Slug})
		}
	}
	if len(choices) < 2 {
		return selected, err
	}
	fmt.Fprintln(output, "\nChoose the project for this Cloud profile:")
	for i, choice := range choices {
		fmt.Fprintf(output, "  %d. %s/%s\n", i+1, choice[0], choice[1])
	}
	scanner := bufio.NewScanner(input)
	for {
		fmt.Fprintf(output, "Project [1-%d], or q to cancel: ", len(choices))
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return [2]string{}, fmt.Errorf("read project selection: %w", err)
			}
			return [2]string{}, errors.New("project selection cancelled; no new profile was saved")
		}
		answer := strings.TrimSpace(scanner.Text())
		if strings.EqualFold(answer, "q") {
			return [2]string{}, errors.New("project selection cancelled; no new profile was saved")
		}
		number, err := strconv.Atoi(answer)
		if err == nil && number >= 1 && number <= len(choices) {
			return choices[number-1], nil
		}
		fmt.Fprintln(output, "Enter a number from the list, or q to cancel.")
	}
}

func cmdHumanLogout(args []string) {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile")
	localOnly := fs.Bool("local", false, "remove only the local keyring session")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 {
		fatal("usage: sshmgr logout [--profile NAME] [--local]")
	}
	human := resolveHumanContext(*profileName)
	token, err := secret.KeyringGet(human.TokenKey)
	if err != nil {
		if secret.IsKeyringNotFound(err) {
			fmt.Println("No human session is stored for this profile.")
			return
		}
		fatal(fmt.Sprintf("read human session from OS keyring %q: %v", human.TokenKey, err))
	}
	if !*localOnly {
		client := newHumanClient(human, token, 30*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = client.Logout(ctx)
		cancel()
		if err != nil && !humanclient.IsCode(err, "human_session_required") {
			fatal("revoke human Cloud session: " + err.Error() + " (use --local only if server revocation is impossible)")
		}
	}
	if err := secret.KeyringDelete(human.TokenKey); err != nil && !secret.IsKeyringNotFound(err) {
		fatal(fmt.Sprintf("remove human session from OS keyring %q: %v", human.TokenKey, err))
	}
	fmt.Println("Logged out. The human session is no longer stored locally.")
}

func cmdHumanWhoAmI(args []string) {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile")
	jsonOutput := fs.Bool("json", false, "print session JSON")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 {
		fatal("usage: sshmgr whoami [--profile NAME] [--json]")
	}
	human, token := requireHumanSession(*profileName)
	client := newHumanClient(human, token, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	session, err := client.Session(ctx)
	cancel()
	if err != nil {
		fatal("query human Cloud session: " + err.Error())
	}
	if *jsonOutput {
		writeJSONStdout(session)
		return
	}
	fmt.Printf("%s (%s)\n", session.User.Email, session.User.DisplayName)
	printHumanProjectStatus(os.Stdout, human, *session)
	for _, organization := range session.Organizations {
		fmt.Printf("  organization %s · %s\n", organization.Slug, organization.Role)
		for _, project := range organization.Projects {
			fmt.Printf("    project %s · %s\n", project.Slug, project.Role)
		}
	}
}

func resolveHumanContext(requestedProfile string) humanContext {
	profiles, _, err := cloudprofile.Load()
	if err != nil {
		fatal(err.Error())
	}
	name, profile, err := cloudprofile.Resolve(profiles, strings.TrimSpace(requestedProfile))
	if err != nil {
		fatal(err.Error())
	}
	return humanContext{ProfileName: name, Profile: profile, TokenKey: "sshmgr-human:" + name}
}

func requireHumanProject(requestedProfile string) (humanContext, string) {
	human, token := requireHumanSession(requestedProfile)
	if !human.Profile.UsesProjectContext() {
		fatal("human access lifecycle requires an organization/project Cloud profile; legacy runner workspaces are not sufficient")
	}
	return human, token
}

func requireHumanSession(requestedProfile string) (humanContext, string) {
	human := resolveHumanContext(requestedProfile)
	token, err := secret.KeyringGet(human.TokenKey)
	if err != nil {
		if secret.IsKeyringNotFound(err) {
			fatal("no human session; run `sshmgr login` (runner tokens cannot authenticate people)")
		}
		fatal(fmt.Sprintf("read human session from OS keyring %q: %v", human.TokenKey, err))
	}
	return human, token
}

func newHumanClient(human humanContext, token string, timeout time.Duration) *humanclient.Client {
	client, err := humanclient.New(humanclient.Options{
		Endpoint: human.Profile.Endpoint, Token: token, AllowInsecureLoopback: human.Profile.AllowInsecureLoopback,
		Timeout: timeout, UserAgent: "sshmgr/" + currentBuildInfo().Version,
	})
	if err != nil {
		fatal(err.Error())
	}
	return client
}

func humanVerificationCommand(profile cloudprofile.Profile, token string) (string, error) {
	if len(token) < 32 || len(token) > 512 || strings.IndexFunc(token, func(r rune) bool {
		return r != '-' && r != '_' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
	}) >= 0 {
		return "", errors.New("Cloud returned an invalid SSH verification token")
	}
	host, port, err := humanVerificationTarget(profile)
	if err != nil {
		return "", err
	}
	destinationHost := host
	if strings.Contains(host, ":") {
		destinationHost = "[" + host + "]"
	}
	if port == 22 {
		return fmt.Sprintf("ssh %s@%s", token, destinationHost), nil
	}
	return fmt.Sprintf("ssh -p %d %s@%s", port, token, destinationHost), nil
}

func humanVerificationTarget(profile cloudprofile.Profile) (string, int, error) {
	raw := strings.TrimSpace(os.Getenv("SSHMGR_VERIFY_HOST"))
	if raw == "" {
		parsed, err := url.Parse(profile.Endpoint)
		if err != nil || parsed.Hostname() == "" {
			raw = "verify.sshmgr.cloud"
		} else if strings.HasPrefix(parsed.Hostname(), "api.") {
			raw = "verify." + strings.TrimPrefix(parsed.Hostname(), "api.")
		} else {
			raw = "verify." + parsed.Hostname()
		}
	}
	parsed, err := url.Parse("ssh://" + raw)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", 0, errors.New("SSHMGR_VERIFY_HOST must be a hostname, IP address, or host:port")
	}
	host := parsed.Hostname()
	if net.ParseIP(host) == nil && !validVerificationHostname(host) {
		return "", 0, errors.New("SSHMGR_VERIFY_HOST contains an invalid hostname")
	}
	port := 22
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("SSHMGR_VERIFY_HOST port must be between 1 and 65535")
		}
	}
	if override := strings.TrimSpace(os.Getenv("SSHMGR_VERIFY_PORT")); override != "" {
		port, err = strconv.Atoi(override)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("SSHMGR_VERIFY_PORT must be between 1 and 65535")
		}
	}
	return host, port, nil
}

func validVerificationHostname(value string) bool {
	if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
				return false
			}
		}
	}
	return true
}

func openBrowserBestEffort(target string) {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{target}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		command, args = "xdg-open", []string{target}
	}
	if err := exec.Command(command, args...).Start(); err != nil && !errors.Is(err, exec.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "[sshmgr] could not open browser automatically: %v\n", err)
	}
}

func writeJSONStdout(value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(string(data))
}
