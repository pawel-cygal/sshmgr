package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/humanclient"
	"github.com/systeampl/sshmgr/internal/secret"
)

type humanContext struct {
	ProfileName string
	Profile     cloudprofile.Profile
	TokenKey    string
}

func cmdHumanLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile supplying endpoint and project context")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum time to wait for browser approval")
	noBrowser := fs.Bool("no-browser", false, "print the verification URL without trying to open it")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 || *timeout <= 0 || *timeout > 15*time.Minute {
		fatal("usage: sshmgr login [--profile NAME] [--timeout 10m] [--no-browser]")
	}
	human := resolveHumanContext(*profileName)
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
			if err := secret.KeyringSet(human.TokenKey, issue.AccessToken); err != nil {
				fatal(fmt.Sprintf("store human session in OS keyring %q: %v", human.TokenKey, err))
			}
			fmt.Printf("Logged in as %s (%s). Human session stored in the OS keyring.\n", issue.Session.User.Email, issue.Session.User.DisplayName)
			return
		}
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
