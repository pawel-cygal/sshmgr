package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/cloudclient"
	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/cloudstate"
	"github.com/systeampl/sshmgr/internal/secret"
	"golang.org/x/term"
)

func cmdCloud(args []string) {
	if len(args) == 0 {
		cloudUsage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "-h", "--help", "help":
		if len(args) == 2 && args[1] == "--all" {
			cloudAdvancedUsage(os.Stdout)
		} else if len(args) == 1 {
			cloudUsage(os.Stdout)
		} else {
			fatal("usage: sshmgr cloud help [--all]")
		}
	case "upload-plan":
		cmdCloudUploadPlan(args[1:])
	case "inspect":
		cmdCloudInspect(args[1:])
	case "history-build":
		cmdCloudHistoryBuild(args[1:])
	case "history-inspect":
		cmdCloudHistoryInspect(args[1:])
	case "ownership-history-build":
		cmdCloudOwnershipHistoryBuild(args[1:])
	case "ownership-history-inspect":
		cmdCloudOwnershipHistoryInspect(args[1:])
	case "offboarding-history-build":
		cmdCloudOffboardingHistoryBuild(args[1:])
	case "offboarding-history-inspect":
		cmdCloudOffboardingHistoryInspect(args[1:])
	case "bundle-build":
		cmdCloudBundleBuild(args[1:])
	case "bundle-inspect":
		cmdCloudBundleInspect(args[1:])
	case "dashboard":
		cmdCloudDashboard(args[1:])
	case "upload":
		cmdCloudUpload(args[1:])
	case "push":
		cmdCloudPush(args[1:])
	case "login":
		cmdCloudLogin(args[1:])
	case "status":
		cmdCloudStatus(args[1:])
	case "workspace":
		cmdCloudWorkspace(args[1:])
	case "project":
		cmdCloudProject(args[1:])
	default:
		fatal(fmt.Sprintf("unknown cloud command %q — use: login, status, project, workspace, push, upload-plan, inspect, history-build, history-inspect, ownership-history-build, ownership-history-inspect, offboarding-history-build, offboarding-history-inspect, bundle-build, bundle-inspect, dashboard, upload, or help", args[0]))
	}
}

func cloudUsage(w io.Writer) {
	fmt.Fprintln(w, "sshmgr cloud — project and runner configuration")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Start here:")
	fmt.Fprintln(w, "  sshmgr login                                  sign in as a human")
	fmt.Fprintln(w, "  sshmgr cloud project list                     list visible projects")
	fmt.Fprintln(w, "  sshmgr cloud project use PROFILE              choose a configured profile")
	fmt.Fprintln(w, "  sshmgr cloud status [--profile NAME]          check the active context")
	fmt.Fprintln(w, "  sshmgr cloud login PROFILE ...                configure a local runner token")
	fmt.Fprintln(w, "  sshmgr audit <selector> --push                review and publish evidence")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Human sessions and runner tokens are separate security planes. Private keys")
	fmt.Fprintln(w, "and usable SSH credentials are never uploaded to Cloud.")
	fmt.Fprintln(w, "Run `sshmgr cloud help --all` for bundle/history/manual-upload tools.")
}

func cloudAdvancedUsage(w io.Writer) {
	fmt.Fprintln(w, "sshmgr cloud — complete local evidence and SaaS ingestion API")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sshmgr cloud login PROFILE --endpoint URL (--organization ORG --project SLUG | --workspace SLUG)")
	fmt.Fprintln(w, "      (--token-stdin | --token-env NAME | --token-keyring NAME) [--timeout 30s] [--allow-http-loopback]")
	fmt.Fprintln(w, "  sshmgr cloud status [--profile NAME] [--json] [--timeout 30s]")
	fmt.Fprintln(w, "  sshmgr cloud project show [--profile NAME] [--json]")
	fmt.Fprintln(w, "  sshmgr cloud project list [--json] | use PROFILE | set SLUG --organization ORG [--profile NAME]")
	fmt.Fprintln(w, "  sshmgr cloud workspace show [--profile NAME] [--json]     (legacy v1 profiles)")
	fmt.Fprintln(w, "  sshmgr cloud workspace list [--json] | use PROFILE | set SLUG [--profile NAME]")
	fmt.Fprintln(w, "  sshmgr cloud push <scan.json> [--profile NAME] [--include-identity-hints] [--yes]")
	fmt.Fprintln(w, "      [--ownership-review review.json] [--ownership-history ownership-history.json]")
	fmt.Fprintln(w, "      [--offboarding-history offboarding-history.json] [--timeout 2m]")
	fmt.Fprintln(w, "      or: --endpoint URL (--organization ORG --project SLUG | --workspace SLUG)")
	fmt.Fprintln(w, "          (--token-keyring NAME | --token-env NAME) [--allow-http-loopback]")
	fmt.Fprintln(w, "  sshmgr cloud upload-plan <scan.json> --workspace SLUG --out upload-plan.json")
	fmt.Fprintln(w, "      [--include-identity-hints]")
	fmt.Fprintln(w, "  sshmgr cloud inspect <upload-plan.json>")
	fmt.Fprintln(w, "  sshmgr cloud history-build <upload-plan1.json> [...] --out history.json")
	fmt.Fprintln(w, "  sshmgr cloud history-inspect <history.json>")
	fmt.Fprintln(w, "  sshmgr cloud ownership-history-build <history.json> <review1.json> [...] --out ownership-history.json")
	fmt.Fprintln(w, "  sshmgr cloud ownership-history-inspect <ownership-history.json>")
	fmt.Fprintln(w, "  sshmgr cloud offboarding-history-build <history.json> <check1.json> [...] --out offboarding-history.json")
	fmt.Fprintln(w, "  sshmgr cloud offboarding-history-inspect <offboarding-history.json>")
	fmt.Fprintln(w, "  sshmgr cloud bundle-build <history.json> [--ownership-review review.json] [--ownership-history ownership-history.json]")
	fmt.Fprintln(w, "      [--offboarding-history offboarding-history.json] --out workspace-bundle.json")
	fmt.Fprintln(w, "  sshmgr cloud bundle-inspect <workspace-bundle.json>")
	fmt.Fprintln(w, "  sshmgr cloud upload <workspace-bundle.json> [--profile NAME] [--timeout 2m]")
	fmt.Fprintln(w, "      or: --endpoint URL (--token-keyring NAME | --token-env NAME) [--allow-http-loopback]")
	fmt.Fprintln(w, "  sshmgr cloud dashboard <history.json> [--ownership-review review.json] [--ownership-history ownership-history.json] [--offboarding-history offboarding-history.json]")
	fmt.Fprintln(w, "      [--html dashboard.html] [--csv access-review.csv] [--fail-on SEVERITY]")
	fmt.Fprintln(w, "      [--require-full] [--require-current-ownership] [--require-complete-offboarding]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Preparation, inspection, and dashboard commands create no network connection.")
	fmt.Fprintln(w, "Raw public keys are always removed. authorized_keys comments are removed")
	fmt.Fprintln(w, "unless --include-identity-hints is explicit. Private keys, passwords,")
	fmt.Fprintln(w, "keyring values, and usable SSH connection credentials are never represented.")
	fmt.Fprintln(w, "Only explicit upload/push commands send one validated bundle over HTTPS.")
	fmt.Fprintln(w, "Login and status are also explicit authenticated network operations.")
	fmt.Fprintln(w, "Profiles: $SSHMGR_CLOUD_CONFIG or the platform user config directory/sshmgr/cloud.json.")
	fmt.Fprintln(w, "Push state: $SSHMGR_CLOUD_STATE or $XDG_STATE_HOME/sshmgr/cloud.")
}

func cmdCloudUploadPlan(args []string) {
	valueFlags := map[string]bool{"-workspace": true, "--workspace": true, "-out": true, "--out": true}
	snapshotPath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if snapshotPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr cloud upload-plan <scan.json> --workspace SLUG --out upload-plan.json [--include-identity-hints]")
	}
	fs := flag.NewFlagSet("cloud upload-plan", flag.ExitOnError)
	workspace := fs.String("workspace", "", "Cloud workspace slug")
	out := fs.String("out", "", "write a private local upload plan JSON")
	includeIdentityHints := fs.Bool("include-identity-hints", false, "include unverified authorized_keys comments")
	_ = fs.Parse(flagArgs)
	*workspace = strings.TrimSpace(*workspace)
	*out = strings.TrimSpace(*out)
	if *workspace == "" || *out == "" {
		fatal("cloud upload-plan requires --workspace SLUG and --out upload-plan.json")
	}
	if sameAccessPath(snapshotPath, *out) {
		fatal("upload-plan output must not overwrite the input snapshot")
	}
	snapshot, err := access.ReadSnapshot(snapshotPath)
	if err != nil {
		fatal(err.Error())
	}
	plan, err := access.BuildUploadPlan(snapshot, *workspace, *includeIdentityHints)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteUploadPlan(*out, plan); err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderUploadPlanText(plan))
	fmt.Fprintf(os.Stderr, "[sshmgr] offline upload plan written to %s (mode 0600); network activity: none\n", *out)
}

func cmdCloudInspect(args []string) {
	if len(args) != 1 {
		fatal("usage: sshmgr cloud inspect <upload-plan.json>")
	}
	plan, err := access.ReadUploadPlan(args[0])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderUploadPlanText(plan))
}

func cmdCloudHistoryBuild(args []string) {
	paths, flagArgs := splitAccessPositionals(args, map[string]bool{"-out": true, "--out": true})
	fs := flag.NewFlagSet("cloud history-build", flag.ExitOnError)
	out := fs.String("out", "", "write a private local workspace history JSON")
	_ = fs.Parse(flagArgs)
	*out = strings.TrimSpace(*out)
	if len(paths) == 0 || *out == "" {
		fatal("usage: sshmgr cloud history-build <upload-plan1.json> [...] --out history.json")
	}
	for _, path := range paths {
		if sameAccessPath(path, *out) {
			fatal("history output must not overwrite an input upload plan")
		}
	}
	plans := make([]*access.UploadPlan, 0, len(paths))
	for _, path := range paths {
		plan, err := access.ReadUploadPlan(path)
		if err != nil {
			fatal(err.Error())
		}
		plans = append(plans, plan)
	}
	history, err := access.BuildWorkspaceHistory(plans...)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteWorkspaceHistory(*out, history); err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceHistoryText(history))
	fmt.Fprintf(os.Stderr, "[sshmgr] offline workspace history written to %s (mode 0600); network activity: none\n", *out)
}

func cmdCloudHistoryInspect(args []string) {
	if len(args) != 1 {
		fatal("usage: sshmgr cloud history-inspect <history.json>")
	}
	history, err := access.ReadWorkspaceHistory(args[0])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceHistoryText(history))
}

func cmdCloudOwnershipHistoryBuild(args []string) {
	paths, flagArgs := splitAccessPositionals(args, map[string]bool{"-out": true, "--out": true})
	fs := flag.NewFlagSet("cloud ownership-history-build", flag.ExitOnError)
	out := fs.String("out", "", "write a private local workspace ownership history JSON")
	_ = fs.Parse(flagArgs)
	*out = strings.TrimSpace(*out)
	if len(paths) < 2 || *out == "" {
		fatal("usage: sshmgr cloud ownership-history-build <history.json> <review1.json> [...] --out ownership-history.json")
	}
	for _, path := range paths {
		if sameAccessPath(path, *out) {
			fatal("ownership history output must not overwrite an input artifact")
		}
	}
	history, err := access.ReadWorkspaceHistory(paths[0])
	if err != nil {
		fatal(err.Error())
	}
	reviews := make([]*access.OwnershipReview, 0, len(paths)-1)
	for _, path := range paths[1:] {
		review, readErr := access.ReadOwnershipReview(path)
		if readErr != nil {
			fatal(readErr.Error())
		}
		reviews = append(reviews, review)
	}
	ownershipHistory, err := access.BuildWorkspaceOwnershipHistory(history, reviews...)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteWorkspaceOwnershipHistory(*out, ownershipHistory); err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceOwnershipHistoryText(ownershipHistory))
	fmt.Fprintf(os.Stderr, "[sshmgr] offline workspace ownership history written to %s (mode 0600); network activity: none\n", *out)
}

func cmdCloudOwnershipHistoryInspect(args []string) {
	if len(args) != 1 {
		fatal("usage: sshmgr cloud ownership-history-inspect <ownership-history.json>")
	}
	history, err := access.ReadWorkspaceOwnershipHistory(args[0])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceOwnershipHistoryText(history))
}

func cmdCloudOffboardingHistoryBuild(args []string) {
	paths, flagArgs := splitAccessPositionals(args, map[string]bool{"-out": true, "--out": true})
	fs := flag.NewFlagSet("cloud offboarding-history-build", flag.ExitOnError)
	out := fs.String("out", "", "write a private local workspace offboarding history JSON")
	_ = fs.Parse(flagArgs)
	*out = strings.TrimSpace(*out)
	if len(paths) < 2 || *out == "" {
		fatal("usage: sshmgr cloud offboarding-history-build <history.json> <check1.json> [...] --out offboarding-history.json")
	}
	for _, path := range paths {
		if sameAccessPath(path, *out) {
			fatal("offboarding history output must not overwrite an input artifact")
		}
	}
	history, err := access.ReadWorkspaceHistory(paths[0])
	if err != nil {
		fatal(err.Error())
	}
	checks := make([]*access.OffboardingCheck, 0, len(paths)-1)
	for _, path := range paths[1:] {
		check, readErr := access.ReadOffboardingCheck(path)
		if readErr != nil {
			fatal(readErr.Error())
		}
		checks = append(checks, check)
	}
	offboardingHistory, err := access.BuildWorkspaceOffboardingHistory(history, checks...)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteWorkspaceOffboardingHistory(*out, offboardingHistory); err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceOffboardingHistoryText(offboardingHistory))
	fmt.Fprintf(os.Stderr, "[sshmgr] offline workspace offboarding history written to %s (mode 0600); network activity: none\n", *out)
}

func cmdCloudOffboardingHistoryInspect(args []string) {
	if len(args) != 1 {
		fatal("usage: sshmgr cloud offboarding-history-inspect <offboarding-history.json>")
	}
	history, err := access.ReadWorkspaceOffboardingHistory(args[0])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceOffboardingHistoryText(history))
}

func cmdCloudBundleBuild(args []string) {
	valueFlags := map[string]bool{
		"-out": true, "--out": true,
		"-ownership-review": true, "--ownership-review": true,
		"-ownership-history": true, "--ownership-history": true,
		"-offboarding-history": true, "--offboarding-history": true,
	}
	historyPath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if historyPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr cloud bundle-build <history.json> [--ownership-review review.json] [--ownership-history ownership-history.json] [--offboarding-history offboarding-history.json] --out workspace-bundle.json")
	}
	fs := flag.NewFlagSet("cloud bundle-build", flag.ExitOnError)
	out := fs.String("out", "", "write a private deterministic workspace ingestion bundle")
	ownershipPath := fs.String("ownership-review", "", "attach a validated latest-snapshot ownership review JSON")
	ownershipHistoryPath := fs.String("ownership-history", "", "attach a validated workspace ownership history JSON")
	offboardingHistoryPath := fs.String("offboarding-history", "", "attach a validated workspace offboarding history JSON")
	_ = fs.Parse(flagArgs)
	*out = strings.TrimSpace(*out)
	*ownershipPath = strings.TrimSpace(*ownershipPath)
	*ownershipHistoryPath = strings.TrimSpace(*ownershipHistoryPath)
	*offboardingHistoryPath = strings.TrimSpace(*offboardingHistoryPath)
	if *out == "" {
		fatal("cloud bundle-build requires --out workspace-bundle.json")
	}
	for _, input := range []string{historyPath, *ownershipPath, *ownershipHistoryPath, *offboardingHistoryPath} {
		if input != "" && sameAccessPath(input, *out) {
			fatal("workspace bundle output must not overwrite an input artifact")
		}
	}
	history, err := access.ReadWorkspaceHistory(historyPath)
	if err != nil {
		fatal(err.Error())
	}
	var ownership *access.OwnershipReview
	if *ownershipPath != "" {
		ownership, err = access.ReadOwnershipReview(*ownershipPath)
		if err != nil {
			fatal(err.Error())
		}
	}
	var ownershipHistory *access.WorkspaceOwnershipHistory
	if *ownershipHistoryPath != "" {
		ownershipHistory, err = access.ReadWorkspaceOwnershipHistory(*ownershipHistoryPath)
		if err != nil {
			fatal(err.Error())
		}
	}
	var offboardingHistory *access.WorkspaceOffboardingHistory
	if *offboardingHistoryPath != "" {
		offboardingHistory, err = access.ReadWorkspaceOffboardingHistory(*offboardingHistoryPath)
		if err != nil {
			fatal(err.Error())
		}
	}
	bundle, err := access.BuildWorkspaceBundle(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteWorkspaceBundle(*out, bundle); err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceBundleText(bundle))
	fmt.Fprintf(os.Stderr, "[sshmgr] offline Cloud ingestion bundle written to %s (mode 0600); network activity: none\n", *out)
}

func cmdCloudBundleInspect(args []string) {
	if len(args) != 1 {
		fatal("usage: sshmgr cloud bundle-inspect <workspace-bundle.json>")
	}
	bundle, err := access.ReadWorkspaceBundle(args[0])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderWorkspaceBundleText(bundle))
}

func cmdCloudLogin(args []string) {
	valueFlags := map[string]bool{
		"-endpoint": true, "--endpoint": true,
		"-workspace": true, "--workspace": true,
		"-organization": true, "--organization": true,
		"-project": true, "--project": true,
		"-token-keyring": true, "--token-keyring": true,
		"-token-env": true, "--token-env": true,
		"-timeout": true, "--timeout": true,
	}
	profileName, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if profileName == "" || len(extras) > 0 {
		fatal("usage: sshmgr cloud login PROFILE --endpoint URL (--organization ORG --project SLUG | --workspace SLUG) (--token-stdin | --token-env NAME | --token-keyring NAME) [--timeout 30s] [--allow-http-loopback]")
	}
	fs := flag.NewFlagSet("cloud login", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "sshmgr Cloud API origin URL")
	workspace := fs.String("workspace", "", "legacy v1 workspace authorized for this profile")
	organization := fs.String("organization", "", "organization owning the selected project (v2)")
	project := fs.String("project", "", "project authorized for this profile (v2)")
	tokenKeyring := fs.String("token-keyring", "", "existing OS keyring entry containing the Cloud bearer token")
	tokenEnv := fs.String("token-env", "", "environment variable containing a token to store in the OS keyring")
	tokenStdin := fs.Bool("token-stdin", false, "read a token from stdin and store it in the OS keyring")
	timeout := fs.Duration("timeout", 30*time.Second, "login verification timeout")
	allowHTTPLoopback := fs.Bool("allow-http-loopback", false, "allow HTTP only to a literal loopback address for local tests")
	_ = fs.Parse(flagArgs)
	profileName = strings.TrimSpace(profileName)
	*workspace = strings.TrimSpace(*workspace)
	*organization = strings.TrimSpace(*organization)
	*project = strings.TrimSpace(*project)
	*tokenKeyring = strings.TrimSpace(*tokenKeyring)
	*tokenEnv = strings.TrimSpace(*tokenEnv)
	normalizedEndpoint, err := cloudclient.NormalizeEndpoint(*endpoint, *allowHTTPLoopback)
	if err != nil {
		fatal(err.Error())
	}
	sources := 0
	if *tokenKeyring != "" {
		sources++
	}
	if *tokenEnv != "" {
		sources++
	}
	if *tokenStdin {
		sources++
	}
	if (*organization != "") != (*project != "") {
		fatal("cloud login requires --organization and --project together")
	}
	projectContext := *organization != ""
	if projectContext == (*workspace != "") || sources != 1 {
		fatal("cloud login requires either --organization with --project or legacy --workspace, plus exactly one token source")
	}

	var token string
	storeToken := false
	keyringName := *tokenKeyring
	switch {
	case *tokenKeyring != "":
		token, err = secret.KeyringGet(*tokenKeyring)
		if err != nil {
			fatal(fmt.Sprintf("read Cloud token from keyring %q: %v", *tokenKeyring, err))
		}
	case *tokenEnv != "":
		var present bool
		token, present = os.LookupEnv(*tokenEnv)
		if !present || token == "" {
			fatal(fmt.Sprintf("Cloud token environment variable %q is unset or empty", *tokenEnv))
		}
		keyringName = cloudprofile.TokenKey(profileName)
		storeToken = true
	default:
		token, err = readCloudLoginToken()
		if err != nil {
			fatal(err.Error())
		}
		keyringName = cloudprofile.TokenKey(profileName)
		storeToken = true
	}
	loginProfile := cloudprofile.Profile{
		Endpoint: normalizedEndpoint, Workspace: *workspace, Organization: *organization, Project: *project,
		TokenKeyring: keyringName, AllowInsecureLoopback: *allowHTTPLoopback,
	}
	validationConfig := cloudprofile.NewConfig()
	if err := cloudprofile.Upsert(validationConfig, profileName, loginProfile, true); err != nil {
		fatal(err.Error())
	}

	client, err := newCloudClient(normalizedEndpoint, token, *allowHTTPLoopback, *timeout)
	if err != nil {
		fatal(err.Error())
	}
	var status *cloudclient.ServiceStatus
	if projectContext {
		status, err = client.ProjectStatus(context.Background(), *organization, *project)
	} else {
		status, err = client.Status(context.Background(), *workspace)
	}
	if err != nil {
		fatal("Cloud login verification failed: " + err.Error())
	}

	var previousToken string
	previousTokenExists := false
	if storeToken {
		if previousToken, err = secret.KeyringGet(keyringName); err == nil {
			previousTokenExists = true
		} else if !secret.IsKeyringNotFound(err) {
			fatal(fmt.Sprintf("inspect existing Cloud token in keyring %q before replacement: %v", keyringName, err))
		}
		if err := secret.KeyringSet(keyringName, token); err != nil {
			fatal("store Cloud token in OS keyring: " + err.Error())
		}
	}
	configPath, err := cloudprofile.Update(func(config *cloudprofile.Config) error {
		return cloudprofile.Upsert(config, profileName, loginProfile, true)
	})
	if err != nil {
		if storeToken {
			var rollbackErr error
			if previousTokenExists {
				rollbackErr = secret.KeyringSet(keyringName, previousToken)
			} else {
				rollbackErr = secret.KeyringDelete(keyringName)
			}
			if rollbackErr != nil && !secret.IsKeyringNotFound(rollbackErr) {
				fatal(fmt.Sprintf("save Cloud profile: %v; keyring rollback also failed: %v", err, rollbackErr))
			}
		}
		fatal("save Cloud profile: " + err.Error())
	}
	fmt.Printf("Cloud login verified\n\n")
	fmt.Printf("Profile:          %s (active)\n", profileName)
	if projectContext {
		fmt.Printf("Organization:     %s\n", *organization)
		fmt.Printf("Project:          %s\n", *project)
	} else {
		fmt.Printf("Workspace:        %s\n", *workspace)
	}
	fmt.Printf("Endpoint:         %s\n", normalizedEndpoint)
	fmt.Printf("Principal:        %s\n", status.PrincipalID)
	fmt.Printf("Service:          %s %s (%s)\n", status.Service, status.Version, status.Commit)
	fmt.Printf("Token keyring:    %s\n", keyringName)
	fmt.Printf("Profile config:   %s\n", configPath)
}

func readCloudLoginToken() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Cloud bearer token: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read Cloud token: %w", err)
		}
		return readCloudToken(strings.NewReader(string(data)))
	}
	return readCloudToken(os.Stdin)
}

func cmdCloudStatus(args []string) {
	fs := flag.NewFlagSet("cloud status", flag.ExitOnError)
	profileName := fs.String("profile", "", "named Cloud profile; defaults to active")
	asJSON := fs.Bool("json", false, "print JSON")
	timeout := fs.Duration("timeout", 30*time.Second, "status request timeout")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fatal("usage: sshmgr cloud status [--profile NAME] [--json] [--timeout 30s]")
	}
	name, profile, token := resolveCloudProfile(*profileName)
	client, err := newCloudClient(profile.Endpoint, token, profile.AllowInsecureLoopback, *timeout)
	if err != nil {
		fatal(err.Error())
	}
	var status *cloudclient.ServiceStatus
	if profile.UsesProjectContext() {
		status, err = client.ProjectStatus(context.Background(), profile.Organization, profile.Project)
	} else {
		status, err = client.Status(context.Background(), profile.Workspace)
	}
	if err != nil {
		fatal(err.Error())
	}
	if *asJSON {
		value := struct {
			Profile  string                     `json:"profile"`
			Endpoint string                     `json:"endpoint"`
			Status   *cloudclient.ServiceStatus `json:"status"`
		}{Profile: name, Endpoint: profile.Endpoint, Status: status}
		if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
			fatal(err.Error())
		}
		return
	}
	fmt.Printf("sshmgr Cloud status  %s\n\n", status.Status)
	fmt.Printf("Profile:       %s\n", name)
	if profile.UsesProjectContext() {
		fmt.Printf("Organization:  %s\n", status.Organization)
		fmt.Printf("Project:       %s\n", status.Project)
	} else {
		fmt.Printf("Workspace:     %s\n", status.Workspace)
	}
	fmt.Printf("Endpoint:      %s\n", profile.Endpoint)
	fmt.Printf("Principal:     %s\n", status.PrincipalID)
	fmt.Printf("Service:       %s %s\n", status.Service, status.Version)
	fmt.Printf("Commit:        %s\n", status.Commit)
	fmt.Printf("API / storage: %s / %s\n", status.APIVersion, status.Storage)
	fmt.Printf("Capabilities:  %s\n", strings.Join(status.Capabilities, ", "))
	if status.Policy != nil {
		if !profile.UsesProjectContext() {
			fmt.Printf("Organization:  %s\n", status.Policy.Organization)
		}
		fmt.Printf("Role:          %s\n", status.Policy.Role)
		fmt.Printf("Rate limit:    %d requests/minute\n", status.Policy.RequestsPerMinute)
		fmt.Printf("Bundle limit:  %d bytes\n", status.Policy.MaxBundleBytes)
		fmt.Printf("Storage:       %d / %d bytes (%d bundles)\n", status.Policy.StorageBytes, status.Policy.MaxStorageBytes, status.Policy.BundleCount)
		fmt.Printf("Retention:     %d days\n", status.Policy.RetentionDays)
	}
	fmt.Printf("Server time:   %s\n", status.ServerTime)
}

type cloudWorkspaceView struct {
	Name                  string `json:"name"`
	Active                bool   `json:"active"`
	Endpoint              string `json:"endpoint"`
	Workspace             string `json:"workspace,omitempty"`
	Organization          string `json:"organization,omitempty"`
	Project               string `json:"project,omitempty"`
	TokenKeyring          string `json:"token_keyring"`
	InsecureLoopbackTests bool   `json:"insecure_loopback_tests"`
}

func (view cloudWorkspaceView) contextLabel() string {
	if view.Organization != "" {
		return view.Organization + "/" + view.Project
	}
	return view.Workspace
}

func cmdCloudWorkspace(args []string) {
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	switch action {
	case "show":
		fs := flag.NewFlagSet("cloud workspace show", flag.ExitOnError)
		profileName := fs.String("profile", "", "named Cloud profile; defaults to active")
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(args)
		if fs.NArg() != 0 {
			fatal("usage: sshmgr cloud workspace show [--profile NAME] [--json]")
		}
		config, path, err := cloudprofile.Load()
		if err != nil {
			fatal(err.Error())
		}
		name, profile, err := cloudprofile.Resolve(config, *profileName)
		if err != nil {
			fatal(err.Error())
		}
		view := cloudProfileView(config, name, profile)
		writeCloudWorkspaceView(view, *asJSON)
		if !*asJSON {
			fmt.Printf("Profile config: %s\n", path)
		}
	case "list":
		fs := flag.NewFlagSet("cloud workspace list", flag.ExitOnError)
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(args)
		if fs.NArg() != 0 {
			fatal("usage: sshmgr cloud workspace list [--json]")
		}
		config, _, err := cloudprofile.Load()
		if err != nil {
			fatal(err.Error())
		}
		names := make([]string, 0, len(config.Profiles))
		for name := range config.Profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		views := make([]cloudWorkspaceView, 0, len(names))
		for _, name := range names {
			views = append(views, cloudProfileView(config, name, config.Profiles[name]))
		}
		if *asJSON {
			if err := json.NewEncoder(os.Stdout).Encode(views); err != nil {
				fatal(err.Error())
			}
			return
		}
		if len(views) == 0 {
			fmt.Println("no Cloud profiles; run `sshmgr cloud login PROFILE ...`")
			return
		}
		for _, view := range views {
			marker := " "
			if view.Active {
				marker = "*"
			}
			fmt.Printf("%s %-20s %-24s %s\n", marker, view.Name, view.contextLabel(), view.Endpoint)
		}
	case "use":
		if len(args) != 1 {
			fatal("usage: sshmgr cloud workspace use PROFILE")
		}
		path, err := cloudprofile.Update(func(config *cloudprofile.Config) error { return cloudprofile.SetActive(config, args[0]) })
		if err != nil {
			fatal(err.Error())
		}
		fmt.Printf("active Cloud profile: %s\nprofile config: %s\n", strings.TrimSpace(args[0]), path)
	case "set":
		valueFlags := map[string]bool{"-profile": true, "--profile": true}
		workspace, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
		fs := flag.NewFlagSet("cloud workspace set", flag.ExitOnError)
		profileName := fs.String("profile", "", "named Cloud profile; defaults to active")
		_ = fs.Parse(flagArgs)
		if workspace == "" || len(extras) > 0 {
			fatal("usage: sshmgr cloud workspace set SLUG [--profile NAME]")
		}
		path, err := cloudprofile.Update(func(config *cloudprofile.Config) error {
			return cloudprofile.SetWorkspace(config, *profileName, workspace)
		})
		if err != nil {
			fatal(err.Error())
		}
		fmt.Printf("Cloud workspace updated to %s\nprofile config: %s\nrun `sshmgr cloud status` to verify authorization\n", workspace, path)
	default:
		fatal("usage: sshmgr cloud workspace [show|list|use PROFILE|set SLUG] [--profile NAME] [--json]")
	}
}

func cmdCloudProject(args []string) {
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	switch action {
	case "show", "list", "use":
		cmdCloudWorkspace(append([]string{action}, args...))
	case "set":
		valueFlags := map[string]bool{
			"-profile": true, "--profile": true,
			"-organization": true, "--organization": true,
		}
		project, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
		fs := flag.NewFlagSet("cloud project set", flag.ExitOnError)
		profileName := fs.String("profile", "", "named Cloud profile; defaults to active")
		organization := fs.String("organization", "", "organization owning the selected project")
		_ = fs.Parse(flagArgs)
		*organization = strings.TrimSpace(*organization)
		if project == "" || *organization == "" || len(extras) > 0 {
			fatal("usage: sshmgr cloud project set SLUG --organization ORG [--profile NAME]")
		}
		path, err := cloudprofile.Update(func(config *cloudprofile.Config) error {
			return cloudprofile.SetProject(config, *profileName, *organization, project)
		})
		if err != nil {
			fatal(err.Error())
		}
		fmt.Printf("Cloud project updated to %s/%s\nprofile config: %s\nrun `sshmgr cloud status` to verify authorization\n", *organization, project, path)
	default:
		fatal("usage: sshmgr cloud project [show|list|use PROFILE|set SLUG --organization ORG] [--profile NAME] [--json]")
	}
}

func cloudProfileView(config *cloudprofile.Config, name string, profile cloudprofile.Profile) cloudWorkspaceView {
	return cloudWorkspaceView{
		Name: name, Active: config.ActiveProfile == name, Endpoint: profile.Endpoint,
		Workspace: profile.Workspace, Organization: profile.Organization, Project: profile.Project,
		TokenKeyring: profile.TokenKeyring, InsecureLoopbackTests: profile.AllowInsecureLoopback,
	}
}

func writeCloudWorkspaceView(view cloudWorkspaceView, asJSON bool) {
	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(view); err != nil {
			fatal(err.Error())
		}
		return
	}
	active := "no"
	if view.Active {
		active = "yes"
	}
	fmt.Printf("Cloud profile\n\n")
	fmt.Printf("Name / active:  %s / %s\n", view.Name, active)
	if view.Organization != "" {
		fmt.Printf("Organization:   %s\n", view.Organization)
		fmt.Printf("Project:        %s\n", view.Project)
	} else {
		fmt.Printf("Workspace:      %s (legacy v1)\n", view.Workspace)
	}
	fmt.Printf("Endpoint:       %s\n", view.Endpoint)
	fmt.Printf("Token keyring:  %s\n", view.TokenKeyring)
	fmt.Printf("HTTP loopback:  %t (tests only)\n", view.InsecureLoopbackTests)
}

func readCloudToken(reader io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 514))
	if err != nil {
		return "", fmt.Errorf("read Cloud token: %w", err)
	}
	data = []byte(strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"))
	if len(data) == 0 || len(data) > 512 {
		return "", errors.New("Cloud token from stdin must be 1-512 bytes")
	}
	return string(data), nil
}

func resolveCloudProfile(requested string) (string, cloudprofile.Profile, string) {
	config, _, err := cloudprofile.Load()
	if err != nil {
		fatal(err.Error())
	}
	name, profile, err := cloudprofile.Resolve(config, requested)
	if err != nil {
		fatal(err.Error())
	}
	token, err := secret.KeyringGet(profile.TokenKeyring)
	if err != nil {
		fatal(fmt.Sprintf("read Cloud token for profile %q from keyring %q: %v", name, profile.TokenKeyring, err))
	}
	return name, profile, token
}

func newCloudClient(endpoint, token string, allowHTTPLoopback bool, timeout time.Duration) (*cloudclient.Client, error) {
	info := currentBuildInfo()
	return cloudclient.New(cloudclient.Options{
		Endpoint: endpoint, Token: token, AllowInsecureLoopback: allowHTTPLoopback,
		Timeout: timeout, UserAgent: "sshmgr/" + info.Version + " (" + info.Commit + ")",
	})
}

type cloudPushDestination struct {
	ProfileName       string
	StateScope        string
	Endpoint          string
	Organization      string
	Project           string
	Workspace         string
	TokenKeyring      string
	TokenEnvironment  string
	AllowHTTPLoopback bool
}

func (destination cloudPushDestination) workspace() string {
	if destination.Project != "" {
		return destination.Project
	}
	return destination.Workspace
}

func (destination cloudPushDestination) stateContext() cloudstate.Context {
	return cloudstate.Context{
		Scope: destination.StateScope, Organization: destination.Organization,
		Project: destination.Project, Workspace: destination.Workspace,
	}
}

func (destination cloudPushDestination) token() (string, error) {
	if destination.TokenKeyring != "" {
		token, err := secret.KeyringGet(destination.TokenKeyring)
		if err != nil {
			return "", fmt.Errorf("read Cloud token from keyring %q: %w", destination.TokenKeyring, err)
		}
		return token, nil
	}
	token, present := os.LookupEnv(destination.TokenEnvironment)
	if !present || token == "" {
		return "", fmt.Errorf("Cloud token environment variable %q is unset or empty", destination.TokenEnvironment)
	}
	return token, nil
}

func resolveCloudPushDestination(profileName, endpoint, organization, project, workspace, tokenKeyring, tokenEnv string, allowHTTPLoopback bool) (cloudPushDestination, error) {
	profileName = strings.TrimSpace(profileName)
	endpoint = strings.TrimSpace(endpoint)
	organization = strings.TrimSpace(organization)
	project = strings.TrimSpace(project)
	workspace = strings.TrimSpace(workspace)
	tokenKeyring = strings.TrimSpace(tokenKeyring)
	tokenEnv = strings.TrimSpace(tokenEnv)
	manual := endpoint != "" || organization != "" || project != "" || workspace != "" || tokenKeyring != "" || tokenEnv != "" || allowHTTPLoopback
	if !manual {
		config, _, err := cloudprofile.Load()
		if err != nil {
			return cloudPushDestination{}, err
		}
		name, profile, err := cloudprofile.Resolve(config, profileName)
		if err != nil {
			return cloudPushDestination{}, err
		}
		return cloudPushDestination{
			ProfileName: name, StateScope: name, Endpoint: profile.Endpoint,
			Organization: profile.Organization, Project: profile.Project, Workspace: profile.Workspace,
			TokenKeyring: profile.TokenKeyring, AllowHTTPLoopback: profile.AllowInsecureLoopback,
		}, nil
	}
	if profileName != "" {
		return cloudPushDestination{}, errors.New("Cloud push accepts either a named profile or a manual endpoint/context, not both")
	}
	if endpoint == "" || (tokenKeyring == "") == (tokenEnv == "") {
		return cloudPushDestination{}, errors.New("manual Cloud push requires --endpoint and exactly one token source")
	}
	if (organization == "") != (project == "") {
		return cloudPushDestination{}, errors.New("manual v2 Cloud push requires --organization and --project together")
	}
	projectContext := organization != ""
	if projectContext == (workspace != "") {
		return cloudPushDestination{}, errors.New("manual Cloud push requires either --organization/--project or legacy --workspace")
	}
	normalized, err := cloudclient.NormalizeEndpoint(endpoint, allowHTTPLoopback)
	if err != nil {
		return cloudPushDestination{}, err
	}
	return cloudPushDestination{
		StateScope: cloudstate.ManualScope(normalized), Endpoint: normalized,
		Organization: organization, Project: project, Workspace: workspace,
		TokenKeyring: tokenKeyring, TokenEnvironment: tokenEnv, AllowHTTPLoopback: allowHTTPLoopback,
	}, nil
}

func cmdCloudPush(args []string) {
	valueFlags := map[string]bool{
		"-profile": true, "--profile": true,
		"-endpoint": true, "--endpoint": true,
		"-organization": true, "--organization": true,
		"-project": true, "--project": true,
		"-workspace": true, "--workspace": true,
		"-token-keyring": true, "--token-keyring": true,
		"-token-env": true, "--token-env": true,
		"-timeout": true, "--timeout": true,
		"-ownership-review": true, "--ownership-review": true,
		"-ownership-history": true, "--ownership-history": true,
		"-offboarding-history": true, "--offboarding-history": true,
	}
	snapshotPath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if snapshotPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr cloud push <scan.json> [--profile NAME] [evidence] [--include-identity-hints] [--yes] [--timeout 2m] or --endpoint URL with context and one token source")
	}
	fs := flag.NewFlagSet("cloud push", flag.ExitOnError)
	profileName := fs.String("profile", "", "named Cloud profile; defaults to active when no manual endpoint is supplied")
	endpoint := fs.String("endpoint", "", "manual sshmgr Cloud API origin URL")
	organization := fs.String("organization", "", "manual v2 upload organization")
	project := fs.String("project", "", "manual v2 upload project")
	workspace := fs.String("workspace", "", "manual legacy v1 workspace")
	tokenKeyring := fs.String("token-keyring", "", "manual OS keyring entry containing the Cloud bearer token")
	tokenEnv := fs.String("token-env", "", "manual environment variable containing the Cloud bearer token")
	timeout := fs.Duration("timeout", 2*time.Minute, "whole upload timeout")
	ownershipPath := fs.String("ownership-review", "", "attach a validated latest-snapshot ownership review")
	ownershipHistoryPath := fs.String("ownership-history", "", "attach a validated workspace ownership history")
	offboardingHistoryPath := fs.String("offboarding-history", "", "attach a validated workspace offboarding history")
	includeIdentityHints := fs.Bool("include-identity-hints", false, "include unverified authorized_keys comments")
	allowHTTPLoopback := fs.Bool("allow-http-loopback", false, "allow HTTP only to a literal loopback address for local E2E")
	yes := fs.Bool("yes", false, "confirm upload non-interactively after printing the privacy preview")
	_ = fs.Parse(flagArgs)
	if *timeout <= 0 || *timeout > 10*time.Minute {
		fatal("Cloud push timeout must be greater than zero and at most 10m")
	}
	destination, err := resolveCloudPushDestination(*profileName, *endpoint, *organization, *project, *workspace, *tokenKeyring, *tokenEnv, *allowHTTPLoopback)
	if err != nil {
		fatal(err.Error())
	}
	paths, err := cloudstate.Resolve(destination.stateContext())
	if err != nil {
		fatal(err.Error())
	}
	lock, err := cloudstate.Acquire(paths)
	if err != nil {
		fatal(err.Error())
	}
	defer lock.Close()

	snapshot, err := access.ReadSnapshot(snapshotPath)
	if err != nil {
		fatal(err.Error())
	}
	plan, err := access.BuildUploadPlan(snapshot, destination.workspace(), *includeIdentityHints)
	if err != nil {
		fatal(err.Error())
	}
	existing, err := cloudstate.LoadHistory(paths)
	if err != nil {
		fatal(err.Error())
	}
	plans := []*access.UploadPlan{plan}
	if existing != nil {
		plans = make([]*access.UploadPlan, 0, len(existing.Plans)+1)
		for index := range existing.Plans {
			plans = append(plans, &existing.Plans[index])
		}
		plans = append(plans, plan)
	}
	history, err := access.BuildWorkspaceHistory(plans...)
	if err != nil {
		fatal(err.Error())
	}
	var ownership *access.OwnershipReview
	if value := strings.TrimSpace(*ownershipPath); value != "" {
		ownership, err = access.ReadOwnershipReview(value)
		if err != nil {
			fatal(err.Error())
		}
	}
	var ownershipHistory *access.WorkspaceOwnershipHistory
	if value := strings.TrimSpace(*ownershipHistoryPath); value != "" {
		ownershipHistory, err = access.ReadWorkspaceOwnershipHistory(value)
		if err != nil {
			fatal(err.Error())
		}
	}
	var offboardingHistory *access.WorkspaceOffboardingHistory
	if value := strings.TrimSpace(*offboardingHistoryPath); value != "" {
		offboardingHistory, err = access.ReadWorkspaceOffboardingHistory(value)
		if err != nil {
			fatal(err.Error())
		}
	}
	bundle, err := access.BuildWorkspaceBundle(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		fatal(err.Error())
	}

	fmt.Println("Cloud push privacy preview")
	fmt.Println()
	fmt.Print(access.RenderUploadPlanText(plan))
	fmt.Println()
	fmt.Print(access.RenderWorkspaceBundleText(bundle))
	fmt.Printf("\nLocal project state after success: %s\n", paths.Root)
	if !*yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fatal("Cloud push requires --yes when stdin is not an interactive terminal")
		}
		confirmed, confirmErr := confirmCloudPush(os.Stdin, os.Stderr, destination)
		if confirmErr != nil {
			fatal(confirmErr.Error())
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "[sshmgr] Cloud push canceled; no network request and no project-state change")
			return
		}
	}
	token, err := destination.token()
	if err != nil {
		fatal(err.Error())
	}
	result, err := uploadCloudBundle(bundle, destination.Endpoint, destination.Organization, destination.Project, token, destination.AllowHTTPLoopback, *timeout)
	if err != nil {
		fatal(err.Error())
	}
	artifacts, err := cloudstate.Commit(paths, plan, history, bundle)
	if err != nil {
		fatal(fmt.Sprintf("Cloud upload returned %s, but local project state could not be committed: %v; rerun the same push safely", result.Status, err))
	}
	writeCloudUploadResult(result)
	fmt.Printf("\nLocal push state\n  plan:    %s\n  history: %s\n  bundle:  %s\n", artifacts.Plan, artifacts.History, artifacts.Bundle)
}

func confirmCloudPush(reader io.Reader, writer io.Writer, destination cloudPushDestination) (bool, error) {
	target := destination.Workspace
	if destination.Organization != "" {
		target = destination.Organization + "/" + destination.Project
	}
	fmt.Fprintf(writer, "\nType `upload` to send this bundle to %s at %s: ", target, destination.Endpoint)
	line, err := bufio.NewReader(io.LimitReader(reader, 65)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read Cloud push confirmation: %w", err)
	}
	if len(line) > 64 {
		return false, errors.New("Cloud push confirmation is too long")
	}
	return strings.TrimSpace(line) == "upload", nil
}

func uploadCloudBundle(bundle *access.WorkspaceBundle, endpoint, organization, project, token string, allowHTTPLoopback bool, timeout time.Duration) (*cloudclient.UploadResult, error) {
	client, err := newCloudClient(endpoint, token, allowHTTPLoopback, timeout)
	if err != nil {
		return nil, err
	}
	if organization != "" {
		fmt.Fprintf(os.Stderr, "[sshmgr] uploading validated bundle %s to project %s/%s at %s\n", bundle.BundleID, organization, project, endpoint)
		return client.UploadProjectBundle(context.Background(), organization, project, bundle)
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] uploading validated bundle %s to workspace %s at %s\n", bundle.BundleID, bundle.Workspace, endpoint)
	return client.UploadBundle(context.Background(), bundle)
}

func writeCloudUploadResult(result *cloudclient.UploadResult) {
	fmt.Printf("Cloud bundle upload  %s\n\n", result.Status)
	fmt.Printf("Workspace:       %s\n", result.Bundle.Workspace)
	fmt.Printf("Bundle:          %s\n", result.Bundle.BundleID)
	fmt.Printf("Latest scan:     %s\n", result.Bundle.LatestScanID)
	fmt.Printf("Payload SHA-256: %s\n", result.Bundle.PayloadSHA256)
	fmt.Printf("Received at:     %s\n", result.Bundle.ReceivedAt)
	fmt.Printf("Principal:       %s\n", result.Bundle.PrincipalID)
}

func cmdCloudUpload(args []string) {
	valueFlags := map[string]bool{
		"-profile": true, "--profile": true,
		"-endpoint": true, "--endpoint": true,
		"-organization": true, "--organization": true,
		"-project": true, "--project": true,
		"-token-keyring": true, "--token-keyring": true,
		"-token-env": true, "--token-env": true,
		"-timeout": true, "--timeout": true,
	}
	bundlePath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if bundlePath == "" || len(extras) > 0 {
		fatal("usage: sshmgr cloud upload <workspace-bundle.json> [--profile NAME] [--timeout 2m] or --endpoint URL with one token source [--organization ORG --project SLUG]")
	}
	fs := flag.NewFlagSet("cloud upload", flag.ExitOnError)
	profileName := fs.String("profile", "", "named Cloud profile; defaults to active when no explicit endpoint is supplied")
	endpoint := fs.String("endpoint", "", "sshmgr Cloud API origin URL")
	organization := fs.String("organization", "", "manual v2 upload organization; requires --endpoint and --project")
	project := fs.String("project", "", "manual v2 upload project; requires --endpoint and --organization")
	tokenKeyring := fs.String("token-keyring", "", "OS keyring entry containing the Cloud bearer token")
	tokenEnv := fs.String("token-env", "", "environment variable containing the Cloud bearer token")
	timeout := fs.Duration("timeout", 2*time.Minute, "whole upload timeout")
	allowHTTPLoopback := fs.Bool("allow-http-loopback", false, "allow HTTP only to a literal loopback address for local E2E")
	_ = fs.Parse(flagArgs)
	*endpoint = strings.TrimSpace(*endpoint)
	*profileName = strings.TrimSpace(*profileName)
	*organization = strings.TrimSpace(*organization)
	*project = strings.TrimSpace(*project)
	*tokenKeyring = strings.TrimSpace(*tokenKeyring)
	*tokenEnv = strings.TrimSpace(*tokenEnv)
	bundle, err := access.ReadWorkspaceBundle(bundlePath)
	if err != nil {
		fatal(err.Error())
	}
	manual := *endpoint != "" || *tokenKeyring != "" || *tokenEnv != ""
	var token string
	if manual {
		if *profileName != "" || *endpoint == "" || (*tokenKeyring == "") == (*tokenEnv == "") {
			fatal("manual Cloud upload requires --endpoint, exactly one token source, and no --profile")
		}
		if (*organization != "") != (*project != "") {
			fatal("manual v2 Cloud upload requires --organization and --project together")
		}
		if *tokenKeyring != "" {
			token, err = secret.KeyringGet(*tokenKeyring)
			if err != nil {
				fatal(fmt.Sprintf("read Cloud token from keyring %q: %v", *tokenKeyring, err))
			}
		} else {
			var present bool
			token, present = os.LookupEnv(*tokenEnv)
			if !present || token == "" {
				fatal(fmt.Sprintf("Cloud token environment variable %q is unset or empty", *tokenEnv))
			}
		}
	} else {
		if *organization != "" || *project != "" {
			fatal("--organization/--project apply to manual uploads only; a profile upload uses the profile context")
		}
		name, profile, profileToken := resolveCloudProfile(*profileName)
		if *allowHTTPLoopback {
			fatal("--allow-http-loopback is stored in the selected profile; do not override it during upload")
		}
		if profile.UsesProjectContext() {
			if bundle.Workspace != profile.Project {
				fatal(fmt.Sprintf("bundle workspace %q does not match Cloud profile %q project %q", bundle.Workspace, name, profile.Project))
			}
			*organization = profile.Organization
			*project = profile.Project
		} else if bundle.Workspace != profile.Workspace {
			fatal(fmt.Sprintf("bundle workspace %q does not match Cloud profile %q workspace %q", bundle.Workspace, name, profile.Workspace))
		}
		*endpoint = profile.Endpoint
		*allowHTTPLoopback = profile.AllowInsecureLoopback
		token = profileToken
	}
	result, err := uploadCloudBundle(bundle, *endpoint, *organization, *project, token, *allowHTTPLoopback, *timeout)
	if err != nil {
		fatal(err.Error())
	}
	writeCloudUploadResult(result)
}

func cmdCloudDashboard(args []string) {
	valueFlags := map[string]bool{
		"-html": true, "--html": true,
		"-csv": true, "--csv": true,
		"-fail-on": true, "--fail-on": true,
		"-ownership-review": true, "--ownership-review": true,
		"-ownership-history": true, "--ownership-history": true,
		"-offboarding-history": true, "--offboarding-history": true,
	}
	historyPath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if historyPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr cloud dashboard <history.json> [evidence] [--html dashboard.html] [--csv access-review.csv] [--fail-on SEVERITY] [--require-full] [--require-current-ownership] [--require-complete-offboarding]")
	}
	fs := flag.NewFlagSet("cloud dashboard", flag.ExitOnError)
	htmlPath := fs.String("html", "", "write a private self-contained local HTML dashboard")
	csvPath := fs.String("csv", "", "write a private spreadsheet-safe local access-review CSV")
	ownershipPath := fs.String("ownership-review", "", "attach a validated latest-snapshot ownership review JSON")
	ownershipHistoryPath := fs.String("ownership-history", "", "attach a validated workspace ownership history JSON")
	offboardingHistoryPath := fs.String("offboarding-history", "", "attach a validated workspace offboarding history JSON")
	failOn := fs.String("fail-on", "", "exit 2 when latest scan/ownership findings meet this severity")
	requireFull := fs.Bool("require-full", false, "exit 2 when latest-snapshot coverage is partial or failed")
	requireCurrentOwnership := fs.Bool("require-current-ownership", false, "exit 2 without a current latest-snapshot ownership review")
	requireCompleteOffboarding := fs.Bool("require-complete-offboarding", false, "exit 2 when tracked offboarding evidence is missing or incomplete")
	_ = fs.Parse(flagArgs)
	*htmlPath = strings.TrimSpace(*htmlPath)
	*csvPath = strings.TrimSpace(*csvPath)
	*ownershipPath = strings.TrimSpace(*ownershipPath)
	*ownershipHistoryPath = strings.TrimSpace(*ownershipHistoryPath)
	*offboardingHistoryPath = strings.TrimSpace(*offboardingHistoryPath)
	*failOn = strings.TrimSpace(*failOn)
	if *htmlPath == "" && *csvPath == "" {
		fatal("cloud dashboard requires --html dashboard.html, --csv access-review.csv, or both")
	}
	inputs := []string{historyPath, *ownershipPath, *ownershipHistoryPath, *offboardingHistoryPath}
	outputs := []string{*htmlPath, *csvPath}
	for _, output := range outputs {
		if output == "" {
			continue
		}
		for _, input := range inputs {
			if input != "" && sameAccessPath(input, output) {
				fatal("dashboard output must not overwrite an input artifact")
			}
		}
	}
	if *htmlPath != "" && *csvPath != "" && sameAccessPath(*htmlPath, *csvPath) {
		fatal("dashboard HTML and CSV outputs must use different paths")
	}
	history, err := access.ReadWorkspaceHistory(historyPath)
	if err != nil {
		fatal(err.Error())
	}
	var ownership *access.OwnershipReview
	if *ownershipPath != "" {
		ownership, err = access.ReadOwnershipReview(*ownershipPath)
		if err != nil {
			fatal(err.Error())
		}
	}
	var offboardingHistory *access.WorkspaceOffboardingHistory
	if *offboardingHistoryPath != "" {
		offboardingHistory, err = access.ReadWorkspaceOffboardingHistory(*offboardingHistoryPath)
		if err != nil {
			fatal(err.Error())
		}
	}
	var ownershipHistory *access.WorkspaceOwnershipHistory
	if *ownershipHistoryPath != "" {
		ownershipHistory, err = access.ReadWorkspaceOwnershipHistory(*ownershipHistoryPath)
		if err != nil {
			fatal(err.Error())
		}
	}
	gate, err := access.EvaluateWorkspaceDashboardGate(history, ownership, ownershipHistory, offboardingHistory, access.WorkspaceDashboardGatePolicy{
		FailOnSeverity: *failOn, RequireFullCoverage: *requireFull,
		RequireCurrentOwnership: *requireCurrentOwnership, RequireCompleteOffboarding: *requireCompleteOffboarding,
	})
	if err != nil {
		fatal(err.Error())
	}
	if *htmlPath != "" {
		if err := access.WriteWorkspaceDashboardHTMLWithAuditEvidence(*htmlPath, history, ownership, ownershipHistory, offboardingHistory); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] self-contained workspace dashboard written to %s (mode 0600); network activity: none\n", *htmlPath)
	}
	if *csvPath != "" {
		if err := access.WriteWorkspaceDashboardCSVWithAuditEvidence(*csvPath, history, ownership, ownershipHistory, offboardingHistory); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] workspace access-review CSV written to %s (mode 0600); network activity: none\n", *csvPath)
	}
	fmt.Print(access.RenderWorkspaceDashboardExportTextWithAuditEvidence(history, ownership, ownershipHistory, offboardingHistory, *htmlPath, *csvPath))
	if gate.Failed() {
		fmt.Fprint(os.Stderr, access.RenderWorkspaceDashboardGateFailure(gate))
		os.Exit(2)
	}
}
