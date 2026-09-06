package main

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/config"
	exec_ "github.com/systeampl/sshmgr/internal/exec"
)

func cmdAccessInvite(args []string) {
	valueFlags := map[string]bool{
		"-group": true, "--group": true, "-tag": true, "--tag": true, "-host": true, "--host": true,
		"-account": true, "--account": true, "-ttl": true, "--ttl": true, "-profile": true, "--profile": true,
		"-name": true, "--name": true,
	}
	email, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if email == "" || len(extras) > 0 {
		fatal("usage: sshmgr access invite EMAIL (--group G|--tag T|--host a,b) --account USER --ttl 30d")
	}
	fs := flag.NewFlagSet("access invite", flag.ExitOnError)
	group := fs.String("group", "", "inventory group")
	tag := fs.String("tag", "", "inventory tag")
	hosts := fs.String("host", "", "comma-separated aliases")
	account := fs.String("account", "", "target OS account")
	ttlText := fs.String("ttl", "30d", "grant lifetime (for example 30d or 12h)")
	profileName := fs.String("profile", "", "Cloud profile")
	displayName := fs.String("name", "", "optional display name")
	_ = fs.Parse(flagArgs)
	if strings.TrimSpace(*account) == "" {
		fatal("access invite requires --account USER")
	}
	ttl, err := parseAccessTTL(*ttlText)
	if err != nil {
		fatal(err.Error())
	}
	targets := lifecycleTargets(*group, *tag, *hosts, strings.TrimSpace(*account))
	human, token := requireHumanProject(*profileName)
	client := newHumanClient(human, token, 30*time.Second)
	request := &cloudcontract.CreateOnboardingRequest{
		IdentityRef: strings.TrimSpace(email), DisplayName: strings.TrimSpace(*displayName), Kind: "human",
		ExpiresIn: int(ttl / time.Hour), Targets: targets,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result, err := client.Invite(ctx, human.Profile.Organization, human.Profile.Project, request)
	cancel()
	if err != nil {
		fatal("create access invitation: " + err.Error())
	}
	verificationCommand, err := humanVerificationCommand(human.Profile, result.SubmissionToken)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Invitation %s created for %s. No host was modified.\n\nNext: send exactly this one-time verification command to the invited identity:\n  %s\n",
		result.Invitation.ID, result.Invitation.IdentityRef, verificationCommand)
	fmt.Printf("\nThe verification endpoint never opens a shell or reaches customer hosts.\nThen review progress with:\n  sshmgr access status %s\n", result.Invitation.ID)
}

func cmdAccessStatus(args []string) {
	filter, flagArgs, extras := splitAccessOnePositional(args, map[string]bool{"-profile": true, "--profile": true})
	if len(extras) > 0 {
		fatal("usage: sshmgr access status [EMAIL|INVITE_ID] [--profile NAME] [--json]")
	}
	fs := flag.NewFlagSet("access status", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile")
	jsonOutput := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(flagArgs)
	filter = strings.TrimSpace(filter)
	human, token := requireHumanProject(*profileName)
	client := newHumanClient(human, token, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result, err := client.Invitations(ctx, human.Profile.Organization, human.Profile.Project)
	cancel()
	if err != nil {
		fatal("list access invitations: " + err.Error())
	}
	filtered := result.Invitations[:0]
	for _, invitation := range result.Invitations {
		if filter == "" || invitation.ID == filter || strings.EqualFold(invitation.IdentityRef, filter) {
			filtered = append(filtered, invitation)
		}
	}
	result.Invitations = filtered
	if *jsonOutput {
		writeJSONStdout(result)
		return
	}
	if len(filtered) == 0 {
		fmt.Println("No matching access invitations.")
		fmt.Println("Next: create one with `sshmgr access invite EMAIL <selector> --account USER --ttl 30d`.")
		return
	}
	fmt.Printf("Access requests · %s/%s · %d shown\n\n", human.Profile.Organization, human.Profile.Project, len(filtered))
	for _, invitation := range filtered {
		fmt.Printf("%s\n  identity      %s\n  state         %s · %s\n", invitation.ID, invitation.IdentityRef, strings.ReplaceAll(invitation.Status, "_", " "), strings.ReplaceAll(invitation.Verification, "_", " "))
		for _, target := range invitation.Targets {
			fmt.Printf("  target        %s:%s → %s\n", target.Kind, target.Selector, target.Account)
		}
		fmt.Printf("  next          %s\n\n", invitationNextStep(invitation))
	}
}

func invitationNextStep(invitation cloudcontract.OnboardingInvitation) string {
	switch invitation.Status {
	case cloudcontract.OnboardingStatusInvited:
		return "the invited identity must complete the one-time verification command"
	case cloudcontract.OnboardingStatusKeySubmitted:
		if invitation.Verification == cloudcontract.VerificationPossession {
			return "sshmgr access approve " + invitation.ID
		}
		return "complete possession verification, or explicitly approve an audited override"
	case cloudcontract.OnboardingStatusApproved:
		groups, tags, hosts := []string{}, []string{}, []string{}
		for _, target := range invitation.Targets {
			switch target.Kind {
			case "group":
				groups = append(groups, target.Selector)
			case "tag":
				tags = append(tags, target.Selector)
			case "host":
				hosts = append(hosts, target.Selector)
			}
		}
		parts := []string{"sshmgr access sync"}
		switch {
		case len(groups) > 0 && len(tags) == 0 && len(hosts) == 0:
			for _, group := range groups {
				parts = append(parts, "--group", group)
			}
		case len(tags) == 1 && len(groups) == 0 && len(hosts) == 0:
			parts = append(parts, "--tag", tags[0])
		case len(hosts) > 0 && len(groups) == 0 && len(tags) == 0:
			parts = append(parts, "--host", strings.Join(hosts, ","))
		default:
			return "run `sshmgr access sync` with a selector covering the approved targets"
		}
		return strings.Join(parts, " ")
	case cloudcontract.OnboardingStatusRejected, cloudcontract.OnboardingStatusExpired:
		return "create a new invitation if access is still required"
	default:
		return "review the request state before continuing"
	}
}

func cmdAccessApprove(args []string) {
	valueFlags := map[string]bool{"-profile": true, "--profile": true, "-reason": true, "--reason": true}
	invitationID, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if invitationID == "" || len(extras) > 0 {
		fatal("usage: sshmgr access approve INVITE_ID [--override-unverified --reason TEXT]")
	}
	fs := flag.NewFlagSet("access approve", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile")
	override := fs.Bool("override-unverified", false, "approve without possession verification (RBAC controlled)")
	reason := fs.String("reason", "", "required reason for --override-unverified")
	_ = fs.Parse(flagArgs)
	if *override && len(strings.TrimSpace(*reason)) < 3 {
		fatal("--override-unverified requires --reason with at least 3 characters")
	}
	if !*override && strings.TrimSpace(*reason) != "" {
		fatal("--reason is valid only with --override-unverified")
	}
	human, token := requireHumanProject(*profileName)
	client := newHumanClient(human, token, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result, err := client.Approve(ctx, human.Profile.Organization, human.Profile.Project, invitationID, &cloudcontract.ReviewOnboardingRequest{
		Decision: "approve", AllowUnverified: *override, OverrideReason: strings.TrimSpace(*reason),
	})
	cancel()
	if err != nil {
		fatal("approve access invitation: " + err.Error())
	}
	fmt.Printf("Approved %s for %s (%s). Desired state changed; no host was modified.\nNext: %s\n", result.ID, result.IdentityRef, result.Verification, invitationNextStep(*result))
}

func cmdAccessRevoke(args []string) {
	valueFlags := map[string]bool{
		"-group": true, "--group": true, "-tag": true, "--tag": true, "-host": true, "--host": true,
		"-account": true, "--account": true, "-profile": true, "--profile": true, "-reason": true, "--reason": true,
	}
	email, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if email == "" || len(extras) > 0 {
		fatal("usage: sshmgr access revoke EMAIL (--group G|--tag T|--host a,b) [--account USER]")
	}
	fs := flag.NewFlagSet("access revoke", flag.ExitOnError)
	group := fs.String("group", "", "inventory group")
	tag := fs.String("tag", "", "inventory tag")
	hosts := fs.String("host", "", "comma-separated aliases")
	account := fs.String("account", "", "optional OS-account filter")
	profileName := fs.String("profile", "", "Cloud profile")
	reason := fs.String("reason", "revoked by human operator", "audit reason")
	_ = fs.Parse(flagArgs)
	requested := lifecycleTargets(*group, *tag, *hosts, strings.TrimSpace(*account))
	human, token := requireHumanProject(*profileName)
	client := newHumanClient(human, token, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	grants, err := client.Grants(ctx, human.Profile.Organization, human.Profile.Project)
	cancel()
	if err != nil {
		fatal("read desired access grants: " + err.Error())
	}
	targets := matchingGrantTargets(grants.Grants, strings.TrimSpace(email), requested, strings.TrimSpace(*account))
	if len(targets) == 0 {
		fatal("no active desired grants match this identity and selector")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	result, err := client.Revoke(ctx, human.Profile.Organization, human.Profile.Project, &cloudcontract.RevokeDesiredGrantsRequest{
		IdentityRef: strings.TrimSpace(email), Targets: targets, Reason: strings.TrimSpace(*reason),
	})
	cancel()
	if err != nil {
		fatal("revoke desired access: " + err.Error())
	}
	fmt.Printf("Revoked %d desired grant(s). No host key was removed; run `sshmgr access sync` to plan and confirm convergence.\n", result.Revoked)
}

func lifecycleTargets(group, tag, hosts, account string) []cloudcontract.OnboardingTarget {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	selector := exec_.Selector{Group: strings.TrimSpace(group), Tag: strings.TrimSpace(tag), Hosts: splitCSV(hosts)}
	if err := exec_.ValidateSelector(cfg, selector); err != nil {
		fatal(err.Error())
	}
	targets := []cloudcontract.OnboardingTarget{}
	switch {
	case selector.Group != "":
		targets = append(targets, cloudcontract.OnboardingTarget{Kind: "group", Selector: selector.Group, Account: account})
	case selector.Tag != "":
		targets = append(targets, cloudcontract.OnboardingTarget{Kind: "tag", Selector: selector.Tag, Account: account})
	default:
		for _, host := range selector.Hosts {
			targets = append(targets, cloudcontract.OnboardingTarget{Kind: "host", Selector: host, Account: account})
		}
	}
	return targets
}

func matchingGrantTargets(grants []cloudcontract.DesiredGrant, identity string, requested []cloudcontract.OnboardingTarget, account string) []cloudcontract.OnboardingTarget {
	wanted := map[string]bool{}
	for _, target := range requested {
		wanted[target.Kind+"\x00"+target.Selector] = true
	}
	unique := map[string]cloudcontract.OnboardingTarget{}
	for _, grant := range grants {
		if grant.Status != cloudcontract.GrantStatusActive || !strings.EqualFold(grant.IdentityRef, identity) || !wanted[grant.Target.Kind+"\x00"+grant.Target.Selector] {
			continue
		}
		if account != "" && grant.Target.Account != account {
			continue
		}
		key := grant.Target.Kind + "\x00" + grant.Target.Selector + "\x00" + grant.Target.Account
		unique[key] = grant.Target
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]cloudcontract.OnboardingTarget, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}

func parseAccessTTL(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil || days < 1 || days > 30 {
			return 0, fmt.Errorf("--ttl days must be between 1d and 30d")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < time.Hour || duration > 30*24*time.Hour || duration%time.Hour != 0 {
		return 0, fmt.Errorf("--ttl must be whole hours between 1h and 30d")
	}
	return duration, nil
}
