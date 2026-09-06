package main

import (
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/cloudcontract"
)

func TestInvitationNextStepGuidesLifecycle(t *testing.T) {
	invitation := cloudcontract.OnboardingInvitation{ID: "invite_0123456789abcdef0123456789abcdef", Status: cloudcontract.OnboardingStatusKeySubmitted, Verification: cloudcontract.VerificationPossession}
	if got := invitationNextStep(invitation); got != "sshmgr access approve "+invitation.ID {
		t.Fatalf("verified request next step = %q", got)
	}

	invitation.Status = cloudcontract.OnboardingStatusApproved
	invitation.Targets = []cloudcontract.OnboardingTarget{{Kind: "host", Selector: "web-01"}, {Kind: "host", Selector: "web-02"}}
	if got := invitationNextStep(invitation); got != "sshmgr access sync --host web-01,web-02" {
		t.Fatalf("approved request next step = %q", got)
	}

	invitation.Status = cloudcontract.OnboardingStatusInvited
	if got := invitationNextStep(invitation); !strings.Contains(got, "verification command") {
		t.Fatalf("invited request next step = %q", got)
	}
}
