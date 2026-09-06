package main

import (
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/cloudprofile"
)

func TestHumanVerificationCommandDerivesSafeProductionTarget(t *testing.T) {
	t.Setenv("SSHMGR_VERIFY_HOST", "")
	t.Setenv("SSHMGR_VERIFY_PORT", "")
	token := strings.Repeat("a", 43)
	command, err := humanVerificationCommand(cloudprofile.Profile{Endpoint: "https://api.example.test"}, token)
	if err != nil || command != "ssh "+token+"@verify.example.test" {
		t.Fatalf("verification command=%q err=%v", command, err)
	}
}

func TestHumanVerificationCommandSupportsExplicitDevelopmentPort(t *testing.T) {
	t.Setenv("SSHMGR_VERIFY_HOST", "127.0.0.1:2222")
	t.Setenv("SSHMGR_VERIFY_PORT", "")
	token := strings.Repeat("b", 43)
	command, err := humanVerificationCommand(cloudprofile.Profile{}, token)
	if err != nil || command != "ssh -p 2222 "+token+"@127.0.0.1" {
		t.Fatalf("verification command=%q err=%v", command, err)
	}
}

func TestHumanVerificationCommandRejectsShellSyntaxAndInvalidPorts(t *testing.T) {
	t.Setenv("SSHMGR_VERIFY_HOST", "verify.example.test;touch-bad")
	if _, err := humanVerificationCommand(cloudprofile.Profile{}, strings.Repeat("c", 43)); err == nil {
		t.Fatal("unsafe verification host was accepted")
	}
	t.Setenv("SSHMGR_VERIFY_HOST", "verify.example.test")
	t.Setenv("SSHMGR_VERIFY_PORT", "70000")
	if _, err := humanVerificationCommand(cloudprofile.Profile{}, strings.Repeat("c", 43)); err == nil {
		t.Fatal("invalid verification port was accepted")
	}
	t.Setenv("SSHMGR_VERIFY_PORT", "22")
	if _, err := humanVerificationCommand(cloudprofile.Profile{}, "bad token; echo owned"); err == nil {
		t.Fatal("unsafe verification token was accepted")
	}
}
