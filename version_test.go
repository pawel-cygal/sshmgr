package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteVersionHuman(t *testing.T) {
	info := buildInfo{
		Version:   "v1.2.3",
		Commit:    "abc1234",
		BuildDate: "2026-08-05T10:00:00Z",
		GoVersion: "go1.25.0",
		OS:        "linux",
		Arch:      "amd64",
	}
	var out bytes.Buffer
	if err := writeVersion(&out, info, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sshmgr v1.2.3", "commit: abc1234", "built: 2026-08-05T10:00:00Z", "go: go1.25.0", "platform: linux/amd64"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("version output %q does not contain %q", out.String(), want)
		}
	}
}

func TestWriteVersionJSON(t *testing.T) {
	info := buildInfo{Version: "v1.2.3", Commit: "abc1234", OS: "linux", Arch: "arm64"}
	var out bytes.Buffer
	if err := writeVersion(&out, info, true); err != nil {
		t.Fatal(err)
	}
	var got buildInfo
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if got != info {
		t.Fatalf("decoded build info: got %+v want %+v", got, info)
	}
}

func TestCurrentBuildInfoIsComplete(t *testing.T) {
	got := currentBuildInfo()
	if got.Version == "" || got.Commit == "" || got.BuildDate == "" || got.GoVersion == "" || got.OS == "" || got.Arch == "" {
		t.Fatalf("incomplete build info: %+v", got)
	}
}
