package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
)

// These values are intentionally useful in local development and replaced by
// release builds through -ldflags -X main.<name>=<value>.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type buildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func currentBuildInfo() buildInfo {
	resolvedVersion, resolvedCommit, resolvedDate := version, commit, buildDate
	// `go install module@version` cannot inject linker flags. Go still embeds
	// module/VCS metadata, so use it as a fallback and avoid reporting a tagged
	// installation as an anonymous development build.
	if info, ok := debug.ReadBuildInfo(); ok {
		if resolvedVersion == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			resolvedVersion = info.Main.Version
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if resolvedCommit == "unknown" && setting.Value != "" {
					resolvedCommit = setting.Value
				}
			case "vcs.time":
				if resolvedDate == "unknown" && setting.Value != "" {
					resolvedDate = setting.Value
				}
			}
		}
	}
	return buildInfo{
		Version:   resolvedVersion,
		Commit:    resolvedCommit,
		BuildDate: resolvedDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

func writeVersion(w io.Writer, info buildInfo, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	_, err := fmt.Fprintf(w, "sshmgr %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n",
		info.Version, info.Commit, info.BuildDate, info.GoVersion, info.OS, info.Arch)
	return err
}

func cmdVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print machine-readable build information")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fatal("version accepts only --json")
	}
	if err := writeVersion(os.Stdout, currentBuildInfo(), *asJSON); err != nil {
		fatal("write version: " + err.Error())
	}
}
