// Package completion emits shell completion scripts. Each script invokes
// `sshmgr __complete` at runtime to get candidates dynamically (so adding a
// host shows up in completion immediately, without re-sourcing).
package completion

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"sshmgr/internal/config"
)

// Print writes the completion script for shell ("bash"|"zsh"|"fish") to w.
func Print(w io.Writer, shell string) error {
	switch shell {
	case "bash":
		_, err := io.WriteString(w, bashScript)
		return err
	case "zsh":
		_, err := io.WriteString(w, zshScript)
		return err
	case "fish":
		_, err := io.WriteString(w, fishScript)
		return err
	}
	return errors.New("unsupported shell: " + shell + " (use bash | zsh | fish)")
}

// Suggest is called by the completion script (via `sshmgr __complete`) and
// prints one candidate per line for the given word.
//
// argv is the user's current command line tokens after "sshmgr" (excluding
// the partial word). The last positional we complete is the host alias; on
// the first slot we mix in subcommand names.
func Suggest(w io.Writer, argv []string, word string) error {
	cfg, _, err := config.Load()
	if err != nil {
		return err
	}
	var out []string

	// Subcommands are only candidates at position 0.
	if len(argv) == 0 {
		out = append(out, subcommands...)
	}

	// Always offer aliases — most invocations take an alias as the first
	// positional arg, and several subcommands (scp/sftp/files/fwd/trust)
	// also take one.
	for a := range cfg.Hosts {
		out = append(out, a)
	}
	sort.Strings(out)
	for _, s := range out {
		if word == "" || strings.HasPrefix(s, word) {
			fmt.Fprintln(w, s)
		}
	}
	return nil
}

var subcommands = []string{
	"ui", "list", "groups", "info", "add", "edit", "rm", "trust",
	"theme", "keyring", "scp", "sftp", "files", "fwd", "exec", "watch",
	"rotate-key", "import", "export", "playbook", "lint", "history",
	"completion", "help",
}

const bashScript = `# sshmgr bash completion. Add to ~/.bashrc:
#   source <(sshmgr completion bash)
_sshmgr() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }
    local -a passed=("${words[@]:1:cword-1}")
    local IFS=$'\n'
    COMPREPLY=( $(sshmgr __complete "$cur" "${passed[@]}" 2>/dev/null) )
}
complete -F _sshmgr sshmgr
`

const zshScript = `# sshmgr zsh completion. Add to ~/.zshrc:
#   source <(sshmgr completion zsh)
_sshmgr() {
    local cur="${words[CURRENT]}"
    local -a passed=("${words[@]:1:CURRENT-2}")
    local -a candidates
    candidates=("${(@f)$(sshmgr __complete "$cur" "${passed[@]}" 2>/dev/null)}")
    compadd -- "${candidates[@]}"
}
compdef _sshmgr sshmgr
`

const fishScript = `# sshmgr fish completion. Place at:
#   ~/.config/fish/completions/sshmgr.fish
function __sshmgr_complete
    set -l tokens (commandline -opc)
    set -l current (commandline -ct)
    set -l passed $tokens[2..-1]
    sshmgr __complete -- $current $passed 2>/dev/null
end
complete -c sshmgr -f -a "(__sshmgr_complete)"
`
