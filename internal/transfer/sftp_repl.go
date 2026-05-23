package transfer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sshmgr/internal/theme"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTP starts an interactive SFTP REPL over client. Supported commands:
//
//	help / ?
//	ls [path]               list remote dir
//	lls [path]              list local dir
//	cd <path>               change remote dir
//	lcd <path>              change local dir
//	pwd                     print remote cwd
//	lpwd                    print local cwd
//	get <remote> [local]    download file
//	put <local>  [remote]   upload file
//	rm <path>               remove remote file
//	mkdir <path>            create remote directory
//	rmdir <path>            remove remote (empty) directory
//	exit / quit / bye       leave
func SFTP(client *ssh.Client, alias string) error {
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp init: %w", err)
	}
	defer sc.Close()

	cwd, err := sc.Getwd()
	if err != nil {
		cwd = "."
	}

	in := bufio.NewReader(os.Stdin)
	primary := theme.ANSI(theme.Current.Primary)
	dim := theme.ANSI(theme.Current.Dim)
	reset := theme.Reset()
	fmt.Fprintf(os.Stderr, "%s[sshmgr]%s SFTP session opened. Type 'help' for commands, 'exit' to quit.\n", primary, reset)
	for {
		fmt.Fprintf(os.Stderr, "%ssftp%s %s[%s]%s%s>%s ", primary, reset, dim, cwd, reset, primary, reset)
		line, err := in.ReadString('\n')
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr)
			return nil
		}
		if err != nil {
			return err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		cmd, args := fields[0], fields[1:]
		switch cmd {
		case "help", "?":
			printSFTPHelp(os.Stderr)
		case "exit", "quit", "bye":
			return nil
		case "ls":
			cwd, err = sftpLs(sc, cwd, args)
		case "lls":
			err = localLs(args)
		case "cd":
			cwd, err = sftpCd(sc, cwd, args)
		case "lcd":
			err = localCd(args)
		case "pwd":
			fmt.Println(cwd)
		case "lpwd":
			p, e := os.Getwd()
			if e != nil {
				err = e
			} else {
				fmt.Println(p)
			}
		case "get":
			err = sftpGet(sc, cwd, args, alias)
		case "put":
			err = sftpPut(sc, cwd, args, alias)
		case "rm":
			err = sftpRm(sc, cwd, args)
		case "mkdir":
			err = sftpMkdir(sc, cwd, args)
		case "rmdir":
			err = sftpRmdir(sc, cwd, args)
		default:
			err = fmt.Errorf("unknown command %q (try 'help')", cmd)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			err = nil
		}
	}
}

func printSFTPHelp(w io.Writer) {
	fmt.Fprintln(w, "  help, ?                 show this help")
	fmt.Fprintln(w, "  ls [path]               list remote directory")
	fmt.Fprintln(w, "  lls [path]              list local directory")
	fmt.Fprintln(w, "  cd <path>               change remote directory")
	fmt.Fprintln(w, "  lcd <path>              change local directory")
	fmt.Fprintln(w, "  pwd                     print remote cwd")
	fmt.Fprintln(w, "  lpwd                    print local cwd")
	fmt.Fprintln(w, "  get <remote> [local]    download file")
	fmt.Fprintln(w, "  put <local> [remote]    upload file")
	fmt.Fprintln(w, "  rm <path>               remove remote file")
	fmt.Fprintln(w, "  mkdir <path>            create remote directory")
	fmt.Fprintln(w, "  rmdir <path>            remove remote (empty) directory")
	fmt.Fprintln(w, "  exit, quit, bye         leave the SFTP session")
}

func resolveRemote(cwd, p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return path(cwd, p)
}

func sftpLs(sc *sftp.Client, cwd string, args []string) (string, error) {
	target := cwd
	if len(args) > 0 {
		target = resolveRemote(cwd, args[0])
	}
	entries, err := sc.ReadDir(target)
	if err != nil {
		return cwd, err
	}
	for _, e := range entries {
		mark := ""
		if e.IsDir() {
			mark = "/"
		}
		fmt.Printf("%-30s %10d  %s\n", e.Name()+mark, e.Size(), e.ModTime().Format("2006-01-02 15:04"))
	}
	return cwd, nil
}

func localLs(args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	for _, e := range entries {
		mark := ""
		if e.IsDir() {
			mark = "/"
		}
		info, _ := e.Info()
		var size int64
		var t string
		if info != nil {
			size = info.Size()
			t = info.ModTime().Format("2006-01-02 15:04")
		}
		fmt.Printf("%-30s %10d  %s\n", e.Name()+mark, size, t)
	}
	return nil
}

func sftpCd(sc *sftp.Client, cwd string, args []string) (string, error) {
	if len(args) < 1 {
		return cwd, errors.New("cd: missing path")
	}
	target := resolveRemote(cwd, args[0])
	info, err := sc.Stat(target)
	if err != nil {
		return cwd, err
	}
	if !info.IsDir() {
		return cwd, fmt.Errorf("%s is not a directory", target)
	}
	return target, nil
}

func localCd(args []string) error {
	if len(args) < 1 {
		return errors.New("lcd: missing path")
	}
	return os.Chdir(args[0])
}

func sftpGet(sc *sftp.Client, cwd string, args []string, alias string) error {
	if len(args) < 1 {
		return errors.New("get: missing remote path")
	}
	remote := resolveRemote(cwd, args[0])
	local := filepath.Base(args[0])
	if len(args) >= 2 {
		local = args[1]
	}
	return downloadFile(sc, remote, local, alias)
}

func sftpPut(sc *sftp.Client, cwd string, args []string, alias string) error {
	if len(args) < 1 {
		return errors.New("put: missing local path")
	}
	local := args[0]
	remote := resolveRemote(cwd, filepath.Base(local))
	if len(args) >= 2 {
		remote = resolveRemote(cwd, args[1])
	}
	return uploadFile(sc, local, remote, alias)
}

func sftpRm(sc *sftp.Client, cwd string, args []string) error {
	if len(args) < 1 {
		return errors.New("rm: missing path")
	}
	return sc.Remove(resolveRemote(cwd, args[0]))
}

func sftpMkdir(sc *sftp.Client, cwd string, args []string) error {
	if len(args) < 1 {
		return errors.New("mkdir: missing path")
	}
	return sc.Mkdir(resolveRemote(cwd, args[0]))
}

func sftpRmdir(sc *sftp.Client, cwd string, args []string) error {
	if len(args) < 1 {
		return errors.New("rmdir: missing path")
	}
	return sc.RemoveDirectory(resolveRemote(cwd, args[0]))
}
