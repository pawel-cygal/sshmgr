package transfer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

type failAfterReader struct {
	reader io.Reader
	left   int
}

func TestSFTPOperationUnsupported(t *testing.T) {
	if !sftpOperationUnsupported(&sftp.StatusError{Code: uint32(sftp.ErrSSHFxOpUnsupported)}) {
		t.Fatal("SFTP operation-unsupported status was not recognized")
	}
	if sftpOperationUnsupported(errors.New("other")) {
		t.Fatal("ordinary error treated as operation unsupported")
	}
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("injected read failure")
	}
	if len(p) > r.left {
		p = p[:r.left]
	}
	n, err := r.reader.Read(p)
	r.left -= n
	return n, err
}

func TestCopyLocalAtomicallyPreservesDestinationOnFailure(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(dst, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	src := &failAfterReader{reader: strings.NewReader("replacement"), left: 4}
	if _, err := copyLocalAtomically(dst, src, 0o600); err == nil {
		t.Fatal("expected injected copy failure")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("failed copy changed destination: got %q", got)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(dst), ".sshmgr-transfer-*")); len(leftovers) != 0 {
		t.Fatalf("temporary files leaked: %v", leftovers)
	}
}

func TestCopyLocalAtomicallyReplacesOnlyAfterSuccess(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := copyLocalAtomically(dst, strings.NewReader("new content"), 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len("new content")) {
		t.Fatalf("copied %d bytes", n)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "new content" {
		t.Fatalf("got %q", got)
	}
	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640", info.Mode().Perm())
	}
}
