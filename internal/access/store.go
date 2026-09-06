package access

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxSnapshotBytes = 128 << 20

func WriteSnapshot(path string, snapshot *Snapshot) error {
	if path == "" {
		return errors.New("snapshot output path is empty")
	}
	if snapshot == nil {
		return errors.New("snapshot is nil")
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal access snapshot: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxSnapshotBytes {
		return fmt.Errorf("snapshot is %d bytes; limit is %d", len(data), maxSnapshotBytes)
	}

	return writePrivateFile(path, data)
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create private output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".sshmgr-access-*")
	if err != nil {
		return fmt.Errorf("create temporary private output: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary private output: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod temporary private output: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary private output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temporary private output: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace private output %s: %w", path, err)
	}
	return nil
}

func ReadSnapshot(path string) (*Snapshot, error) {
	var snapshot Snapshot
	if err := readBoundedJSON(path, "access snapshot", &snapshot); err != nil {
		return nil, err
	}
	if err := ValidateSnapshot(&snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func readBoundedJSON(path, artifact string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s %s: %w", artifact, path, err)
	}
	defer file.Close()
	if stat, err := file.Stat(); err == nil && stat.Size() > maxSnapshotBytes {
		return fmt.Errorf("%s is %d bytes; limit is %d", artifact, stat.Size(), maxSnapshotBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", artifact, err)
	}
	if len(data) > maxSnapshotBytes {
		return fmt.Errorf("%s exceeds %d bytes", artifact, maxSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse %s: %w", artifact, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%s contains more than one JSON value", artifact)
		}
		return fmt.Errorf("parse trailing %s data: %w", artifact, err)
	}
	return nil
}
