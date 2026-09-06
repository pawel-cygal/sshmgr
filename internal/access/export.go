package access

import (
	"bytes"
	"encoding/csv"
	"errors"
	"sort"
	"strconv"
	"strings"
)

var accessCSVHeader = []string{
	"scan_id",
	"host",
	"host_coverage",
	"groups",
	"tags",
	"account",
	"uid",
	"gid",
	"source_type",
	"source_path",
	"source_mode",
	"source_owner_uid",
	"line",
	"fingerprint",
	"algorithm",
	"bits",
	"comment",
	"identity_status",
	"options",
	"parse_error",
}

type accessCSVRow struct {
	host        string
	account     string
	source      string
	line        int
	fingerprint string
	record      []string
}

// RenderAccessCSV exports one row per observed authorized_keys entry. It is
// deterministic regardless of snapshot slice order and includes malformed
// entries so the CSV cannot silently make source problems disappear.
func RenderAccessCSV(snapshot *Snapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is nil")
	}
	rows := make([]accessCSVRow, 0, snapshot.Summary.AuthorizedKeyEntries+snapshot.Summary.MalformedEntries)
	for _, host := range snapshot.Hosts {
		groups := strings.Join(sortedCopy(host.Groups), ";")
		tags := strings.Join(sortedCopy(host.Tags), ";")
		for _, account := range host.Accounts {
			uid := optionalUint(account.UID)
			gid := optionalUint(account.GID)
			for _, source := range account.Sources {
				ownerUID := optionalUint(source.OwnerUID)
				for _, entry := range source.Entries {
					identityStatus := "unclaimed"
					if strings.TrimSpace(entry.Comment) != "" {
						identityStatus = "comment_hint_unverified"
					}
					record := []string{
						snapshot.ScanID,
						host.Alias,
						host.Coverage,
						groups,
						tags,
						account.Username,
						uid,
						gid,
						source.Type,
						source.Path,
						source.Mode,
						ownerUID,
						strconv.Itoa(entry.Line),
						entry.Fingerprint,
						entry.Algorithm,
						strconv.Itoa(entry.Bits),
						entry.Comment,
						identityStatus,
						strings.Join(entry.Options, ";"),
						entry.ParseError,
					}
					for index := range record {
						record[index] = spreadsheetSafeCSVCell(record[index])
					}
					rows = append(rows, accessCSVRow{
						host: host.Alias, account: account.Username, source: source.Path,
						line: entry.Line, fingerprint: entry.Fingerprint, record: record,
					})
				}
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		if left.host != right.host {
			return left.host < right.host
		}
		if left.account != right.account {
			return left.account < right.account
		}
		if left.source != right.source {
			return left.source < right.source
		}
		if left.line != right.line {
			return left.line < right.line
		}
		return left.fingerprint < right.fingerprint
	})

	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write(accessCSVHeader); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if err := writer.Write(row.record); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func WriteAccessCSV(path string, snapshot *Snapshot) error {
	data, err := RenderAccessCSV(snapshot)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func sortedCopy(values []string) []string {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return copyValues
}

func optionalUint(value *uint64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatUint(*value, 10)
}

// Quoting is insufficient to stop spreadsheet formula execution. Prefix
// formula-like, tab-leading, and carriage-return-leading fields with a single
// quote while preserving ordinary values exactly.
func spreadsheetSafeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \n")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}
