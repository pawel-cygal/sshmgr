package transfer

import "time"

// Logger receives a record for every completed file transfer. The default is
// a no-op; main wires this to persist into config.TransferHistory.
type Logger func(direction, alias, local, remote string, bytes int64, when time.Time)

// Log is the package-level transfer logger. Replace at process start.
var Log Logger = func(string, string, string, string, int64, time.Time) {}

func logXfer(direction, alias, local, remote string, n int64) {
	Log(direction, alias, local, remote, n, time.Now())
}
