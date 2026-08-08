package tui

import (
	"fmt"
	"testing"

	"github.com/systeampl/sshmgr/internal/config"
)

// newTestState builds a uiState with real widgets but no Application. tview's
// List and Table both work standalone, so selection behaviour is testable
// without a screen or an event loop.
func newTestState(t *testing.T, hosts map[string]config.HostConfig) *uiState {
	t.Helper()
	cfg := &config.Config{
		Hosts:  hosts,
		Groups: map[string]config.GroupDefaults{},
	}
	s := &uiState{
		cfg:           cfg,
		mode:          modeFlat,
		sort:          sortName,
		pings:         newPingMap(),
		multiSelected: map[string]bool{},
	}
	buildHostWidget(s)
	return s
}

// fixture returns a deterministic set of hosts whose sort order is known.
func fixture() map[string]config.HostConfig {
	return map[string]config.HostConfig{
		"alpha":   {Host: "10.0.0.1", Port: 22, Tags: []string{"web"}},
		"bravo":   {Host: "10.0.0.2", Port: 22, Tags: []string{"db"}},
		"charlie": {Host: "10.0.0.3", Port: 22, Tags: []string{"web"}},
		"delta":   {Host: "10.0.0.4", Port: 22, Tags: []string{"cache"}},
	}
}

func TestAliasAtMatchesRefreshOrder(t *testing.T) {
	s := newTestState(t, fixture())
	s.refreshList("")

	want := []string{"alpha", "bravo", "charlie", "delta"}
	for i, w := range want {
		if got := s.aliasAt(i); got != w {
			t.Errorf("aliasAt(%d) = %q, want %q", i, got, w)
		}
	}
}

func TestCurrentAliasFollowsTheCursor(t *testing.T) {
	s := newTestState(t, fixture())
	s.refreshList("")

	for i, want := range []string{"alpha", "bravo", "charlie", "delta"} {
		selectRow(s, i)
		if got := s.currentAlias(); got != want {
			t.Errorf("cursor at index %d: currentAlias() = %q, want %q", i, got, want)
		}
	}
}

func TestCurrentAliasUnderFilter(t *testing.T) {
	s := newTestState(t, fixture())
	s.filter = "tag:web"
	s.refreshList("")

	// Only alpha and charlie match; the cursor indexes the FILTERED order.
	if n := len(s.aliases); n != 2 {
		t.Fatalf("filter tag:web matched %d hosts, want 2 (%v)", n, s.aliases)
	}
	for i, want := range []string{"alpha", "charlie"} {
		selectRow(s, i)
		if got := s.currentAlias(); got != want {
			t.Errorf("filtered cursor %d: currentAlias() = %q, want %q", i, got, want)
		}
	}
}

func TestCurrentAliasWithPinnedHostsFloating(t *testing.T) {
	hosts := fixture()
	d := hosts["delta"]
	d.Pinned = true
	hosts["delta"] = d

	s := newTestState(t, hosts)
	s.refreshList("")

	// delta floats to the top; the rest keep name order behind it.
	want := []string{"delta", "alpha", "bravo", "charlie"}
	for i, w := range want {
		selectRow(s, i)
		if got := s.currentAlias(); got != w {
			t.Errorf("pinned layout, cursor %d: currentAlias() = %q, want %q", i, got, w)
		}
	}
}

// Multi-select marks must not disturb the mapping — the marker is decoration
// on the row, not a change to what the row points at.
func TestCurrentAliasWithMultiSelectMarks(t *testing.T) {
	s := newTestState(t, fixture())
	s.multiSelected["bravo"] = true
	s.multiSelected["delta"] = true
	s.refreshList("")

	for i, want := range []string{"alpha", "bravo", "charlie", "delta"} {
		selectRow(s, i)
		if got := s.currentAlias(); got != want {
			t.Errorf("with marks, cursor %d: currentAlias() = %q, want %q", i, got, want)
		}
	}
}

func TestAliasAtOutOfRangeIsEmpty(t *testing.T) {
	s := newTestState(t, fixture())
	s.refreshList("")
	for _, i := range []int{-1, 4, 99} {
		if got := s.aliasAt(i); got != "" {
			t.Errorf("aliasAt(%d) = %q, want empty", i, got)
		}
	}
}

func TestEmptyAndUnmatchedListsResolveToEmpty(t *testing.T) {
	s := newTestState(t, map[string]config.HostConfig{})
	s.refreshList("")
	if got := s.currentAlias(); got != "" {
		t.Errorf("empty config: currentAlias() = %q, want empty", got)
	}

	s2 := newTestState(t, fixture())
	s2.filter = "tag:nonesuch"
	s2.refreshList("")
	if got := s2.currentAlias(); got != "" {
		t.Errorf("filter matching nothing: currentAlias() = %q, want empty", got)
	}
}

// TestEmptyRefreshLeavesASelectableRow guards against a hang: tview's
// InputHandler moves the cursor by scanning forward/backward for the next
// cell that is not NotSelectable, in a loop that only exits by finding one or
// by reaching the exact last cell in the scan direction. If a refresh with
// zero matches left the table with no selectable body row at all (every
// header cell is SetSelectable(false)), the very next j/k/Down/Up would spin
// forever -- this does not send that keystroke (a regression here would hang
// the test suite), it asserts the precondition that makes the loop
// terminate: a selectable cell exists at the selected row, and it carries no
// alias reference so Enter stays inert.
func TestEmptyRefreshLeavesASelectableRow(t *testing.T) {
	check := func(t *testing.T, s *uiState) {
		t.Helper()
		row, _ := s.table.GetSelection()
		if row < 1 {
			t.Fatalf("selected row = %d, want a body row (>= 1)", row)
		}
		if got := s.aliasAtRow(row); got != "" {
			t.Errorf("aliasAtRow(%d) = %q, want empty (placeholder must carry no reference)", row, got)
		}
		selectable := false
		for col := 0; col < colCount; col++ {
			if cell := s.table.GetCell(row, col); cell != nil && !cell.NotSelectable {
				selectable = true
				break
			}
		}
		if !selectable {
			t.Errorf("no selectable cell on row %d -- the next j/k would hang tview's InputHandler", row)
		}
	}

	t.Run("empty config", func(t *testing.T) {
		s := newTestState(t, map[string]config.HostConfig{})
		s.refreshList("")
		check(t, s)
	})

	t.Run("filter matches nothing", func(t *testing.T) {
		s := newTestState(t, fixture())
		s.filter = "tag:nonesuch"
		s.refreshList("")
		check(t, s)
	})
}

// A 388-host config is the real-world case; make sure nothing is quadratic or
// index-fragile at that size.
func TestMappingHoldsAcrossALargeFleet(t *testing.T) {
	hosts := map[string]config.HostConfig{}
	for i := 0; i < 400; i++ {
		hosts[fmt.Sprintf("host-%03d", i)] = config.HostConfig{
			Host: fmt.Sprintf("10.1.%d.%d", i/256, i%256), Port: 22,
		}
	}
	s := newTestState(t, hosts)
	s.refreshList("")

	for _, i := range []int{0, 1, 199, 398, 399} {
		selectRow(s, i)
		want := fmt.Sprintf("host-%03d", i)
		if got := s.currentAlias(); got != want {
			t.Errorf("large fleet, cursor %d: currentAlias() = %q, want %q", i, got, want)
		}
	}
}
