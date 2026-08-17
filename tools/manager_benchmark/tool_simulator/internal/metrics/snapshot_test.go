package metrics

import (
	"reflect"
	"testing"
)

// TestSnapshotCopiesEveryCounter guards the one hazard of snapshotBucket's
// field-by-field atomic read: a counter added to Counters but forgotten there
// reads as a silent, permanent zero -- the request happens, the wire shows it,
// and every artifact says it never did. Reflection walks the struct so the test
// covers fields that do not exist yet.
func TestSnapshotCopiesEveryCounter(t *testing.T) {
	b := newBucket()
	v := reflect.ValueOf(&b.c).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() != reflect.Uint64 {
			t.Fatalf("Counters.%s is not uint64: snapshotBucket's atomic reads assume it is",
				v.Type().Field(i).Name)
		}
		v.Field(i).SetUint(uint64(i) + 1) // distinct, non-zero
	}

	got := reflect.ValueOf(snapshotBucket(b).C)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if want := uint64(i) + 1; got.Field(i).Uint() != want {
			t.Errorf("snapshotBucket dropped Counters.%s: got %d, want %d "+
				"(add it to the snapshotBucket literal)", name, got.Field(i).Uint(), want)
		}
	}
}

// TestRecordScanVDClassifiesStatuses pins the /scan/vd status mapping: 409 and
// 503 are contract outcomes with counters of their own, and anything unexpected
// (including the 400/401 that invalidate a run) lands in ScanOther rather than
// being lost.
func TestRecordScanVDClassifiesStatuses(t *testing.T) {
	r := NewRegistry([]string{"linux"}, []string{"vd"})
	for _, status := range []int{200, 200, 409, 503, 401, 418} {
		r.RecordScanVD("linux", "vd", status, 1000)
	}
	c := r.GlobalSnapshot().C
	if c.ScanSent != 6 || c.Scan200 != 2 || c.Scan409 != 1 || c.Scan503 != 1 || c.ScanOther != 2 {
		t.Errorf("unexpected classification: sent=%d 200=%d 409=%d 503=%d other=%d",
			c.ScanSent, c.Scan200, c.Scan409, c.Scan503, c.ScanOther)
	}
	if h := r.GlobalSnapshot().Hists["scan"]; h.Count != 6 {
		t.Errorf("scan latency histogram got %d observations, want 6", h.Count)
	}
	// Per-lane attribution is what a mixed scenario reads: a scan storm on one
	// lane must not be invisible in the by_lane breakdown.
	if lane := r.LaneSnapshots()["vd"].C; lane.ScanSent != 6 {
		t.Errorf("by_lane scan_sent = %d, want 6", lane.ScanSent)
	}
}
