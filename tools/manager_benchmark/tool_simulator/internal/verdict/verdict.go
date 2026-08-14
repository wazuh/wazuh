// Package verdict evaluates a scenario's optional `expected` block against the
// run's final counters. This is the ONE deliberate exception to the tool's
// "record everything, judge nothing" stance (docu/09): a scenario may opt into
// a contract verdict, and only over COUNTERS -- statuses and counts hold on any
// hardware, unlike latency or throughput, which belong to the machine that
// produced them. A scenario without the block is never judged.
package verdict

import (
	"fmt"
	"sort"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/metrics"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

// Result is what lands in sender_summary.json under "expected" and drives the
// exit code (3 on failure, after the measurement-validity codes).
type Result struct {
	Passed   bool     `json:"passed"`
	Checked  int      `json:"checked"`
	Failures []string `json:"failures,omitempty"`
}

// The counter tables: JSON name -> accessor. These are the names of the
// summary's `totals` section, so an assertion reads exactly like the artifact
// it checks. "s5xx" is derived (s500 + s503); the untyped "other" bucket is a
// name of its own, never folded into it.
var sessionCounters = map[string]func(metrics.Counters) uint64{
	"sent":               func(c metrics.Counters) uint64 { return c.SessionsSent },
	"ok":                 func(c metrics.Counters) uint64 { return c.SessionsOK },
	"noop":               func(c metrics.Counters) uint64 { return c.SessionsNoop },
	"s400":               func(c metrics.Counters) uint64 { return c.S400 },
	"s401":               func(c metrics.Counters) uint64 { return c.S401 },
	"s403":               func(c metrics.Counters) uint64 { return c.S403 },
	"s409":               func(c metrics.Counters) uint64 { return c.S409 },
	"s413":               func(c metrics.Counters) uint64 { return c.S413 },
	"s500":               func(c metrics.Counters) uint64 { return c.S500 },
	"s503":               func(c metrics.Counters) uint64 { return c.S503 },
	"s503_retry_after":   func(c metrics.Counters) uint64 { return c.S503RetryAfter },
	"s5xx":               func(c metrics.Counters) uint64 { return c.S500 + c.S503 },
	"other":              func(c metrics.Counters) uint64 { return c.SessOther },
	"abandoned_on_drain": func(c metrics.Counters) uint64 { return c.AbandonedOnDrain },
	"retries_feed":       func(c metrics.Counters) uint64 { return c.RetriesFeed },
	"retries_503":        func(c metrics.Counters) uint64 { return c.Retries503 },
	"retries_exhausted":  func(c metrics.Counters) uint64 { return c.RetriesExhausted },
	"transport_errors":   func(c metrics.Counters) uint64 { return c.TransportErrors },
	"documents_sent":     func(c metrics.Counters) uint64 { return c.DocumentsSent },
}

var statelessCounters = map[string]func(metrics.Counters) uint64{
	"sent":        func(c metrics.Counters) uint64 { return c.StatelessSent },
	"s202":        func(c metrics.Counters) uint64 { return c.St202 },
	"s400":        func(c metrics.Counters) uint64 { return c.StBad400 },
	"s413":        func(c metrics.Counters) uint64 { return c.StBad413 },
	"s503":        func(c metrics.Counters) uint64 { return c.St503 },
	"other":       func(c metrics.Counters) uint64 { return c.StOther },
	"events_sent": func(c metrics.Counters) uint64 { return c.EventsSent },
}

var controlCounters = map[string]func(metrics.Counters) uint64{
	"startup_ok":   func(c metrics.Counters) uint64 { return c.StartupOK },
	"startup_err":  func(c metrics.Counters) uint64 { return c.StartupErr },
	"notify_ok":    func(c metrics.Counters) uint64 { return c.NotifyOK },
	"notify_err":   func(c metrics.Counters) uint64 { return c.NotifyErr },
	"shutdown_ok":  func(c metrics.Counters) uint64 { return c.ShutdownOK },
	"shutdown_err": func(c metrics.Counters) uint64 { return c.ShutdownErr },
}

// scanCounters are the POST /scan/vd outcomes. "s200" asserts how many re-scan
// requests were ACCEPTED (queued), which is the only part of the scan this side
// of the wire can observe -- whether the scan then ran is in the manager's own
// log/metrics, not here (docu/14-scan-vd.md).
var scanCounters = map[string]func(metrics.Counters) uint64{
	"sent":  func(c metrics.Counters) uint64 { return c.ScanSent },
	"s200":  func(c metrics.Counters) uint64 { return c.Scan200 },
	"s409":  func(c metrics.Counters) uint64 { return c.Scan409 },
	"s503":  func(c metrics.Counters) uint64 { return c.Scan503 },
	"other": func(c metrics.Counters) uint64 { return c.ScanOther },
}

var deleteCounters = map[string]func(metrics.Counters) uint64{
	"ok":  func(c metrics.Counters) uint64 { return c.DeletesOK },
	"err": func(c metrics.Counters) uint64 { return c.DeletesErr },
}

var validOps = map[string]bool{"eq": true, "gte": true, "lte": true}

// Validate strict-checks an expected block: unknown counter names and unknown
// operators are load-time errors, exactly like an unknown step kind -- a typo
// must not silently produce a weaker verdict. A nil block validates.
func Validate(exp *scenario.Expected) error {
	if exp == nil {
		return nil
	}
	groups := []struct {
		name    string
		table   map[string]func(metrics.Counters) uint64
		asserts map[string]scenario.Assertion
	}{
		{"sessions", sessionCounters, exp.Sessions},
		{"stateless", statelessCounters, exp.Stateless},
		{"control", controlCounters, exp.Control},
		{"deletes", deleteCounters, exp.Deletes},
		{"scan", scanCounters, exp.Scan},
	}
	for _, g := range groups {
		for counter, assertion := range g.asserts {
			if _, ok := g.table[counter]; !ok {
				return fmt.Errorf("expected.%s: unknown counter %q", g.name, counter)
			}
			if err := validAssertion(fmt.Sprintf("expected.%s.%s", g.name, counter), assertion); err != nil {
				return err
			}
		}
	}
	if err := validAssertion("expected.transport_errors", exp.TransportErrors); err != nil {
		return err
	}
	return validAssertion("expected.retries_exhausted", exp.RetriesExhausted)
}

func validAssertion(where string, a scenario.Assertion) error {
	if len(a) == 0 && a != nil {
		return fmt.Errorf("%s: empty assertion", where)
	}
	for op := range a {
		if !validOps[op] {
			return fmt.Errorf("%s: unknown operator %q (use eq, gte or lte)", where, op)
		}
	}
	return nil
}

// Count returns how many individual operator checks the block carries.
func Count(exp *scenario.Expected) int {
	if exp == nil {
		return 0
	}
	n := len(exp.TransportErrors) + len(exp.RetriesExhausted)
	for _, group := range []map[string]scenario.Assertion{exp.Sessions, exp.Stateless, exp.Control, exp.Deletes, exp.Scan} {
		for _, a := range group {
			n += len(a)
		}
	}
	return n
}

// Evaluate runs every assertion against the final total counters. It assumes a
// Validate()d block (unknown names would panic-by-omission otherwise).
func Evaluate(exp *scenario.Expected, c metrics.Counters) *Result {
	if exp == nil {
		return nil
	}
	res := &Result{Passed: true}
	check := func(where string, actual uint64, a scenario.Assertion) {
		// Deterministic failure order, so two runs of the same scenario report
		// the same first failure.
		ops := make([]string, 0, len(a))
		for op := range a {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			want := a[op]
			res.Checked++
			ok := false
			switch op {
			case "eq":
				ok = actual == want
			case "gte":
				ok = actual >= want
			case "lte":
				ok = actual <= want
			}
			if !ok {
				res.Passed = false
				res.Failures = append(res.Failures, fmt.Sprintf("%s: expected %s %d, got %d", where, op, want, actual))
			}
		}
	}

	groups := []struct {
		name    string
		table   map[string]func(metrics.Counters) uint64
		asserts map[string]scenario.Assertion
	}{
		{"sessions", sessionCounters, exp.Sessions},
		{"stateless", statelessCounters, exp.Stateless},
		{"control", controlCounters, exp.Control},
		{"deletes", deleteCounters, exp.Deletes},
		{"scan", scanCounters, exp.Scan},
	}
	for _, g := range groups {
		counters := make([]string, 0, len(g.asserts))
		for counter := range g.asserts {
			counters = append(counters, counter)
		}
		sort.Strings(counters)
		for _, counter := range counters {
			check(g.name+"."+counter, g.table[counter](c), g.asserts[counter])
		}
	}
	check("transport_errors", c.TransportErrors, exp.TransportErrors)
	check("retries_exhausted", c.RetriesExhausted, exp.RetriesExhausted)
	return res
}
