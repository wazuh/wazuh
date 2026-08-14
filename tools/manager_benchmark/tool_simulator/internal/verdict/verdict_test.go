package verdict

import (
	"strings"
	"testing"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/metrics"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

func TestNoBlockMeansNoVerdict(t *testing.T) {
	if err := Validate(nil); err != nil {
		t.Fatalf("nil block must validate, got %v", err)
	}
	if res := Evaluate(nil, metrics.Counters{}); res != nil {
		t.Fatalf("nil block must produce no verdict, got %+v", res)
	}
	if n := Count(nil); n != 0 {
		t.Fatalf("nil block carries no checks, got %d", n)
	}
}

func TestValidateRefusesUnknownCounterAndOperator(t *testing.T) {
	bad := &scenario.Expected{Sessions: map[string]scenario.Assertion{"s404": {"eq": 0}}}
	if err := Validate(bad); err == nil || !strings.Contains(err.Error(), "s404") {
		t.Fatalf("unknown counter must be refused by name, got %v", err)
	}
	bad = &scenario.Expected{Stateless: map[string]scenario.Assertion{"s202": {"ge": 1}}}
	if err := Validate(bad); err == nil || !strings.Contains(err.Error(), `"ge"`) {
		t.Fatalf("unknown operator must be refused by name, got %v", err)
	}
	bad = &scenario.Expected{Deletes: map[string]scenario.Assertion{"ok": {}}}
	if err := Validate(bad); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty assertion asserts nothing and must be refused, got %v", err)
	}
}

func TestEvaluateAllOperators(t *testing.T) {
	c := metrics.Counters{SessionsOK: 48, S413: 3, St202: 10, DeletesErr: 0}
	exp := &scenario.Expected{
		Sessions: map[string]scenario.Assertion{
			"ok":   {"eq": 48},
			"s413": {"gte": 1, "lte": 5}, // conjunction on one counter
			"s5xx": {"eq": 0},
		},
		Stateless: map[string]scenario.Assertion{"s202": {"gte": 10}},
		Deletes:   map[string]scenario.Assertion{"err": {"lte": 0}},
	}
	if err := Validate(exp); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res := Evaluate(exp, c)
	if !res.Passed {
		t.Fatalf("expected pass, failures: %v", res.Failures)
	}
	if res.Checked != 6 || Count(exp) != 6 {
		t.Fatalf("expected 6 checks, got evaluated=%d counted=%d", res.Checked, Count(exp))
	}
}

func TestEvaluateReportsEveryFailureWithActuals(t *testing.T) {
	c := metrics.Counters{SessionsOK: 40, S500: 2, S503: 1}
	exp := &scenario.Expected{
		Sessions:        map[string]scenario.Assertion{"ok": {"eq": 48}, "s5xx": {"eq": 0}},
		TransportErrors: scenario.Assertion{"eq": 0},
	}
	res := Evaluate(exp, c)
	if res.Passed {
		t.Fatal("expected failure")
	}
	if len(res.Failures) != 2 {
		t.Fatalf("both failed assertions must be reported, got %v", res.Failures)
	}
	// The message carries the actual value: that is what makes a CI log readable.
	if !strings.Contains(res.Failures[0], "got 40") || !strings.Contains(res.Failures[1], "got 3") {
		t.Fatalf("failures must name the actual values (40, 3=derived s5xx), got %v", res.Failures)
	}
}

func TestDerivedS5xxExcludesTheUntypedOtherBucket(t *testing.T) {
	// "other" may hold a 429 as well as a 502: it cannot be claimed as 5xx.
	c := metrics.Counters{SessOther: 7}
	res := Evaluate(&scenario.Expected{Sessions: map[string]scenario.Assertion{"s5xx": {"eq": 0}}}, c)
	if !res.Passed {
		t.Fatalf("other-bucket responses must not count as s5xx: %v", res.Failures)
	}
}
