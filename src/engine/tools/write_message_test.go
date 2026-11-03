// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rawBatch(id string) string {
	return fmt.Sprintf("H {\"wazuh\":{\"agent\":{\"id\":%q}}}\nE 1:syslog:hello\n", id)
}

func TestRawRequestUsesItsOwnIdentityAndPreservesBytes(t *testing.T) {
	for _, id := range []string{"000", "001", "123", "1000", "4294967295"} {
		t.Run(id, func(t *testing.T) {
			body := rawBatch(id) + " continuation\n H literal continuation\n"
			req, err := eventRequest(body, 9999, true, "application/x-ndjson", "")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(req.Body)
			if string(got) != body || req.Header.Get("X-Wazuh-Agent-Id") != id {
				t.Fatalf("header=%q body=%q", req.Header.Get("X-Wazuh-Agent-Id"), got)
			}
			if _, err = eventRequest(body, 0, true, "application/x-ndjson", id); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := eventRequest(rawBatch("001"), 0, true, "application/x-ndjson", "002"); err == nil {
		t.Fatal("expected explicit ID mismatch")
	}
}

func TestInvalidRawIdentityFailsBeforeSending(t *testing.T) {
	for _, body := range []string{"", "E 1:syslog:hello\n", "H broken\n", "H {}\n", `H {"wazuh":{"agent":{"id":1}}}`,
		rawBatch(""), rawBatch("1"), rawBatch("0001"), rawBatch("-1"), rawBatch("4294967296"), rawBatch("001") + rawBatch("002")} {
		t.Run(body, func(t *testing.T) {
			if _, err := eventRequest(body, 1, true, "application/x-ndjson", ""); err == nil {
				t.Fatal("accepted invalid raw identity")
			}
		})
	}
}

func TestRawFileKeepsWholeBatchesAndLargeContinuationLines(t *testing.T) {
	first := rawBatch("007") + " " + strings.Repeat("x", 128*1024) + "\n H embedded marker\n"
	second := rawBatch("042")
	file := filepath.Join(t.TempDir(), "batches.log")
	if err := os.WriteFile(file, []byte(first+second), 0600); err != nil {
		t.Fatal(err)
	}
	batches, err := readMessages(file, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || batches[0] != first || batches[1] != second {
		t.Fatal("raw batch boundaries changed")
	}
	for i, want := range []string{"007", "042"} {
		req, err := eventRequest(batches[i], 1000+i, true, "application/x-wev1", "")
		if err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("X-Wazuh-Agent-Id"); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
	for _, body := range []string{"", "E 1:syslog:orphan\n", rawBatch("007") + "H {}\n"} {
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readMessages(file, true); err == nil {
			t.Fatal("accepted malformed batch file")
		}
	}
}

func TestGeneratedMessagesRetainMatchingHeaderAndBody(t *testing.T) {
	req, err := eventRequest("hello", 1000, false, "application/x-ndjson", "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	id, err := rawAgentID(string(body))
	if err != nil {
		t.Fatal(err)
	}
	if id != "1000" || req.Header.Get("X-Wazuh-Agent-Id") != id {
		t.Fatal("generated identity mismatch")
	}
	file := filepath.Join(t.TempDir(), "lines.log")
	if err := os.WriteFile(file, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := readMessages(file, false)
	if err != nil || len(lines) != 2 || lines[0] != "one" || lines[1] != "two" {
		t.Fatalf("lines=%v err=%v", lines, err)
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestEngineRejectionIncludesResponseDetail(t *testing.T) {
	client := &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Wazuh-Agent-Id") != "007" {
			t.Fatal("wrong carrier")
		}
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"invalid identity"}`)), Header: make(http.Header)}, nil
	})}
	err := sendEvent(client, rawBatch("007"), 1000, true, "application/x-ndjson", "")
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "invalid identity") {
		t.Fatalf("error=%v", err)
	}
}
