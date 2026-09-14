// Package enrollhttps enrolls a brand-new agent over POST /enroll with an
// enrollment-token bearer (issue #38993): the HTTPS self-enrollment a 5.x agent
// performs when the operator handed it a token minted with
// `wazuh-manager-authd --create-enrollment-token` instead of the shared
// password (docu/16-enroll-https.md).
//
// It serves two callers. As the `enroll_https` STEP it measures the path --
// remoted verifying the bearer against its replica of authd's token store,
// forwarding the token id to authd, authd consuming a use and minting the agent
// -- and as the fleet's BOOTSTRAP (`--bootstrap enroll-token`, issue #39054) it
// is how every simulated agent obtains the identity it then runs under, which is
// what lets the harness run against a manager whose <use_password> is the
// installed default. Every call enrolls a NEW name (authd answers 409 to a
// repeat), so the cost includes authd's client.keys write: it is what a fleet's
// first contact costs.
package enrollhttps

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

const path = "/enroll"

// Result is what the caller records: the status and latency, plus the record the
// manager answered a 200 with -- the agent id it assigned, the key its bearers
// are signed with and the re-enrollment secret. A measured step keeps only the
// status and the latency; the bootstrap adopts the whole record as the agent's
// identity.
type Result struct {
	Status  int
	Latency time.Duration
	AgentID string
	Key     string
	// ReenrollSecret is authd's `reenroll_secret`, absent only against a master
	// whose authd predates the field (agent-api.yaml), so it is never required.
	ReenrollSecret string
}

// ErrProtocol signals a run-invalidating answer: a 200 whose body is not the
// {id,name,ip,key} record, or a status the contract does not name (a 400 means
// the sender built a body remoted rejects; a 5xx that the manager's own
// contract does not describe for this route). Either means the measurement is
// not of the path it claims to be (docu/10).
type ErrProtocol struct{ msg string }

func (e *ErrProtocol) Error() string { return e.msg }

// enrollResponse is the 200 body of POST /enroll (agent-api.yaml): authd's
// record for the new agent, verbatim.
type enrollResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	IP             string `json:"ip"`
	Key            string `json:"key"`
	ReenrollSecret string `json:"reenroll_secret"`
}

// Request enrolls one agent name with the enrollment token whose key and id
// (the bearer's `kid`) the caller resolved once from the pasted token. name
// must be unique per call; version is what the agent claims to run (the
// manager may refuse a version newer than its own).
//
// 200 (agent created), 401 (the manager refused the bearer: unknown, expired
// or revoked token, or a clock/key problem), 403 (authd refused the use of a
// bearer remoted had verified: no uses left, or revoked/expired between the two
// checks) and 409 (duplicate name) are ORDINARY results the caller records; a
// scenario's `expected` block decides which are acceptable for the run.
func Request(c *wire.Client, key []byte, kid, name, version string, now int64) (Result, error) {
	body, err := json.Marshal(map[string]string{"name": name, "version": version})
	if err != nil {
		return Result{}, err
	}
	headers, err := wire.EnrollTokenAuthHeaders(key, kid, now)
	if err != nil {
		return Result{}, err
	}
	headers["Content-Type"] = "application/json"

	resp, err := c.DoWithHeaders("POST", path, body, headers)
	if err != nil {
		return Result{}, err
	}
	result := Result{Status: resp.Status, Latency: resp.Latency}

	switch resp.Status {
	case 200:
		var record enrollResponse
		if err := json.Unmarshal(resp.Body, &record); err != nil || record.ID == "" || record.Key == "" ||
			record.Name != name {
			return result, &ErrProtocol{fmt.Sprintf("enroll: 200 without the agent record for %q: %s", name, truncate(resp.Body))}
		}
		result.AgentID = record.ID
		result.Key = record.Key
		result.ReenrollSecret = record.ReenrollSecret
	case 401, 403, 409:
		// Contract outcomes, recorded as such.
	default:
		return result, &ErrProtocol{fmt.Sprintf("enroll answered %d: %s", resp.Status, truncate(resp.Body))}
	}
	return result, nil
}

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
