// Package engine frames log events into the H/E batch an engine ingress
// accepts: remoted's POST /stateless (agent mode) or the engine's own
// POST /events/enriched (uds mode) (docu/13-engine-event-streams.md). It knows
// nothing about transports.
package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxStatelessHeaderBytes is remoted's cap on the H-line JSON of a POST
// /stateless body: a larger header is answered 400 before it is parsed
// (src/remoted/remoted_module/src/endpoints/statelessEndpoint.cpp).
const MaxStatelessHeaderBytes = 8192

// widestAgentID is the longest id a canonical agent id can spell (ten digits),
// so a size computed with it bounds the header of every real agent.
const widestAgentID = "4294967295"

// HeaderSpec shapes the H line of an engine step, so a run can measure how the
// header's size and layout drive the identity check and the engine's metadata
// cache. A nil spec produces the minimal header an agent sends.
type HeaderSpec struct {
	// PadBytes is the exact size of the H-line JSON (the text after "H ").
	// A filler member under wazuh.agent, off the identity path, is grown to
	// reach it. 0 leaves the header unpadded.
	PadBytes int `json:"pad_bytes"`
	// ExtraFields adds that many string members under wazuh.agent.
	ExtraFields int `json:"extra_fields"`
	// OffPathFields adds that many string members under a root "bench"
	// object, outside wazuh.
	OffPathFields int `json:"off_path_fields"`
	// IDPosition places wazuh.agent.id "first" (the default) or "last"
	// among the members of wazuh.agent.
	IDPosition string `json:"id_position"`
	// ChangeEvery changes the header every that many batches an agent sends,
	// through a wazuh.agent.bench_seq member, so the engine sees a new header
	// for a known agent. 0 never changes it.
	ChangeEvery int `json:"change_every"`
}

// Batch builds the body of an engine batch with the minimal header:
//
//	H {"wazuh":{"agent":{"id":"<agentID>"}}}
//	E <locationID>:<location>:<raw line>
//	E ...
//
// The H line's agent id MUST match the authenticated identity, or the batch is
// answered 400. Each event is one line verbatim from the source log.
func Batch(agentID, locationID, location string, lines []string) []byte {
	return BatchWithHeader(HeaderLine(agentID, nil, 0), locationID, location, lines)
}

// BatchWithHeader builds the body of an engine batch around an H-line JSON
// built by HeaderLine.
func BatchWithHeader(headerJSON, locationID, location string, lines []string) []byte {
	var sb strings.Builder
	sb.WriteString("H ")
	sb.WriteString(headerJSON)
	sb.WriteByte('\n')
	for _, line := range lines {
		fmt.Fprintf(&sb, "E %s:%s:%s\n", locationID, location, line)
	}
	return []byte(sb.String())
}

// HeaderLine returns the H-line JSON for agentID shaped by spec, with seq as
// the value of wazuh.agent.bench_seq when spec.ChangeEvery is set. Members are
// written in a fixed order, so equal inputs always give equal bytes: the
// engine's cache compares headers byte for byte. When spec.PadBytes is smaller
// than the unpadded header, the header is returned unpadded; the scenario
// loader refuses such a spec (MinHeaderBytes).
func HeaderLine(agentID string, spec *HeaderSpec, seq int) string {
	if spec == nil {
		return `{"wazuh":{"agent":{"id":` + strconv.Quote(agentID) + `}}}`
	}
	unpadded := buildHeader(agentID, spec, seq, -1)
	if spec.PadBytes <= 0 {
		return unpadded
	}
	emptyPad := buildHeader(agentID, spec, seq, 0)
	if spec.PadBytes < len(emptyPad) {
		return unpadded
	}
	return buildHeader(agentID, spec, seq, spec.PadBytes-len(emptyPad))
}

// MinHeaderBytes is the smallest H-line JSON spec can produce for any
// canonical agent id, padding member included when spec pads: the size of the
// header of the widest id. A PadBytes below it cannot be reached by every
// agent of a fleet.
func MinHeaderBytes(spec *HeaderSpec) int {
	if spec == nil {
		return len(HeaderLine(widestAgentID, nil, 0))
	}
	padLen := -1
	if spec.PadBytes > 0 {
		padLen = 0
	}
	// The widest bench_seq a run reaches is unknown here; one digit is the
	// floor, and every later value only adds digits, which the padding absorbs.
	return len(buildHeader(widestAgentID, spec, 0, padLen))
}

// buildHeader writes the shaped header. padLen < 0 omits the filler member;
// padLen >= 0 writes it with that many filler characters.
func buildHeader(agentID string, spec *HeaderSpec, seq, padLen int) string {
	var agent []string
	idMember := `"id":` + strconv.Quote(agentID)
	if spec.IDPosition != "last" {
		agent = append(agent, idMember)
	}
	for i := 0; i < spec.ExtraFields; i++ {
		agent = append(agent, fmt.Sprintf(`"bench_field_%d":"value_%d"`, i, i))
	}
	if spec.ChangeEvery > 0 {
		agent = append(agent, `"bench_seq":`+strconv.Itoa(seq))
	}
	if padLen >= 0 {
		agent = append(agent, `"bench_pad":"`+strings.Repeat("x", padLen)+`"`)
	}
	if spec.IDPosition == "last" {
		agent = append(agent, idMember)
	}

	var sb strings.Builder
	sb.WriteString(`{"wazuh":{"agent":{`)
	sb.WriteString(strings.Join(agent, ","))
	sb.WriteString(`}}`)
	if spec.OffPathFields > 0 {
		off := make([]string, spec.OffPathFields)
		for i := range off {
			off[i] = fmt.Sprintf(`"field_%d":"value_%d"`, i, i)
		}
		sb.WriteString(`,"bench":{`)
		sb.WriteString(strings.Join(off, ","))
		sb.WriteString(`}`)
	}
	sb.WriteString(`}`)
	return sb.String()
}
