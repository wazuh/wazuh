// Package engine frames log events into the H/E batch an engine ingress
// accepts: remoted's POST /stateless (agent mode) or the engine's own
// POST /events/enriched (uds mode) (docu/13-engine-event-streams.md). It knows
// nothing about transports.
package engine

import (
	"encoding/json"
	"fmt"
	"sort"
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
	// Profile "agent" writes the members a real agent reports about itself
	// (AgentInfo) in the layout the agent sends them; "" (the default) writes
	// only the id.
	Profile string `json:"profile"`
}

// ProfileAgent is the HeaderSpec.Profile of a real agent's H line.
const ProfileAgent = "agent"

// AgentInfo is what an agent reports about itself in its H line
// (docs/ref/modules/remoted/event-protocol.md, "Field Specifications"). Empty
// strings and an empty Groups are omitted, as the agent omits them.
type AgentInfo struct {
	Name         string
	Version      string
	Groups       []string
	Architecture string
	Hostname     string
	OSName       string
	OSPlatform   string
	OSType       string
	OSVersion    string
	ClusterName  string
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
	return HeaderLineFor(agentID, nil, spec, seq)
}

// HeaderLineFor is HeaderLine with the agent's own metadata, which the "agent"
// profile writes; info is ignored by the default profile and may be nil.
func HeaderLineFor(agentID string, info *AgentInfo, spec *HeaderSpec, seq int) string {
	if spec == nil {
		return `{"wazuh":{"agent":{"id":` + strconv.Quote(agentID) + `}}}`
	}
	unpadded := buildHeader(agentID, info, spec, seq, -1)
	if spec.PadBytes <= 0 {
		return unpadded
	}
	emptyPad := buildHeader(agentID, info, spec, seq, 0)
	if spec.PadBytes < len(emptyPad) {
		return unpadded
	}
	return buildHeader(agentID, info, spec, seq, spec.PadBytes-len(emptyPad))
}

// MinHeaderBytes is the smallest H-line JSON spec can produce for any
// canonical agent id, padding member included when spec pads: the size of the
// header of the widest id. A PadBytes below it cannot be reached by every
// agent of a fleet.
func MinHeaderBytes(spec *HeaderSpec) int {
	return MinHeaderBytesFor(nil, spec)
}

// MinHeaderBytesFor is MinHeaderBytes for an agent reporting info.
func MinHeaderBytesFor(info *AgentInfo, spec *HeaderSpec) int {
	if spec == nil {
		return len(HeaderLine(widestAgentID, nil, 0))
	}
	padLen := -1
	if spec.PadBytes > 0 {
		padLen = 0
	}
	// The widest bench_seq a run reaches is unknown here; one digit is the
	// floor, and every later value only adds digits, which the padding absorbs.
	return len(buildHeader(widestAgentID, info, spec, 0, padLen))
}

// jsonString encodes s as a JSON string: profile values come from scenario
// text, so they must not be able to break out of their quotes.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// member is one "name":value pair of an object being written.
type member struct{ name, value string }

// object writes members as a JSON object, sorted by name when sorted is set:
// the agent builds its H line with nlohmann::json, whose objects are ordered
// maps, so a real header lists every object's members by name.
func object(members []member, sorted bool) string {
	if sorted {
		sort.SliceStable(members, func(i, j int) bool { return members[i].name < members[j].name })
	}
	parts := make([]string, len(members))
	for i, m := range members {
		parts[i] = jsonString(m.name) + ":" + m.value
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// profileMembers are the wazuh.agent members an agent reports besides its id.
func profileMembers(info *AgentInfo) []member {
	if info == nil {
		info = &AgentInfo{}
	}
	var out []member
	add := func(to *[]member, name, value string) {
		if value != "" {
			*to = append(*to, member{name, jsonString(value)})
		}
	}
	add(&out, "name", info.Name)
	add(&out, "version", info.Version)
	if len(info.Groups) > 0 {
		groups := make([]string, len(info.Groups))
		for i, g := range info.Groups {
			groups[i] = jsonString(g)
		}
		out = append(out, member{"groups", "[" + strings.Join(groups, ",") + "]"})
	}
	var os, host []member
	add(&os, "name", info.OSName)
	add(&os, "version", info.OSVersion)
	add(&os, "platform", info.OSPlatform)
	add(&os, "type", info.OSType)
	add(&host, "architecture", info.Architecture)
	add(&host, "hostname", info.Hostname)
	// The agent always sends host and host.os, empty or not.
	host = append(host, member{"os", object(os, true)})
	return append(out, member{"host", object(host, true)})
}

// buildHeader writes the shaped header. padLen < 0 omits the filler member;
// padLen >= 0 writes it with that many filler characters.
func buildHeader(agentID string, info *AgentInfo, spec *HeaderSpec, seq, padLen int) string {
	real := spec.Profile == ProfileAgent
	var agent []member
	idMember := member{"id", strconv.Quote(agentID)}
	if real || spec.IDPosition != "last" {
		agent = append(agent, idMember)
	}
	if real {
		agent = append(agent, profileMembers(info)...)
	}
	for i := 0; i < spec.ExtraFields; i++ {
		agent = append(agent, member{fmt.Sprintf("bench_field_%d", i), fmt.Sprintf(`"value_%d"`, i)})
	}
	if spec.ChangeEvery > 0 {
		agent = append(agent, member{"bench_seq", strconv.Itoa(seq)})
	}
	if padLen >= 0 {
		agent = append(agent, member{"bench_pad", `"` + strings.Repeat("x", padLen) + `"`})
	}
	if !real && spec.IDPosition == "last" {
		agent = append(agent, idMember)
	}

	wazuh := []member{{"agent", object(agent, real)}}
	if real {
		// The agent always sends cluster, as agent's sibling, with only its name.
		var cluster []member
		if info != nil && info.ClusterName != "" {
			cluster = append(cluster, member{"name", jsonString(info.ClusterName)})
		}
		wazuh = append(wazuh, member{"cluster", object(cluster, true)})
	}
	root := []member{{"wazuh", object(wazuh, real)}}
	if spec.OffPathFields > 0 {
		off := make([]member, spec.OffPathFields)
		for i := range off {
			off[i] = member{fmt.Sprintf("field_%d", i), fmt.Sprintf(`"value_%d"`, i)}
		}
		root = append(root, member{"bench", object(off, false)})
	}
	return object(root, real)
}
