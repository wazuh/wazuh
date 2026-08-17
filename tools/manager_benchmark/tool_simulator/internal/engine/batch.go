// Package engine frames log events into the H/E batch remoted forwards to the
// engine over POST /stateless (docu/13-engine-event-streams.md). It knows
// nothing about transports.
package engine

import (
	"fmt"
	"strings"
)

// Batch builds the body of a POST /stateless request:
//
//	H {"wazuh":{"agent":{"id":"<agentID>"}}}
//	E <locationID>:<location>:<raw line>
//	E ...
//
// The H line's agent id MUST match the authenticated identity, or remoted
// answers 400. Each event is one line verbatim from the source log.
func Batch(agentID, locationID, location string, lines []string) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, `H {"wazuh":{"agent":{"id":%q}}}`, agentID)
	sb.WriteByte('\n')
	for _, line := range lines {
		fmt.Fprintf(&sb, "E %s:%s:%s\n", locationID, location, line)
	}
	return []byte(sb.String())
}
