package wire

import "fmt"

// AgentVersion is hard-coded to match the value the Python sender uses in
// the post-connect control message. See benchmark_sender.py connect().
const AgentVersion = "5.0.0"

// BuildStartupControlMessage returns the literal text payload for the
// `#!-agent startup` control frame that an agent emits immediately after
// connecting to remoted. Wrap it via EncodeText.
func BuildStartupControlMessage(name, id string) string {
	return fmt.Sprintf(`#!-agent startup {"version":"%s","name":"%s","id":"%s"}`, AgentVersion, name, id)
}
