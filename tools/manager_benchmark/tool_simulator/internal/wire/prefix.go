package wire

import (
	"fmt"
	"strings"
)

// Global endpoint prefix (<remote><https><global_prefix>) support.
//
// The prefix is part of the request target the manager ROUTES on; it plays no part in
// authentication (the wazuh-agent+jwt bearer binds the agent's identity, not the URL).
// So the one failure mode worth knowing when a run goes wrong is a prefix mismatch:
// sending the bare target against a prefixed manager (or the wrong prefix) -> 404, the
// route does not exist and auth is never reached. A 401 is never about the prefix.
//
// Client.Do prepends the prefix to the URL only; see client.go.

// NormalizeGlobalPrefix mirrors, byte for byte, normalize_global_prefix() in the manual
// senders (src/remoted/remoted_module/tools/send_control.py and the five other
// send_*.py): "" and "/" (and "///") mean no prefix; anything else gets a leading '/'
// and loses its trailing one.
//
// Deliberately lenient, like the Python: an interior "//" is preserved rather than
// rejected, so the simulator can reproduce a malformed prefix on purpose and observe how
// the manager answers. The manager's own normalizer (httpServerConfig.cpp
// normalizeGlobalPrefix) is stricter, not different — it agrees on every value it
// accepts. GlobalPrefixWarning reports the difference without blocking.
func NormalizeGlobalPrefix(raw string) string {
	stripped := strings.Trim(raw, "/")
	if stripped == "" {
		return ""
	}
	return "/" + stripped
}

// globalPrefixAllowedRunes is the charset the manager accepts in a prefix
// (httpServerConfig.cpp): RFC 3986 unreserved characters plus the path separator.
func globalPrefixAllowedRune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '.', r == '_', r == '~', r == '-', r == '/':
		return true
	}
	return false
}

// GlobalPrefixWarning returns a human-readable reason when prefix (already through
// NormalizeGlobalPrefix) is one the manager would refuse to start with, or "" when it
// looks fine.
//
// It is a warning and never an error on purpose: sending a malformed prefix is a
// legitimate thing to ask this tool to do. Its value is that the alternative symptom —
// every request answering 404 — is indistinguishable from a broken manager, so a typo
// would otherwise cost a whole run to diagnose.
func GlobalPrefixWarning(prefix string) string {
	if prefix == "" {
		return ""
	}
	if strings.Contains(prefix, "//") {
		return fmt.Sprintf("%q contains an empty path segment (\"//\"); the manager refuses to start with it", prefix)
	}
	for _, r := range prefix {
		if !globalPrefixAllowedRune(r) {
			return fmt.Sprintf("%q contains %q, outside the charset the manager accepts (A-Za-z0-9 . _ ~ - /)", prefix, r)
		}
	}
	for _, seg := range strings.Split(strings.TrimPrefix(prefix, "/"), "/") {
		if seg == "." || seg == ".." {
			return fmt.Sprintf("%q contains a %q segment; the manager refuses to start with it", prefix, seg)
		}
	}
	return ""
}
