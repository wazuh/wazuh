package wire

import "testing"

// The table IS the parity contract with the manual senders' normalize_global_prefix()
// (src/remoted/remoted_module/tools/send_*.py) and with the manager's own normalizer
// (httpServerConfig.cpp). A change here that is not mirrored there is a bug: the URL
// this tool sends would stop matching the route the manager registered (404).
func TestNormalizeGlobalPrefix(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"/", ""},
		{"//", ""},
		{"///", ""},
		{"wazuh-manager", "/wazuh-manager"},
		{"/wazuh-manager", "/wazuh-manager"},
		{"/wazuh-manager/", "/wazuh-manager"},
		{"wazuh-manager/", "/wazuh-manager"},
		{"//wazuh-manager//", "/wazuh-manager"},
		{"/edge/wazuh-5/", "/edge/wazuh-5"},
		{"/a/b", "/a/b"},
		// Lenient like the Python: an interior "//" survives normalization so the
		// simulator can send a prefix the manager would refuse.
		{"/a//b/", "/a//b"},
	}
	for _, tc := range cases {
		if got := NormalizeGlobalPrefix(tc.raw); got != tc.want {
			t.Errorf("NormalizeGlobalPrefix(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestGlobalPrefixWarning(t *testing.T) {
	quiet := []string{"", "/wazuh-manager", "/a/b", "/a-b_c.d~e", "/5"}
	for _, p := range quiet {
		if w := GlobalPrefixWarning(p); w != "" {
			t.Errorf("GlobalPrefixWarning(%q) = %q, want no warning", p, w)
		}
	}

	// Values the manager refuses to start with. The warning must not block them --
	// sending one on purpose is a legitimate use -- but it must be reported.
	loud := []string{"/a//b", "/a?b", "/a b", "/a%20b", "/a:b", "/a*b", "/..", "/a/../b", "/a/./b"}
	for _, p := range loud {
		if GlobalPrefixWarning(p) == "" {
			t.Errorf("GlobalPrefixWarning(%q) = \"\", want a warning", p)
		}
	}
}
