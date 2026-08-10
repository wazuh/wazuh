import sys
import types

import pytest

# check_files.py imports pandas at module load time, but path_match does not
# need it. Provide a lightweight stub so the module can be imported in a plain
# test environment (the real pandas is used if it happens to be installed).
sys.modules.setdefault('pandas', types.ModuleType('pandas'))

from check_files import path_match  # noqa: E402


class TestPathMatch:
    """Tests for the glob matching used against the expected-files CSV."""

    @pytest.mark.parametrize("filename", [
        # The temp directory name expands to different lengths; every one of
        # these must match the same pattern. Long expansions used to break the
        # previous length-based check and were wrongly reported as unexpected.
        "/var/ossec/tmp/sca-4.9-x-tmp/rhel/8/sca.files",
        "/var/ossec/tmp/sca-4.14.8-a1b2c3-tmp/rhel/8/sca.files",
        "/var/ossec/tmp/sca-4.14.8-12345678901234-tmp/rhel/8/sca.files",
        "/var/ossec/tmp/sca-4.14.8-0000000000000000000000-tmp/rhel/8/sca.files",
    ])
    def test_wildcard_in_middle_segment_any_length(self, filename):
        pattern = "/var/ossec/tmp/sca-4.*-*-tmp/rhel/8/sca.files"
        assert path_match(filename, pattern)

    def test_wildcard_does_not_cross_directory_separator(self):
        # A '*' inside a segment must not swallow additional directories.
        pattern = "/var/ossec/tmp/sca-4.*-*-tmp/rhel/8/sca.files"
        filename = "/var/ossec/tmp/sca-4.14.8-x/extra/y-tmp/rhel/8/sca.files"
        assert not path_match(filename, pattern)

    def test_trailing_wildcard_matches_exact_and_suffix(self):
        pattern = "/var/ossec/ruleset/sca/cis_alma_linux_8.yml*"
        assert path_match("/var/ossec/ruleset/sca/cis_alma_linux_8.yml", pattern)
        assert path_match("/var/ossec/ruleset/sca/cis_alma_linux_8.yml.gz", pattern)

    def test_trailing_wildcard_does_not_match_deeper_path(self):
        pattern = "/var/ossec/ruleset/sca/cis_alma_linux_8.yml*"
        filename = "/var/ossec/ruleset/sca/cis_alma_linux_8.yml/child"
        assert not path_match(filename, pattern)

    def test_different_segment_count_is_not_a_match(self):
        pattern = "/var/ossec/tmp/sca-4.*-*-tmp/rhel/8/sca.files"
        assert not path_match("/var/ossec/tmp/sca-4.14.8-x-tmp/rhel/8", pattern)

    def test_literal_path_without_wildcards(self):
        pattern = "/var/ossec/etc/ossec.conf"
        assert path_match("/var/ossec/etc/ossec.conf", pattern)
        assert not path_match("/var/ossec/etc/ossec.conf.bak", pattern)

    def test_windows_backslash_paths(self):
        pattern = r"C:\Program Files (x86)\ossec-agent\*.dll"
        assert path_match(r"C:\Program Files (x86)\ossec-agent\dbsync.dll", pattern)
        # The wildcard must stay within its segment on Windows too.
        assert not path_match(
            r"C:\Program Files (x86)\ossec-agent\sub\dbsync.dll", pattern)
