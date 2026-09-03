#pragma once

#include <cstddef>
#include <string>

namespace wazuh::container_baseline {

/// @brief Hex digests of a file. A field is empty when that digest was not
/// requested, or when the file could not be read.
struct FileHashes
{
    std::string md5;
    std::string sha1;
    std::string sha256;
};

/// @brief Which digests to compute. Mirrors FIM's CHECK_MD5SUM / CHECK_SHA1SUM
/// / CHECK_SHA256SUM options, so a container walk pays for exactly the digests
/// the configuration asked for instead of always computing all three.
struct HashSelection
{
    bool md5{true};
    bool sha1{true};
    bool sha256{true};

    [[nodiscard]] bool any() const noexcept { return md5 || sha1 || sha256; }
};

/// @brief Compute the requested digests over the WHOLE file, in a single pass.
///
/// There is deliberately no byte limit here. A digest of a file prefix is not a
/// weaker version of the file's hash — it is a different value that matches no
/// other reader's, and that collides for any two files sharing that prefix,
/// which in a file-integrity feature is worse than reporting no hash. Callers
/// that must bound I/O decide NOT TO HASH a file (leaving the digests empty),
/// exactly as host FIM does with syscheck.file_max_size; they do not ask for a
/// partial digest.
///
/// @param path Host-side path to read (for containers, under /proc/<pid>/root).
/// @param out Receives the hex digests; requested-but-uncomputable digests stay empty.
/// @param selection Which digests to compute.
/// @return false if the file could not be opened, or no digest was requested.
bool HashFile(const std::string& path, FileHashes& out, const HashSelection& selection = {});

} // namespace wazuh::container_baseline
