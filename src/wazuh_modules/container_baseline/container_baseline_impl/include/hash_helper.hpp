#pragma once

#include <string>

namespace wazuh::container_baseline {

/// @brief One file's md5/sha1/sha256 digests, lowercase hex, matching the exact
/// wire format of FIM's os_md5/os_sha1/os_sha256 (32/40/64 hex chars) so baseline
/// rows are drop-in compatible with fim_file_data's hash fields.
struct FileHashes
{
    std::string md5;
    std::string sha1;
    std::string sha256;
};

/// @brief Hash a file's contents with MD5+SHA1+SHA256 in a single read pass.
///
/// Reused algorithm (not the exact os_crypto binary — see rootfs_file_walker.hpp
/// for why this module hashes via OpenSSL EVP directly instead of linking the
/// `wazuh` static lib): read in fixed-size chunks, feed all three EVP_MD_CTX
/// digests per chunk, hex-encode at the end.
///
/// @param path Host-visible path to read (e.g. /proc/<pid>/root/<rel>).
/// @param max_bytes Stop hashing after this many bytes (0 = no limit). Mirrors
///                   FIM's own size-capped hashing behavior for huge files.
/// @return true on success; false if the file could not be opened for reading.
///         On failure `out` is left with empty strings.
bool HashFile(const std::string& path, size_t max_bytes, FileHashes& out);

} // namespace wazuh::container_baseline
