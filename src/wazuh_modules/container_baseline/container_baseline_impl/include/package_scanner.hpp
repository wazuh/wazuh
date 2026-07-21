#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One installed package read from a container's own package database.
///
/// Field names mirror the json PackageLinuxHelper::parseDpkg()/parseRpm()
/// emit (data_provider/src/packages/*.h) — those two helpers are reused
/// verbatim, so this struct is just their common key set plus container
/// context. `format` is "deb", "rpm" or "apk".
struct PackageBaselineRow
{
    std::string name;
    std::string version;
    std::string architecture;
    std::string description;
    int64_t     size{0};
    std::string vendor;
    std::string install_time;
    std::string category;
    std::string source;
    std::string format;

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Which package database(s) a rootfs carries. A normal image has
/// exactly one; distroless/scratch has none (empty result, not an error).
enum class PackageDbFormat
{
    Dpkg,        ///< /var/lib/dpkg/status               (Debian, Ubuntu)
    DpkgStatusD, ///< /var/lib/dpkg/status.d/<pkg>       (distroless: one status block per file)
    Apk,         ///< /lib/apk/db/installed              (Alpine)
    RpmSqlite,   ///< /var/lib/rpm/rpmdb.sqlite          (RHEL 9+, Fedora 37+)
    RpmBdb,      ///< /var/lib/rpm/Packages, BerkeleyDB  (RHEL 7/8, CentOS)
};

/// @brief Probe `rootfs` (a "/proc/<pid>/root"-style prefix) for known package
/// databases. Order is fixed: dpkg, apk, rpm-sqlite, rpm-bdb; rpm-bdb is only
/// reported when no rpmdb.sqlite exists (rpm ≥ 4.16 leaves both, sqlite wins).
[[nodiscard]] std::vector<PackageDbFormat> DetectPackageDbs(const std::string& rootfs);

/// @brief Parse one apk "installed" block (blank-line-separated, one-letter
/// "K:value" lines: P=name V=version A=arch T=description I=size m=maintainer
/// o=origin t=build-time). Exposed for unit testing.
/// @return false if the block has no P (name) line.
[[nodiscard]] bool ParseApkBlock(const std::vector<std::string>& block, PackageBaselineRow& row);

/// @brief Read every installed package from the container addressed by a live
/// `pid`, via /proc/<pid>/root/<db path>, across all databases DetectPackageDbs()
/// finds:
///   - dpkg:       PackageLinuxHelper::parseDpkg() reused verbatim (sysinfo's
///                 getDpkgInfo() is equally reusable — it already takes the
///                 status-file path — but linking it drags the python-package
///                 walker and FileSystemWrapper along, so only the parser
///                 header is included and the 20-line block loop is local).
///   - rpm (both backends): BerkeleyRpmDBReader reused verbatim — its blob
///                 parser is backend-agnostic behind IBerkeleyDbWrapper, so the
///                 BDB backend uses sysinfo's BerkeleyDbWrapper (vendored
///                 libdb, already on the shipped stack — contra the options
///                 matrix, which assumed no BDB parser existed) and the sqlite
///                 backend a local SqliteRpmDbWrapper over vendored sqlite3.
///   - apk:        local parser (no apk support exists anywhere in sysinfo).
[[nodiscard]] std::vector<PackageBaselineRow> ScanContainerPackages(pid_t pid);

} // namespace wazuh::container_baseline
