#include "package_scanner.hpp"

// Reused verbatim from sysinfo (data_provider) — parse helpers are header-only,
// so including them costs no sysinfo link (see package_scanner.hpp rationale):
//   - PackageLinuxHelper::parseDpkg()  (packageLinuxParserHelper.h)
//   - PackageLinuxHelper::parseRpm()   (packageLinuxRpmParserHelperLegacy.h)
//   - BerkeleyRpmDBReader + BerkeleyDbWrapper (vendored libdb)
#include "berkeleyDbWrapper.h"
#include "berkeleyRpmDbHelper.h"
#include "packageLinuxParserHelper.h"
#include "packageLinuxRpmParserHelperLegacy.h"

#include <sqlite3.h>
#include <stdlib.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

namespace {

constexpr auto kDpkgStatusPath   = "/var/lib/dpkg/status";
constexpr auto kDpkgStatusDDir   = "/var/lib/dpkg/status.d";
constexpr auto kApkInstalledPath = "/lib/apk/db/installed";

// rpm keeps its db under /var/lib/rpm classically; newer Fedora moved it to
// /usr/lib/sysimage/rpm with /var/lib/rpm a symlink there. The symlink case is
// already covered by the first probe — /proc/<pid>/root is a chroot-like view,
// so absolute symlinks inside it resolve against the *container's* root — but
// probe both in case an image ships only the sysimage location. First hit wins
// so a symlinked layout is never scanned twice.
constexpr const char* kRpmSqliteProbes[] = {"/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite"};
constexpr const char* kRpmBdbProbes[]    = {"/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/Packages"};

[[nodiscard]] bool RegularFileExists(const std::string& path)
{
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

[[nodiscard]] std::string FirstExisting(const std::string& rootfs, const char* const (&probes)[2])
{
    for (const auto* probe : probes) {
        if (auto path = rootfs + probe; RegularFileExists(path)) return path;
    }
    return {};
}

/// sqlite's unix VFS canonicalizes the database path (symlinks fully
/// resolved), and /proc/<pid>/root is a magic symlink to the container's "/":
/// canonicalization collapses the path onto the *host's* filesystem, where it
/// doesn't exist — sqlite3_open_v2() on the /proc path fails outright, even
/// though plain open()/read() on it works. The db is therefore copied to a
/// private temp dir and opened there. That also solves two problems a direct
/// open would have anyway: no lock/journal side-files ever touch the
/// container's rootfs (which may be a read-only layer), and a pending -wal
/// left by rpm can be applied, since the copy is ours to write.
class TempDbCopy final
{
    public:
        explicit TempDbCopy(const std::string& db_path)
        {
            char tmpl[] = "/tmp/wazuh_cbaseline_rpmdb_XXXXXX";
            if (::mkdtemp(tmpl) == nullptr) {
                throw std::runtime_error{"Failed to create temp dir for rpmdb copy"};
            }
            m_dir  = tmpl;
            m_copy = m_dir + "/rpmdb.sqlite";

            std::filesystem::copy_file(db_path, m_copy);
            std::error_code ec;
            std::filesystem::copy_file(db_path + "-wal", m_copy + "-wal", ec); // optional sidecar.
        }

        ~TempDbCopy()
        {
            std::error_code ec;
            std::filesystem::remove_all(m_dir, ec);
        }

        TempDbCopy(const TempDbCopy&) = delete;
        TempDbCopy& operator=(const TempDbCopy&) = delete;

        [[nodiscard]] const std::string& path() const noexcept { return m_copy; }

    private:
        std::string m_dir;
        std::string m_copy;
};

/// Serves rpmdb.sqlite package-header blobs through the same one-method
/// interface BerkeleyDbWrapper implements, so BerkeleyRpmDBReader's
/// backend-agnostic header-blob parser handles both RPM backends unchanged.
class SqliteRpmDbWrapper final : public IBerkeleyDbWrapper
{
    public:
        explicit SqliteRpmDbWrapper(const std::string& db_path)
            : m_temp_copy{db_path}
        {
            sqlite3* db = nullptr;

            // READWRITE on the private copy: lets sqlite recover/apply the
            // copied -wal, which a read-only open is not allowed to do.
            if (sqlite3_open_v2(m_temp_copy.path().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
                const std::string msg = (db != nullptr) ? sqlite3_errmsg(db) : "out of memory";
                sqlite3_close(db);
                throw std::runtime_error{"Failed to open rpmdb '" + db_path + "': " + msg};
            }
            m_db.reset(db);

            sqlite3_stmt* stmt = nullptr;

            if (sqlite3_prepare_v2(m_db.get(), "SELECT blob FROM Packages ORDER BY hnum;", -1, &stmt, nullptr) !=
                    SQLITE_OK) {
                throw std::runtime_error{"Failed to query rpmdb '" + db_path + "': " + sqlite3_errmsg(m_db.get())};
            }
            m_stmt.reset(stmt);
        }

        int32_t getRow(DBT& key, DBT& data) override
        {
            std::memset(&key, 0, sizeof(DBT));
            std::memset(&data, 0, sizeof(DBT));

            // BerkeleyRpmDBReader unconditionally skips the first row it reads
            // (the BDB Packages file starts with a metadata record). sqlite has
            // no such record, so serve one synthetic empty row for that skip.
            if (m_synthetic_first_row) {
                m_synthetic_first_row = false;
                return 0;
            }

            if (sqlite3_step(m_stmt.get()) != SQLITE_ROW) return 1; // non-zero = cursor end.

            const auto* blob = sqlite3_column_blob(m_stmt.get(), 0);
            const auto  size = sqlite3_column_bytes(m_stmt.get(), 0);
            if (blob == nullptr || size <= 0) return getRow(key, data); // NULL blob row: skip to the next.

            m_current_blob.assign(static_cast<const uint8_t*>(blob), static_cast<const uint8_t*>(blob) + size);
            data.data = m_current_blob.data();
            data.size = static_cast<u_int32_t>(m_current_blob.size());
            return 0;
        }

    private:
        struct SqliteCloser
        {
            void operator()(sqlite3* db) const { sqlite3_close(db); }
            void operator()(sqlite3_stmt* stmt) const { sqlite3_finalize(stmt); }
        };

        TempDbCopy                                  m_temp_copy;
        std::unique_ptr<sqlite3, SqliteCloser>      m_db;
        std::unique_ptr<sqlite3_stmt, SqliteCloser> m_stmt;
        std::vector<uint8_t>                        m_current_blob;
        bool                                        m_synthetic_first_row{true};
};

[[nodiscard]] std::string JsonField(const nlohmann::json& j, const char* key)
{
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return {};
    auto value = it->get<std::string>();
    return (value == UNKNOWN_VALUE) ? std::string{} : value; // sysinfo's "unknown" is a single space.
}

[[nodiscard]] PackageBaselineRow RowFromHelperJson(const nlohmann::json& j, std::string format)
{
    PackageBaselineRow row;
    row.name         = JsonField(j, "name");
    row.version      = JsonField(j, "version_"); // dbsync column name, both helpers emit it.
    row.architecture = JsonField(j, "architecture");
    row.description  = JsonField(j, "description");
    row.size         = j.value("size", static_cast<int64_t>(0));
    row.vendor       = JsonField(j, "vendor");
    row.install_time = JsonField(j, "installed");
    row.category     = JsonField(j, "category");
    row.source       = JsonField(j, "source");
    row.format       = std::move(format);
    return row;
}

void ScanDpkg(const std::string& status_path, std::vector<PackageBaselineRow>& out)
{
    std::ifstream file{status_path};
    if (!file) return;

    // Same block-splitting shape as sysinfo's getDpkgInfo() — that function is
    // directly reusable (it takes the status-file path), but compiling its TU
    // drags FileSystemWrapper + the python-package walker into this module, so
    // the 20-line loop lives here and the actual parser is the reused one.
    std::string line;
    std::vector<std::string> block;

    const auto flush = [&out, &block]() {
        if (block.empty()) return;
        try {
            if (auto pkg = PackageLinuxHelper::parseDpkg(block); !pkg.empty()) {
                out.push_back(RowFromHelperJson(pkg, "deb"));
            }
        } catch (...) {
            // A malformed block (no Status field, non-numeric size) aborts that
            // package only, never the scan.
        }
        block.clear();
    };

    while (std::getline(file, line)) {
        if (line.empty()) {
            flush();
        } else if (!block.empty() && line.front() == ' ') {
            block.back() += "\n" + line; // continuation (multi-line Description).
        } else {
            block.push_back(line);
        }
    }
    flush();
}

void ScanDpkgStatusD(const std::string& status_d_dir, std::vector<PackageBaselineRow>& out)
{
    // Distroless images ship no /var/lib/dpkg/status; each package instead has
    // its own status-format file under status.d/ (usually without a Status
    // line, since dpkg itself never ran). parseDpkg() requires "ok installed",
    // so a synthetic Status line is appended when the block lacks one — every
    // file present in status.d/ is an installed package by construction.
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator{status_d_dir, ec}) {
        if (!entry.is_regular_file(ec)) continue;
        if (entry.path().extension() == ".md5sums") continue; // checksum sidecars, not package blocks.

        std::ifstream file{entry.path()};
        if (!file) continue;

        std::string line;
        std::vector<std::string> block;
        bool has_status = false;

        while (std::getline(file, line)) {
            if (line.empty()) continue; // one package per file: blank lines never split.
            if (!block.empty() && line.front() == ' ') {
                block.back() += "\n" + line;
            } else {
                has_status = has_status || line.rfind("Status:", 0) == 0;
                block.push_back(line);
            }
        }

        if (block.empty()) continue;
        if (!has_status) block.emplace_back("Status: install ok installed");

        try {
            if (auto pkg = PackageLinuxHelper::parseDpkg(block); !pkg.empty()) {
                out.push_back(RowFromHelperJson(pkg, "deb"));
            }
        } catch (...) {
            // Same per-package containment as the classic status file.
        }
    }
}

void ScanRpm(std::shared_ptr<IBerkeleyDbWrapper> wrapper, std::vector<PackageBaselineRow>& out)
{
    BerkeleyRpmDBReader reader{std::move(wrapper)};

    for (auto row_str = reader.getNext(); !row_str.empty(); row_str = reader.getNext()) {
        try {
            if (auto pkg = PackageLinuxHelper::parseRpm(row_str); !pkg.empty()) {
                out.push_back(RowFromHelperJson(pkg, "rpm"));
            }
        } catch (...) {
            // Same per-package containment as dpkg.
        }
    }
}

void ScanApk(const std::string& installed_path, std::vector<PackageBaselineRow>& out)
{
    std::ifstream file{installed_path};
    if (!file) return;

    std::string line;
    std::vector<std::string> block;

    const auto flush = [&out, &block]() {
        if (block.empty()) return;
        PackageBaselineRow row;
        if (ParseApkBlock(block, row)) out.push_back(std::move(row));
        block.clear();
    };

    while (std::getline(file, line)) {
        if (line.empty()) {
            flush();
        } else {
            block.push_back(line);
        }
    }
    flush();
}

} // namespace

bool ParseApkBlock(const std::vector<std::string>& block, PackageBaselineRow& row)
{
    row = PackageBaselineRow{};
    row.format = "apk";

    for (const auto& line : block) {
        if (line.size() < 2 || line[1] != ':') continue;
        const auto value = line.substr(2);

        switch (line.front()) {
            case 'P': row.name = value; break;
            case 'V': row.version = value; break;
            case 'A': row.architecture = value; break;
            case 'T': row.description = value; break;
            case 'm': row.vendor = value; break;
            case 'o': row.source = value; break;
            case 'I':
                try {
                    row.size = std::stoll(value);
                } catch (...) {
                    row.size = 0;
                }
                break;
            default: break; // dependency/checksum lines are not inventory fields.
        }
    }

    return !row.name.empty();
}

std::vector<PackageDbFormat> DetectPackageDbs(const std::string& rootfs)
{
    std::vector<PackageDbFormat> found;

    if (RegularFileExists(rootfs + kDpkgStatusPath)) {
        found.push_back(PackageDbFormat::Dpkg);
    } else {
        std::error_code ec;
        if (std::filesystem::is_directory(rootfs + kDpkgStatusDDir, ec)) {
            found.push_back(PackageDbFormat::DpkgStatusD);
        }
    }
    if (RegularFileExists(rootfs + kApkInstalledPath)) found.push_back(PackageDbFormat::Apk);

    if (!FirstExisting(rootfs, kRpmSqliteProbes).empty()) {
        found.push_back(PackageDbFormat::RpmSqlite);
    } else if (!FirstExisting(rootfs, kRpmBdbProbes).empty()) {
        // rpm ≥ 4.16 may leave a stale BDB Packages file next to rpmdb.sqlite;
        // BDB is only the truth when no sqlite db exists.
        found.push_back(PackageDbFormat::RpmBdb);
    }

    return found;
}

std::vector<PackageBaselineRow> ScanContainerPackages(pid_t pid)
{
    std::vector<PackageBaselineRow> out;
    const std::string rootfs = "/proc/" + std::to_string(pid) + "/root";

    for (const auto format : DetectPackageDbs(rootfs)) {
        try {
            switch (format) {
                case PackageDbFormat::Dpkg:
                    ScanDpkg(rootfs + kDpkgStatusPath, out);
                    break;
                case PackageDbFormat::DpkgStatusD:
                    ScanDpkgStatusD(rootfs + kDpkgStatusDDir, out);
                    break;
                case PackageDbFormat::Apk:
                    ScanApk(rootfs + kApkInstalledPath, out);
                    break;
                case PackageDbFormat::RpmSqlite:
                    ScanRpm(std::make_shared<SqliteRpmDbWrapper>(FirstExisting(rootfs, kRpmSqliteProbes)), out);
                    break;
                case PackageDbFormat::RpmBdb:
                    ScanRpm(std::make_shared<BerkeleyDbWrapper>(FirstExisting(rootfs, kRpmBdbProbes)), out);
                    break;
            }
        } catch (...) {
            // An unreadable/corrupt database yields whatever was parsed before
            // the failure; other databases (and the rest of the baseline) go on.
        }
    }

    return out;
}

} // namespace wazuh::container_baseline
