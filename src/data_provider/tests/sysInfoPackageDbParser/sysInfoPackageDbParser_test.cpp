/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 * November 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoPackageDbParser_test.h"
#include "packages/packageDbParser.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include "db.h"
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

void SysInfoPackageDbParserTest::SetUp() {};
void SysInfoPackageDbParserTest::TearDown() {};

namespace
{
    // AddressSanitizer replaces the allocator: unlike glibc, it does not take its locks before fork, so a child can
    // inherit a lock another thread held, and it ends the process instead of throwing std::bad_alloc when an
    // allocation fails.
#if defined(__SANITIZE_ADDRESS__)
    constexpr bool UNDER_ADDRESS_SANITIZER { true };
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
    constexpr bool UNDER_ADDRESS_SANITIZER { true };
#else
    constexpr bool UNDER_ADDRESS_SANITIZER { false };
#endif
#else
    constexpr bool UNDER_ADDRESS_SANITIZER { false };
#endif

    constexpr int32_t TYPE_INT32 { 4 };
    constexpr int32_t TYPE_STRING { 6 };
    constexpr int32_t TYPE_I18NSTRING { 9 };

    const std::string DPKG_STATUS { "var/lib/dpkg/status" };
    const std::string DPKG_STATUS_D { "var/lib/dpkg/status.d/" };
    const std::string APK_DB { "lib/apk/db/installed" };
    const std::string APK_USR_DB { "usr/lib/apk/db/installed" };
    const std::string RPM_SQLITE { "var/lib/rpm/rpmdb.sqlite" };
    const std::string RPM_SQLITE_USR { "usr/lib/sysimage/rpm/rpmdb.sqlite" };
    const std::string RPM_NDB { "var/lib/rpm/Packages.db" };
    const std::string RPM_NDB_USR { "usr/lib/sysimage/rpm/Packages.db" };
    const std::string RPM_BDB { "var/lib/rpm/Packages" };
    const std::string RPM_BDB_USR { "usr/lib/sysimage/rpm/Packages" };

    void appendUint32BE(std::string& output, const uint32_t value)
    {
        output += static_cast<char>((value >> 24) & 0xFF);
        output += static_cast<char>((value >> 16) & 0xFF);
        output += static_cast<char>((value >> 8) & 0xFF);
        output += static_cast<char>(value & 0xFF);
    }

    void appendUint32LE(std::string& output, const uint32_t value)
    {
        output += static_cast<char>(value & 0xFF);
        output += static_cast<char>((value >> 8) & 0xFF);
        output += static_cast<char>((value >> 16) & 0xFF);
        output += static_cast<char>((value >> 24) & 0xFF);
    }

    /// @brief One tag as it is written into a header blob.
    struct Tag
    {
        int32_t tag;
        int32_t type;
        std::string text;   ///< Used by the string types.
        int32_t number {0}; ///< Used by the int32 type.
    };

    std::string headerBlob(const std::vector<Tag>& tags)
    {
        std::string index;
        std::string section;

        for (const auto& tag : tags)
        {
            appendUint32BE(index, static_cast<uint32_t>(tag.tag));
            appendUint32BE(index, static_cast<uint32_t>(tag.type));
            appendUint32BE(index, static_cast<uint32_t>(section.size()));
            appendUint32BE(index, 1);

            if (TYPE_INT32 == tag.type)
            {
                appendUint32BE(section, static_cast<uint32_t>(tag.number));
            }
            else
            {
                section += tag.text;
                section += '\0';
            }
        }

        std::string blob;
        appendUint32BE(blob, static_cast<uint32_t>(tags.size()));
        appendUint32BE(blob, static_cast<uint32_t>(section.size()));
        blob += index;
        blob += section;

        return blob;
    }

    /// @brief A header blob holding the full set of tags the agent collects.
    std::string rpmBlob(const std::string& name,
                        const std::string& version,
                        const std::string& release = "9.el9",
                        const int epoch = -1)
    {
        std::vector<Tag> tags
        {
            {1000, TYPE_STRING, name, 0},
            {1001, TYPE_STRING, version, 0},
            {1002, TYPE_STRING, release, 0},
            {1004, TYPE_I18NSTRING, "summary of " + name, 0},
            {1008, TYPE_INT32, "", 1700000000},
            {1009, TYPE_INT32, "", 7802001},
            {1011, TYPE_STRING, "Rocky", 0},
            {1016, TYPE_I18NSTRING, "Unspecified", 0},
            {1022, TYPE_STRING, "x86_64", 0},
            {1044, TYPE_STRING, name + "-" + version + ".src.rpm", 0}
        };

        if (epoch >= 0)
        {
            tags.push_back({1003, TYPE_INT32, "", epoch});
        }

        return headerBlob(tags);
    }

    std::string sqliteDatabase(const std::vector<std::string>& blobs)
    {
        sqlite3* database { nullptr };
        sqlite3_open(":memory:", &database);
        sqlite3_exec(database, "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL);", nullptr, nullptr, nullptr);

        sqlite3_stmt* statement { nullptr };
        sqlite3_prepare_v2(database, "INSERT INTO Packages (blob) VALUES (?);", -1, &statement, nullptr);

        for (const auto& blob : blobs)
        {
            sqlite3_bind_blob(statement, 1, blob.data(), static_cast<int>(blob.size()), SQLITE_STATIC);
            sqlite3_step(statement);
            sqlite3_reset(statement);
        }

        sqlite3_finalize(statement);

        sqlite3_int64 size { 0 };
        auto* bytes { sqlite3_serialize(database, "main", &size, 0) };
        std::string content { reinterpret_cast<const char*>(bytes), static_cast<size_t>(size) };

        sqlite3_free(bytes);
        sqlite3_close(database);

        return content;
    }

    std::string ndbDatabase(const std::vector<std::string>& blobs)
    {
        constexpr size_t BLOCK { 16 };
        constexpr size_t PAGE { 4096 };

        std::string slots;
        std::string payloads;

        for (size_t package = 0; package < blobs.size(); ++package)
        {
            slots += "Slot";
            appendUint32LE(slots, static_cast<uint32_t>(package + 1));
            appendUint32LE(slots, static_cast<uint32_t>((PAGE + payloads.size()) / BLOCK));
            appendUint32LE(slots, static_cast<uint32_t>((BLOCK + blobs[package].size() + BLOCK - 1) / BLOCK));

            payloads += "BlbS";
            appendUint32LE(payloads, static_cast<uint32_t>(package + 1));
            appendUint32LE(payloads, 1);
            appendUint32LE(payloads, static_cast<uint32_t>(blobs[package].size()));
            payloads += blobs[package];
            payloads.resize(((payloads.size() + BLOCK - 1) / BLOCK) * BLOCK, '\0');
        }

        std::string database { "RpmP" };
        appendUint32LE(database, 0);
        appendUint32LE(database, 1);
        appendUint32LE(database, 1);
        appendUint32LE(database, static_cast<uint32_t>(blobs.size() + 1));
        database.resize(32, '\0');
        database += slots;
        database.resize(PAGE, '\0');
        database += payloads;

        return database;
    }

    std::string dpkgStanza(const std::string& name,
                           const std::string& version,
                           const std::string& status = "install ok installed")
    {
        return "Package: " + name + "\n"
               "Status: " + status + "\n"
               "Priority: optional\n"
               "Section: utils\n"
               "Installed-Size: 100\n"
               "Maintainer: Debian " + name + " Maintainers <team@debian.org>\n"
               "Architecture: amd64\n"
               "Multi-Arch: same\n"
               "Source: " + name + "-source\n"
               "Version: " + version + "\n"
               "Description: short description of " + name + "\n"
               " a continuation line that is not part of the short description\n"
               "\n";
    }

    std::string apkStanza(const std::string& name, const std::string& version)
    {
        return "C:Q1exampleexampleexampleexampleexample=\n"
               "P:" + name + "\n"
               "V:" + version + "\n"
               "A:x86_64\n"
               "S:1000\n"
               "I:2048\n"
               "T:short description of " + name + "\n"
               "U:https://example.invalid/" + name + "\n"
               "o:" + name + "-origin\n"
               "m:Alpine " + name + " Maintainers <team@alpinelinux.org>\n"
               "\n";
    }

    std::vector<std::string> names(const std::vector<PackageDb::Package>& packages)
    {
        std::vector<std::string> result;

        for (const auto& package : packages)
        {
            result.push_back(package.name);
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    const PackageDb::DatabaseReport* reportFor(const PackageDb::Result& result, const std::string& path)
    {
        const auto report
        {
            std::find_if(result.databases.begin(), result.databases.end(), [&path](const PackageDb::DatabaseReport & entry)
            {
                return entry.path == path;
            })
        };

        return report == result.databases.end() ? nullptr : &*report;
    }

#if defined(__linux__)
    /// @brief Build a Berkeley DB `Packages` file with libdb: a hash database keyed by the header number.
    ///
    /// The first record is rpm's own bookkeeping (the next header number), not a header blob.
    std::string berkeleyDatabase(const std::vector<std::string>& blobs)
    {
        std::random_device device;
        const auto directory { std::filesystem::temp_directory_path() / ("package_db_fixture_" + std::to_string(device())) };
        std::filesystem::create_directories(directory);
        const auto file { directory / "Packages" };

        DB* database { nullptr };
        EXPECT_EQ(db_create(&database, nullptr, 0), 0);
        database->set_lorder(database, 1234);

        const auto put = [database](uint32_t number, const std::string & value)
        {
            DBT key;
            DBT data;
            std::memset(&key, 0, sizeof(key));
            std::memset(&data, 0, sizeof(data));
            key.data = &number;
            key.size = sizeof(number);
            data.data = const_cast<char*>(value.data());
            data.size = static_cast<uint32_t>(value.size());
            return database->put(database, nullptr, &key, &data, 0);
        };

        int status { database->open(database, nullptr, file.c_str(), nullptr, DB_HASH, DB_CREATE, 0644) };

        if (status == 0)
        {
            status = put(0, std::string(4, '\0'));
        }

        for (size_t package = 0; status == 0 && package < blobs.size(); ++package)
        {
            status = put(static_cast<uint32_t>(package + 1), blobs[package]);
        }

        database->close(database, 0);
        EXPECT_EQ(status, 0);

        std::ifstream input { file, std::ios::binary };
        std::string content { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
        std::filesystem::remove_all(directory);

        return content;
    }

    /// @brief Number of entries named like the directories the parser creates, under @p root.
    size_t leftoverDirectories(const std::filesystem::path& root)
    {
        size_t count { 0 };

        for (const auto& entry : std::filesystem::directory_iterator { root })
        {
            if (entry.path().filename().string().rfind("wazuh_package_db_", 0) == 0)
            {
                ++count;
            }
        }

        return count;
    }


    std::string fixture(const std::string& name)
    {
        std::ifstream input { std::string { PACKAGE_DB_FIXTURES_DIR } + "/" + name, std::ios::binary };
        return { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
    }

    /// @brief True when no child of this process is left, running or waiting to be reaped.
    bool noChildLeft()
    {
        errno = 0;
        return waitpid(-1, nullptr, WNOHANG) == -1 && errno == ECHILD;
    }

    /// @brief A child entry point that cannot be ended by the alarm the child sets for itself, so that
    /// what ends it, in a test that expects a timeout, is the parent's kill.
    std::function<std::string(const std::string&, const std::string&)> withoutAlarm(
        const std::function<std::string(const std::string&, const std::string&)>& work)
    {
        return [work](const std::string & file, const std::string & dbPath)
        {
            sigset_t alarm;
            sigemptyset(&alarm);
            sigaddset(&alarm, SIGALRM);
            pthread_sigmask(SIG_BLOCK, &alarm, nullptr);
            return work(file, dbPath);
        };
    }

    PackageDb::BerkeleyDbOptions childThat(const std::function<std::string(const std::string&, const std::string&)>& work,
                                           std::chrono::milliseconds deadline = std::chrono::seconds { 10 })
    {
        PackageDb::BerkeleyDbOptions options;
        options.deadline = deadline;
        options.child = work;
        return options;
    }

    /// @brief Points the temporary directory at a fresh folder for the length of a test.
    class ScopedTempDirectory
    {
        public:
            ScopedTempDirectory()
            {
                std::random_device device;
                m_root = std::filesystem::temp_directory_path() / ("package_db_root_" + std::to_string(device()));
                std::filesystem::create_directories(m_root);
                // Traversable by the account a child drops to when the tests run as root, and by nobody else.
                std::filesystem::permissions(m_root, std::filesystem::perms::owner_all | std::filesystem::perms::group_exec | std::filesystem::perms::others_exec);

                const auto* previous { std::getenv("TMPDIR") };
                m_hadPrevious = previous != nullptr;

                if (m_hadPrevious)
                {
                    m_previous = previous;
                }

                setenv("TMPDIR", m_root.c_str(), 1);
            }

            ~ScopedTempDirectory()
            {
                if (m_hadPrevious)
                {
                    setenv("TMPDIR", m_previous.c_str(), 1);
                }
                else
                {
                    unsetenv("TMPDIR");
                }

                std::filesystem::remove_all(m_root);
            }

            ScopedTempDirectory(const ScopedTempDirectory&) = delete;
            ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

            const std::filesystem::path& path() const
            {
                return m_root;
            }

            /// @brief A directory inside it that anyone can write, for a test whose child runs as another user.
            std::filesystem::path sharedDirectory() const
            {
                const auto directory { m_root / "shared" };
                std::filesystem::create_directories(directory);
                std::filesystem::permissions(directory, std::filesystem::perms::all);
                return directory;
            }

        private:
            std::filesystem::path m_root;
            std::string m_previous;
            bool m_hadPrevious { false };
    };
#endif
} // namespace

// ---------------------------------------------------------------------------
// dpkg.
// ---------------------------------------------------------------------------

TEST_F(SysInfoPackageDbParserTest, DpkgMapsEveryField)
{
    const auto packages { PackageDb::parseDpkg(dpkgStanza("curl", "7.88.1-10"), DPKG_STATUS) };

    ASSERT_EQ(packages.size(), 1U);

    const auto& package { packages.front() };
    EXPECT_EQ(package.name, "curl");
    EXPECT_EQ(package.version, "7.88.1-10");
    EXPECT_EQ(package.architecture, "amd64");
    EXPECT_EQ(package.type, "deb");
    EXPECT_EQ(package.vendor, "Debian curl Maintainers <team@debian.org>");
    EXPECT_EQ(package.category, "utils");
    EXPECT_EQ(package.priority, "optional");
    EXPECT_EQ(package.multiarch, "same");
    EXPECT_EQ(package.source, "curl-source");
    EXPECT_EQ(package.packageDbPath, DPKG_STATUS);
    EXPECT_EQ(package.size, 100 * 1024);
    EXPECT_EQ(package.description, "short description of curl");
    EXPECT_TRUE(package.installed.empty());
}

TEST_F(SysInfoPackageDbParserTest, DpkgReportsInstalledPackagesOnly)
{
    const auto content
    {
        dpkgStanza("curl", "7.0") + dpkgStanza("wget", "1.0", "deinstall ok config-files") +
        dpkgStanza("nano", "5.0", "install ok half-configured") + dpkgStanza("tar", "1.34")
    };

    EXPECT_EQ(names(PackageDb::parseDpkg(content, DPKG_STATUS)), std::vector<std::string>({"curl", "tar"}));
}

TEST_F(SysInfoPackageDbParserTest, DpkgSkipsStanzasWithoutANameOrStatus)
{
    EXPECT_TRUE(PackageDb::parseDpkg("Status: install ok installed\nVersion: 1.0\n", DPKG_STATUS).empty());
    EXPECT_TRUE(PackageDb::parseDpkg("Package: curl\nVersion: 1.0\n", DPKG_STATUS).empty());
}

TEST_F(SysInfoPackageDbParserTest, DpkgKeepsAPackageWhoseSizeIsNotANumber)
{
    // The host parser drops the whole package for this. The package is installed all the same.
    const auto packages { PackageDb::parseDpkg("Installed-Size: not-a-number\nPackage: curl\nStatus: install ok installed\n", DPKG_STATUS) };

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().size, 0);
}

TEST_F(SysInfoPackageDbParserTest, ADpkgSizeThatOverflowsOnceScaledIsNotATrustedSize)
{
    const auto sizeOf = [](const std::string & value)
    {
        const auto packages { PackageDb::parseDpkg("Package: a\nStatus: install ok installed\nInstalled-Size: " + value + "\n", DPKG_STATUS) };
        EXPECT_EQ(packages.size(), 1U) << value;
        return packages.empty() ? -1 : packages.front().size;
    };

    EXPECT_EQ(sizeOf("9007199254740991"), 9007199254740991LL * 1024);
    EXPECT_EQ(sizeOf("9007199254740992"), 0);
    EXPECT_EQ(sizeOf("9223372036854775807"), 0);
    EXPECT_EQ(sizeOf("-9223372036854775808"), 0);
    EXPECT_EQ(sizeOf("-9007199254740992"), -9007199254740992LL * 1024);
    EXPECT_EQ(sizeOf("100"), 100 * 1024);
}

TEST_F(SysInfoPackageDbParserTest, DpkgReadsWindowsLineEndings)
{
    auto content { dpkgStanza("curl", "7.0") + dpkgStanza("tar", "1.34") };
    std::string crlf;

    for (const auto character : content)
    {
        if (character == '\n')
        {
            crlf += '\r';
        }

        crlf += character;
    }

    const auto packages { PackageDb::parseDpkg(crlf, DPKG_STATUS) };

    EXPECT_EQ(names(packages), std::vector<std::string>({"curl", "tar"}));
    EXPECT_EQ(packages.front().version, "7.0");
}

TEST_F(SysInfoPackageDbParserTest, DpkgSurvivesBinaryGarbage)
{
    std::string garbage;

    for (int i = 0; i < 4096; ++i)
    {
        garbage += static_cast<char>((i * 31) % 256);
    }

    EXPECT_NO_THROW(PackageDb::parseDpkg(garbage, DPKG_STATUS));
    EXPECT_NO_THROW(PackageDb::parseDpkg(std::string(100000, ':'), DPKG_STATUS));
    EXPECT_TRUE(PackageDb::parseDpkg("", DPKG_STATUS).empty());
}

TEST_F(SysInfoPackageDbParserTest, DpkgStatusDEntryWithoutAStatusLineIsInstalled)
{
    const auto packages { PackageDb::parseDpkgStatusD("Package: base-files\nVersion: 12.4\nArchitecture: amd64\nDescription: base\n", DPKG_STATUS_D + "base-files") };

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "base-files");
    EXPECT_EQ(packages.front().version, "12.4");
    EXPECT_EQ(packages.front().type, "deb");
    EXPECT_EQ(packages.front().packageDbPath, DPKG_STATUS_D + "base-files");
}

TEST_F(SysInfoPackageDbParserTest, DpkgStatusDEntryThatStatesAnotherStatusIsNotInstalled)
{
    EXPECT_TRUE(PackageDb::parseDpkgStatusD("Package: base-files\nStatus: deinstall ok config-files\nVersion: 12.4\n", DPKG_STATUS_D + "base-files").empty());
}

TEST_F(SysInfoPackageDbParserTest, DpkgStatusDEntryIsOnePackageWhateverBlankLinesItHolds)
{
    const auto packages { PackageDb::parseDpkgStatusD("Package: base-files\n\nVersion: 12.4\n\nArchitecture: amd64\n", DPKG_STATUS_D + "base-files") };

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().version, "12.4");
    EXPECT_EQ(packages.front().architecture, "amd64");
}

TEST_F(SysInfoPackageDbParserTest, DpkgStatusDEntriesAreDirectChildrenWithoutTheChecksumSuffix)
{
    EXPECT_TRUE(PackageDb::isStatusDEntry("var/lib/dpkg/status.d/base-files"));
    EXPECT_FALSE(PackageDb::isStatusDEntry("var/lib/dpkg/status.d/base-files.md5sums"));
    EXPECT_FALSE(PackageDb::isStatusDEntry("var/lib/dpkg/status.d/nested/base-files"));
    EXPECT_FALSE(PackageDb::isStatusDEntry("var/lib/dpkg/status.d/"));
    EXPECT_FALSE(PackageDb::isStatusDEntry("var/lib/dpkg/status.d"));
    EXPECT_FALSE(PackageDb::isStatusDEntry("var/lib/dpkg/status"));
    EXPECT_FALSE(PackageDb::isStatusDEntry("var/lib/dpkg/status.dx/base-files"));
}

// ---------------------------------------------------------------------------
// apk.
// ---------------------------------------------------------------------------

TEST_F(SysInfoPackageDbParserTest, ApkMapsEveryField)
{
    const auto packages { PackageDb::parseApk(apkStanza("busybox", "1.36.1-r5"), APK_DB) };

    ASSERT_EQ(packages.size(), 1U);

    const auto& package { packages.front() };
    EXPECT_EQ(package.name, "busybox");
    EXPECT_EQ(package.version, "1.36.1-r5");
    EXPECT_EQ(package.architecture, "x86_64");
    EXPECT_EQ(package.type, "apk");
    EXPECT_EQ(package.vendor, "Alpine busybox Maintainers <team@alpinelinux.org>");
    EXPECT_EQ(package.source, "busybox-origin");
    EXPECT_EQ(package.description, "short description of busybox");
    EXPECT_EQ(package.packageDbPath, APK_DB);
    EXPECT_EQ(package.size, 2048);
}

TEST_F(SysInfoPackageDbParserTest, ApkReadsSeveralStanzas)
{
    const auto content { apkStanza("busybox", "1.36") + apkStanza("musl", "1.2.4") + apkStanza("apk-tools", "2.14") };

    EXPECT_EQ(names(PackageDb::parseApk(content, APK_DB)), std::vector<std::string>({"apk-tools", "busybox", "musl"}));
}

TEST_F(SysInfoPackageDbParserTest, ApkSkipsStanzasWithoutANameAndSurvivesGarbage)
{
    EXPECT_TRUE(PackageDb::parseApk("V:1.0\nA:x86_64\n", APK_DB).empty());
    EXPECT_TRUE(PackageDb::parseApk("", APK_DB).empty());
    EXPECT_NO_THROW(PackageDb::parseApk(std::string(5000, 'P'), APK_DB));

    const auto packages { PackageDb::parseApk("P:busybox\nI:not-a-number\n", APK_DB) };
    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().size, 0);
}

// ---------------------------------------------------------------------------
// rpm, sqlite and ndb.
// ---------------------------------------------------------------------------

TEST_F(SysInfoPackageDbParserTest, RpmMapsEveryFieldOfASqliteDatabase)
{
    const auto packages { PackageDb::parseRpm(sqliteDatabase({rpmBlob("bash", "5.1.8")}), RPM_SQLITE) };

    ASSERT_EQ(packages.size(), 1U);

    const auto& package { packages.front() };
    EXPECT_EQ(package.name, "bash");
    EXPECT_EQ(package.version, "5.1.8-9.el9");
    EXPECT_EQ(package.architecture, "x86_64");
    EXPECT_EQ(package.type, "rpm");
    EXPECT_EQ(package.vendor, "Rocky");
    EXPECT_EQ(package.category, "Unspecified");
    EXPECT_EQ(package.description, "summary of bash");
    EXPECT_EQ(package.source, "bash-5.1.8.src.rpm");
    EXPECT_EQ(package.size, 7802001);
    EXPECT_EQ(package.packageDbPath, RPM_SQLITE);
    EXPECT_FALSE(package.installed.empty());
}

TEST_F(SysInfoPackageDbParserTest, RpmReadsASqliteDatabaseInWriteAheadLogMode)
{
    auto database { sqliteDatabase({rpmBlob("bash", "5.1.8")}) };
    database[18] = 2;
    database[19] = 2;

    EXPECT_EQ(names(PackageDb::parseRpm(database, RPM_SQLITE)), std::vector<std::string>({"bash"}));
}

TEST_F(SysInfoPackageDbParserTest, RpmReadsAnNdbDatabase)
{
    const auto packages { PackageDb::parseRpm(ndbDatabase({rpmBlob("aaa_base", "84.87", "150300.10.20.1")}), RPM_NDB) };

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "aaa_base");
    EXPECT_EQ(packages.front().version, "84.87-150300.10.20.1");
    EXPECT_EQ(packages.front().packageDbPath, RPM_NDB);
}

TEST_F(SysInfoPackageDbParserTest, RpmReadsEveryPackageOfADatabase)
{
    const std::vector<std::string> blobs { rpmBlob("bash", "5.1.8"), rpmBlob("glibc", "2.34") };

    EXPECT_EQ(names(PackageDb::parseRpm(sqliteDatabase(blobs), RPM_SQLITE)), std::vector<std::string>({"bash", "glibc"}));
    EXPECT_EQ(names(PackageDb::parseRpm(ndbDatabase(blobs), RPM_NDB)), std::vector<std::string>({"bash", "glibc"}));
}

TEST_F(SysInfoPackageDbParserTest, RpmKeepsTheEpochInTheVersionIncludingAnExplicitZero)
{
    const auto packages { PackageDb::parseRpm(sqliteDatabase({rpmBlob("gdbm-libs", "1.19", "4.el9", 1), rpmBlob("zero", "2.0", "1", 0), rpmBlob("plain", "3.0", "1")}), RPM_SQLITE) };

    ASSERT_EQ(packages.size(), 3U);

    std::map<std::string, std::string> versions;

    for (const auto& package : packages)
    {
        versions[package.name] = package.version;
    }

    EXPECT_EQ(versions["gdbm-libs"], "1:1.19-4.el9");
    EXPECT_EQ(versions["zero"], "0:2.0-1");
    EXPECT_EQ(versions["plain"], "3.0-1");
}

TEST_F(SysInfoPackageDbParserTest, RpmSkipsTheSigningKeys)
{
    EXPECT_EQ(names(PackageDb::parseRpm(sqliteDatabase({rpmBlob("gpg-pubkey", "3228467c"), rpmBlob("bash", "5.1.8")}), RPM_SQLITE)),
              std::vector<std::string>({"bash"}));
}

TEST_F(SysInfoPackageDbParserTest, RpmReportsNothingForContentThatIsNoDatabase)
{
    EXPECT_TRUE(PackageDb::parseRpm("", RPM_SQLITE).empty());
    EXPECT_TRUE(PackageDb::parseRpm("not a database at all", RPM_SQLITE).empty());
    EXPECT_TRUE(PackageDb::parseRpm(std::string("SQLite format 3\0 truncated", 26), RPM_SQLITE).empty());
    EXPECT_TRUE(PackageDb::parseRpm(std::string("RpmP", 4) + std::string(60, '\0'), RPM_NDB).empty());
}

TEST_F(SysInfoPackageDbParserTest, RpmSurvivesTruncatedDatabases)
{
    const auto sqlite { sqliteDatabase({rpmBlob("bash", "5.1.8")}) };
    const auto ndb { ndbDatabase({rpmBlob("bash", "5.1.8")}) };

    const std::vector<size_t> sqliteCuts { size_t { 1 }, size_t { 16 }, sqlite.size() / 4, sqlite.size() / 2, sqlite.size() - 1 };

    for (const auto cut : sqliteCuts)
    {
        EXPECT_NO_THROW(PackageDb::parseRpm(sqlite.substr(0, cut), RPM_SQLITE)) << cut;
    }

    const std::vector<size_t> ndbCuts { size_t { 1 }, size_t { 31 }, size_t { 4096 }, ndb.size() - 16, ndb.size() - 1 };

    for (const auto cut : ndbCuts)
    {
        EXPECT_NO_THROW(PackageDb::parseRpm(ndb.substr(0, cut), RPM_NDB)) << cut;
    }

    EXPECT_TRUE(PackageDb::parseRpm(ndb.substr(0, ndb.size() - 16), RPM_NDB).empty());
}

TEST_F(SysInfoPackageDbParserTest, RpmReportsAFileThatIsNeitherSqliteNorNdb)
{
    std::string error;

    EXPECT_TRUE(PackageDb::parseRpm("not a database at all", RPM_SQLITE, &error).empty());
    EXPECT_EQ(error, "the rpm database could not be read as SQLite or NDB");

    // A database of either format, and an empty file, are no error.
    error.clear();
    EXPECT_EQ(PackageDb::parseRpm(sqliteDatabase({rpmBlob("bash", "5.1.8")}), RPM_SQLITE, &error).size(), 1U);
    EXPECT_EQ(PackageDb::parseRpm(ndbDatabase({rpmBlob("bash", "5.1.8")}), RPM_NDB, &error).size(), 1U);
    EXPECT_TRUE(PackageDb::parseRpm("", RPM_SQLITE, &error).empty());
    EXPECT_TRUE(error.empty()) << error;

    const auto result { PackageDb::read({{RPM_SQLITE, "a corrupt blob"}, {DPKG_STATUS, dpkgStanza("curl", "7.0")}}) };

    ASSERT_NE(reportFor(result, RPM_SQLITE), nullptr);
    EXPECT_EQ(reportFor(result, RPM_SQLITE)->error, "the rpm database could not be read as SQLite or NDB");
    EXPECT_FALSE(reportFor(result, RPM_SQLITE)->transient);
    EXPECT_EQ(names(result.packages), std::vector<std::string>({"curl"}));
}

TEST_F(SysInfoPackageDbParserTest, RpmSkipsABlobItCannotRead)
{
    const auto packages { PackageDb::parseRpm(sqliteDatabase({std::string("\xff\xff\xff\xff\x00\x00\x00\x10", 8), rpmBlob("bash", "5.1.8")}), RPM_SQLITE) };

    EXPECT_EQ(names(packages), std::vector<std::string>({"bash"}));
}

TEST_F(SysInfoPackageDbParserTest, TheInstallDateIsConvertedWithoutTheTimeFunctionsOfTheLibrary)
{
    const std::vector<std::pair<uint32_t, std::string>> dates
    {
        {0U, "1970-01-01T00:00:00.000Z"},
        {86399U, "1970-01-01T23:59:59.000Z"},
        {86400U, "1970-01-02T00:00:00.000Z"},
        {946684799U, "1999-12-31T23:59:59.000Z"},
        {951782399U, "2000-02-28T23:59:59.000Z"},
        {951782400U, "2000-02-29T00:00:00.000Z"},
        {951868800U, "2000-03-01T00:00:00.000Z"},
        {1078012800U, "2004-02-29T00:00:00.000Z"},
        {1234567890U, "2009-02-13T23:31:30.000Z"},
        {1700000000U, "2023-11-14T22:13:20.000Z"},
        {1709164800U, "2024-02-29T00:00:00.000Z"},
        {1709251200U, "2024-03-01T00:00:00.000Z"},
        {2147483648U, "2038-01-19T03:14:08.000Z"},
        {4107542399U, "2100-02-28T23:59:59.000Z"},
        {4107542400U, "2100-03-01T00:00:00.000Z"},
        {4294967295U, "2106-02-07T06:28:15.000Z"},
    };

    for (const auto& [seconds, expected] : dates)
    {
        EXPECT_EQ(PackageDb::detail::isoTimestamp(seconds), expected) << seconds;
        EXPECT_EQ(PackageDb::detail::rpmInstallDate(std::to_string(seconds)), expected) << seconds;
    }

    EXPECT_EQ(PackageDb::detail::rpmInstallDate(""), "");
    EXPECT_EQ(PackageDb::detail::rpmInstallDate("soon"), "");
    EXPECT_EQ(PackageDb::detail::rpmInstallDate("99999999999999999999"), "");
}

// ---------------------------------------------------------------------------
// rpm, Berkeley DB.
// ---------------------------------------------------------------------------

#if defined(__linux__)

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbPackagesAreRead)
{
    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46", "35.el7_9"), rpmBlob("glibc", "2.17", "326.el7_9", 0)}), RPM_BDB, error) };

    EXPECT_TRUE(error.empty()) << error;
    EXPECT_EQ(names(packages), std::vector<std::string>({"bash", "glibc"}));

    for (const auto& package : packages)
    {
        EXPECT_EQ(package.type, "rpm");
        EXPECT_EQ(package.packageDbPath, RPM_BDB);

        if (package.name == "bash")
        {
            EXPECT_EQ(package.version, "4.2.46-35.el7_9");
            EXPECT_EQ(package.architecture, "x86_64");
            EXPECT_EQ(package.source, "bash-4.2.46.src.rpm");
            EXPECT_EQ(package.size, 7802001);
        }
        else
        {
            EXPECT_EQ(package.version, "0:2.17-326.el7_9");
        }
    }
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbReadsADatabaseWithManyPackages)
{
    std::vector<std::string> blobs;
    std::vector<std::string> expected;

    for (int i = 0; i < 300; ++i)
    {
        const auto name { "package-" + std::to_string(1000 + i) };
        blobs.push_back(rpmBlob(name, "1.0"));
        expected.push_back(name);
    }

    std::sort(expected.begin(), expected.end());

    std::string error;
    EXPECT_EQ(names(PackageDb::parseRpmBerkeleyDb(berkeleyDatabase(blobs), RPM_BDB, error)), expected);
    EXPECT_TRUE(error.empty()) << error;
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbWithNoPackagesIsEmptyWithoutAnError)
{
    std::string error;

    EXPECT_TRUE(PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({}), RPM_BDB, error).empty());
    EXPECT_TRUE(error.empty()) << error;
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbSkipsABlobItCannotRead)
{
    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({std::string("\xff\xff\xff\xff\x00\x00\x00\x10", 8), rpmBlob("bash", "4.2.46")}), RPM_BDB, error) };

    EXPECT_EQ(names(packages), std::vector<std::string>({"bash"}));
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbThatIsNotAHashDatabaseIsReported)
{
    std::string error;

    EXPECT_TRUE(PackageDb::parseRpmBerkeleyDb("a Berkeley DB hash file", RPM_BDB, error).empty());
    EXPECT_FALSE(error.empty());

    EXPECT_TRUE(PackageDb::parseRpmBerkeleyDb("", RPM_BDB, error).empty());
    EXPECT_FALSE(error.empty());

    // A sqlite file under the Berkeley DB name is not read as one.
    EXPECT_TRUE(PackageDb::parseRpmBerkeleyDb(sqliteDatabase({rpmBlob("bash", "5.1.8")}), RPM_BDB, error).empty());
    EXPECT_FALSE(error.empty());
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbSurvivesTruncation)
{
    std::vector<std::string> blobs;

    for (int i = 0; i < 40; ++i)
    {
        blobs.push_back(rpmBlob("package-" + std::to_string(i), "1.0"));
    }

    const auto database { berkeleyDatabase(blobs) };
    std::string error;

    // Whole pages read as a shorter database. Anything else is refused by libdb.
    const std::vector<size_t> cuts { size_t { 16 }, size_t { 4096 }, database.size() / 2, database.size() - 1 };

    for (const auto cut : cuts)
    {
        EXPECT_NO_THROW(PackageDb::parseRpmBerkeleyDb(database.substr(0, cut), RPM_BDB, error)) << cut;
    }
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbOfTwoHundredPackagesIsRead)
{
    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(fixture("bdb_valid_200_packages.bin"), RPM_BDB, error) };

    EXPECT_TRUE(error.empty()) << error;
    EXPECT_EQ(packages.size(), 200U);
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbThatHangsLibdbIsKilledAtTheDeadline)
{
    ScopedTempDirectory root;
    const auto database { fixture("bdb_damaged_hang.bin") };
    ASSERT_EQ(database.size(), 40960U);

    std::string error;
    const auto start { std::chrono::steady_clock::now() };
    const auto packages { PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error, childThat(withoutAlarm(PackageDb::detail::readBerkeleyDbFile), std::chrono::milliseconds { 500 })) };
    const auto elapsed { std::chrono::steady_clock::now() - start };

    EXPECT_TRUE(packages.empty());
    EXPECT_EQ(error, "the read timed out after 500 ms");
    EXPECT_GE(elapsed, std::chrono::milliseconds { 500 });
    // A ceiling and not a tight bound: a host can stall for seconds after a build, and a child that was not killed never returns.
    EXPECT_LT(elapsed, std::chrono::seconds { 10 });
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbThatCrashesLibdbUnderASanitizerIsContained)
{
    // This file sends libdb into a wild read when it runs under AddressSanitizer, and reads as damaged
    // or not at all in a plain build. Either way the read returns, in time, and leaves nothing behind.
    ScopedTempDirectory root;
    std::string error;

    EXPECT_NO_THROW(PackageDb::parseRpmBerkeleyDb(fixture("bdb_damaged_crash.bin"), RPM_BDB, error, childThat(nullptr, std::chrono::seconds { 5 })));
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, AChildThatCrashesCostsOneDatabaseAndTheScanContinues)
{
    ScopedTempDirectory root;

    for (const auto signalNumber :
            {
                SIGSEGV, SIGABRT, SIGBUS
            })
    {
        std::string error;
        const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat([signalNumber](const std::string&, const std::string&) -> std::string
            {
                std::signal(signalNumber, SIG_DFL);
                std::raise(signalNumber);
                return {};
            })) };

        EXPECT_TRUE(packages.empty());
        EXPECT_EQ(error, "the read crashed with signal " + std::to_string(signalNumber));
        EXPECT_TRUE(noChildLeft());
        EXPECT_EQ(leftoverDirectories(root.path()), 0U);
    }

    // The next database is read as usual.
    std::string error;
    EXPECT_EQ(PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error).size(), 1U);
}

TEST_F(SysInfoPackageDbParserTest, AChildThatNeverEndsIsKilledAndReaped)
{
    ScopedTempDirectory root;
    std::string error;

    const auto start { std::chrono::steady_clock::now() };
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat(withoutAlarm([](const std::string&, const std::string&) -> std::string
        {
            while (true)
            {
                pause();
            }
        }), std::chrono::milliseconds { 200 })) };
    const auto elapsed { std::chrono::steady_clock::now() - start };

    EXPECT_TRUE(packages.empty());
    EXPECT_EQ(error, "the read timed out after 200 ms");
    EXPECT_LT(elapsed, std::chrono::milliseconds { 1200 });
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, AChildDoesNotOutliveItsParent)
{
    ScopedTempDirectory root;
    const auto pidFile { (root.sharedDirectory() / "child.pid").string() };
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };

    const auto parent { fork() };
    ASSERT_GE(parent, 0);

    if (parent == 0)
    {
        // The parent of the read: it starts one that never ends, then is killed before its deadline.
        std::string error;
        PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error, childThat([&pidFile](const std::string&, const std::string&) -> std::string
        {
            std::ofstream { pidFile } << getpid() << std::endl;

            while (true)
            {
                pause();
            }
        }, std::chrono::seconds { 60 }));
        _exit(0);
    }

    pid_t child { 0 };

    for (int attempt = 0; attempt < 200 && child == 0; ++attempt)
    {
        std::ifstream { pidFile } >> child;
        std::this_thread::sleep_for(std::chrono::milliseconds { 10 });
    }

    ASSERT_GT(child, 0);
    kill(parent, SIGKILL);
    waitpid(parent, nullptr, 0);

    bool gone { false };

    for (int attempt = 0; attempt < 300 && !gone; ++attempt)
    {
        gone = kill(child, 0) == -1 && errno == ESRCH;
        std::this_thread::sleep_for(std::chrono::milliseconds { 10 });
    }

    EXPECT_TRUE(gone);
}

TEST_F(SysInfoPackageDbParserTest, AChildThatIgnoresTerminationStillDies)
{
    std::string error;

    PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat(withoutAlarm([](const std::string&, const std::string&) -> std::string
    {
        std::signal(SIGTERM, SIG_IGN);

        while (true)
        {
            pause();
        }
    }), std::chrono::milliseconds { 200 }));

    EXPECT_EQ(error, "the read timed out after 200 ms");
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, AChildThatExitsAbnormallyOrAnswersNonsenseIsReported)
{
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    std::string error;

    PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error, childThat([](const std::string&, const std::string&) -> std::string
    {
        _exit(5);
    }));
    EXPECT_EQ(error, "the read exited with status 5");

    PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error, childThat([](const std::string&, const std::string&) -> std::string
    {
        throw std::runtime_error { "unexpected" };
    }));
    EXPECT_EQ(error, "the read exited with status 2");

    const std::vector<std::string> nonsense { std::string {}, "?", "P", "Pabcd", "E", std::string { "E\0\0\0\0", 5 } };

    for (const auto& reply : nonsense)
    {
        PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error, childThat([&reply](const std::string&, const std::string&)
        {
            return reply;
        }));
        EXPECT_EQ(error, "the reply of the read was malformed") << reply;
    }

    PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error, childThat([](const std::string&, const std::string&)
    {
        return PackageDb::detail::serializeError("libdb said no");
    }));
    EXPECT_EQ(error, "libdb said no");

    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, AReplyWithMorePackagesThanItHoldsOrTrailingBytesIsMalformed)
{
    std::vector<PackageDb::Package> packages(2);
    packages[0].name = "a";
    packages[1].name = "b";
    const auto reply { PackageDb::detail::serializePackages(packages) };

    std::vector<PackageDb::Package> read;
    std::string reported;

    EXPECT_TRUE(PackageDb::detail::parseReply(reply, read, reported));
    EXPECT_EQ(read.size(), 2U);

    EXPECT_FALSE(PackageDb::detail::parseReply(reply + "x", read, reported));
    EXPECT_FALSE(PackageDb::detail::parseReply(reply.substr(0, reply.size() - 1), read, reported));

    auto lying { reply };
    lying[1] = '\xff';
    EXPECT_FALSE(PackageDb::detail::parseReply(lying, read, reported));

    // A field that declares more bytes than the reply has left.
    auto oversized { reply };
    oversized[5] = '\x7f';
    EXPECT_FALSE(PackageDb::detail::parseReply(oversized, read, reported));
}

TEST_F(SysInfoPackageDbParserTest, AReplyLargerThanTheLimitIsRefused)
{
    std::string error;

    PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat([](const std::string&, const std::string&)
    {
        return std::string(PackageDb::detail::BERKELEY_REPLY_LIMIT + 1, 'x');
    }, std::chrono::seconds { 20 }));

    EXPECT_EQ(error, "the reply was larger than the supported size");
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, TheChildInheritsNoDescriptorOfTheParent)
{
    const int descriptor { ::open("/proc/self/exe", O_RDONLY) };
    ASSERT_GE(descriptor, 3);

    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat([descriptor](const std::string&, const std::string&)
    {
        std::vector<PackageDb::Package> seen(1);
        seen[0].name = fcntl(descriptor, F_GETFD) == -1 && errno == EBADF ? "closed" : "inherited";
        seen[0].version = write(STDOUT_FILENO, "x", 1) == 1 ? "stdout-open" : "stdout-closed";
        return PackageDb::detail::serializePackages(seen);
    })) };

    close(descriptor);

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "closed");
    // Standard output goes to the null device, so the child never writes into the parent's.
    EXPECT_EQ(packages.front().version, "stdout-open");
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, SeveralThreadsReadBerkeleyDatabasesAtTheSameTime)
{
    if (UNDER_ADDRESS_SANITIZER)
    {
        GTEST_SKIP() << "A child forked while another thread holds the sanitizer's allocator lock blocks until its read deadline";
    }

    const auto database { fixture("bdb_valid_200_packages.bin") };
    std::vector<size_t> counts(6, 0);
    std::atomic<bool> busy { true };

    // A thread that keeps the allocator and the standard streams in use while the others fork.
    std::thread noise([&busy]()
    {
        while (busy)
        {
            std::vector<std::string> strings(200, std::string(1000, 'x'));
            std::ostringstream stream;
            stream << strings.size();
        }
    });

    std::vector<std::thread> threads;

    for (size_t index = 0; index < counts.size(); ++index)
    {
        threads.emplace_back([&database, &counts, index]()
        {
            for (int round = 0; round < 4; ++round)
            {
                std::string error;
                counts[index] += PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error).size();
            }
        });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    busy = false;
    noise.join();

    for (const auto count : counts)
    {
        EXPECT_EQ(count, 800U);
    }

    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, ReadReportsAHungBerkeleyDbAndStillReadsTheOthers)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {RPM_BDB, fixture("bdb_damaged_hang.bin")}
    };

    const auto result { PackageDb::read(files, childThat(withoutAlarm(PackageDb::detail::readBerkeleyDbFile), std::chrono::milliseconds { 300 })) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"curl"}));
    ASSERT_NE(reportFor(result, RPM_BDB), nullptr);
    EXPECT_EQ(reportFor(result, RPM_BDB)->error, "the read timed out after 300 ms");
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, TheChildMemoryLimitIsRelativeToTheSizeOfTheParent)
{
    const auto before { PackageDb::detail::processSize() };
    ASSERT_GT(before, 0U);

    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat([](const std::string&, const std::string&)
    {
        rlimit limit;
        getrlimit(RLIMIT_AS, &limit);

        std::vector<PackageDb::Package> seen(1);
        seen[0].name = "limit";
        seen[0].version = std::to_string(limit.rlim_cur);
        return PackageDb::detail::serializePackages(seen);
    })) };

    const auto after { PackageDb::detail::processSize() };

    ASSERT_EQ(packages.size(), 1U) << error;

    constexpr std::size_t SLACK { 64UL * 1024 * 1024 };
    const auto limit { std::stoull(packages.front().version) };

    EXPECT_GE(limit, before + PackageDb::detail::CHILD_MEMORY_HEADROOM - SLACK);
    EXPECT_LE(limit, after + PackageDb::detail::CHILD_MEMORY_HEADROOM + SLACK);

    // The parent keeps whatever limit it had.
    rlimit own;
    ASSERT_EQ(getrlimit(RLIMIT_AS, &own), 0);
    EXPECT_NE(own.rlim_cur, static_cast<rlim_t>(limit));
}

TEST_F(SysInfoPackageDbParserTest, TheChildMemoryLimitSaturatesInsteadOfOverflowing)
{
    constexpr std::size_t headroom { PackageDb::detail::CHILD_MEMORY_HEADROOM };
    const auto largest { static_cast<std::size_t>(~0UL) };

    EXPECT_EQ(PackageDb::detail::limitFor(0), 0U);
    EXPECT_EQ(PackageDb::detail::limitFor(1000), 1000 + headroom);
    EXPECT_EQ(PackageDb::detail::limitFor(largest - headroom), largest);
    EXPECT_EQ(PackageDb::detail::limitFor(largest - headroom + 1), largest);
    EXPECT_EQ(PackageDb::detail::limitFor(largest), largest);
}

TEST_F(SysInfoPackageDbParserTest, AChildThatAllocatesPastItsLimitIsReportedAndTheParentLivesOn)
{
    if (UNDER_ADDRESS_SANITIZER)
    {
        GTEST_SKIP() << "The sanitizer ends a child whose allocation fails instead of throwing std::bad_alloc";
    }

    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat([](const std::string&, const std::string&) -> std::string
        {
            std::vector<char> big(2UL * 1024 * 1024 * 1024, 1);
            return std::string(1, big.back());
        })) };

    EXPECT_TRUE(packages.empty());
    EXPECT_EQ(error, "the read exited with status 2");
    EXPECT_TRUE(noChildLeft());

    // The next database is read as usual, in the same process.
    EXPECT_EQ(PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error).size(), 1U);
}

TEST_F(SysInfoPackageDbParserTest, AMemoryLimitThatCannotBeSetIsReportedAndTheReadGoesOn)
{
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    const auto parent { fork() };
    ASSERT_GE(parent, 0);

    if (parent == 0)
    {
        // A process whose hard limit is below what the read would ask for, so setting it fails.
        const rlimit hard { PackageDb::detail::processSize() + (256UL << 20), PackageDb::detail::processSize() + (256UL << 20) };

        if (setrlimit(RLIMIT_AS, &hard) != 0)
        {
            _exit(10);
        }

        // A process allowed to raise its hard limit, as root is, can always set the limit.
        const rlimit higher { hard.rlim_cur + (1UL << 30), hard.rlim_max + (1UL << 30) };

        if (setrlimit(RLIMIT_AS, &higher) == 0)
        {
            _exit(12);
        }

        const auto result { PackageDb::readRpmBerkeleyDb(database, RPM_BDB) };

        _exit(result.error.empty() && result.packages.size() == 1 &&
              result.warning == "the memory limit of the read could not be set" ? 0 : 11);
    }

    int status { 0 };
    ASSERT_EQ(waitpid(parent, &status, 0), parent);
    ASSERT_TRUE(WIFEXITED(status));

    if (WEXITSTATUS(status) == 12)
    {
        GTEST_SKIP() << "This process may raise its hard address space limit (root, or CAP_SYS_RESOURCE), so the limit can always be set.";
    }

    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(SysInfoPackageDbParserTest, AStopRequestCancelsARunningChildAtOnce)
{
    ScopedTempDirectory root;
    std::atomic<bool> stop { false };
    std::thread requester([&stop]()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds { 150 });
        stop = true;
    });

    auto options { childThat(withoutAlarm([](const std::string&, const std::string&) -> std::string
        {
            while (true)
            {
                pause();
            }
        }), std::chrono::seconds { 30 }) };
    options.stop = [&stop]()
    {
        return stop.load();
    };

    const auto start { std::chrono::steady_clock::now() };
    const auto result { PackageDb::readRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, options) };
    const auto elapsed { std::chrono::steady_clock::now() - start };
    requester.join();

    EXPECT_TRUE(result.packages.empty());
    EXPECT_EQ(result.error, "the read was cancelled by a stop request");
    EXPECT_LT(elapsed, std::chrono::seconds { 2 });
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, AStopRequestMadeBeforeTheReadStartsCancelsIt)
{
    auto options { childThat(withoutAlarm([](const std::string&, const std::string&) -> std::string
        {
            while (true)
            {
                pause();
            }
        }), std::chrono::seconds { 30 }) };
    options.stop = []()
    {
        return true;
    };

    const auto result { PackageDb::readRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, options) };

    EXPECT_EQ(result.error, "the read was cancelled by a stop request");
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, AnExceptionWhileWaitingStillKillsAndReapsTheChild)
{
    ScopedTempDirectory root;
    auto options { childThat(withoutAlarm([](const std::string&, const std::string&) -> std::string
        {
            while (true)
            {
                pause();
            }
        }), std::chrono::seconds { 30 }) };
    options.stop = []() -> bool
    {
        throw std::runtime_error { "stop failed" };
    };

    const auto result { PackageDb::readRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, options) };

    EXPECT_EQ(result.error, "stop failed");
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, TheGuardOfAChildKillsAndReapsItWhenTheScopeIsLeft)
{
    const auto child { fork() };
    ASSERT_GE(child, 0);

    if (child == 0)
    {
        while (true)
        {
            pause();
        }
    }

    try
    {
        PackageDb::detail::ChildGuard guard { child };
        throw std::runtime_error { "leaving" };
    }
    catch (const std::runtime_error&)
    {
    }

    EXPECT_EQ(kill(child, 0), -1);
    EXPECT_EQ(errno, ESRCH);
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, TheChildRunsWithDefaultSignalHandlersAndNothingBlocked)
{
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    struct sigaction handler {};
    handler.sa_handler = [](int) {};
    struct sigaction previousHup {};
    struct sigaction previousUsr1 {};
    struct sigaction previousTerm {};
    struct sigaction previousInt {};

    sigaction(SIGHUP, &ignore, &previousHup);
    sigaction(SIGUSR1, &handler, &previousUsr1);
    sigaction(SIGTERM, &handler, &previousTerm);
    sigaction(SIGINT, &handler, &previousInt);

    sigset_t usr2;
    sigset_t before;
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &usr2, &before);

    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error, childThat([](const std::string&, const std::string&)
    {
        std::vector<PackageDb::Package> seen(1);

        for (const auto signalNumber :
                {
                    SIGHUP, SIGUSR1, SIGTERM, SIGINT
                })
        {
            struct sigaction current {};
            sigaction(signalNumber, nullptr, &current);
            seen[0].version += current.sa_handler == SIG_DFL ? "default," : "changed,";
        }

        sigset_t blocked;
        pthread_sigmask(SIG_BLOCK, nullptr, &blocked);
        seen[0].name = sigismember(&blocked, SIGUSR2) == 0 ? "unblocked" : "blocked";
        return PackageDb::detail::serializePackages(seen);
    })) };

    pthread_sigmask(SIG_SETMASK, &before, nullptr);
    sigaction(SIGHUP, &previousHup, nullptr);
    sigaction(SIGUSR1, &previousUsr1, nullptr);
    sigaction(SIGTERM, &previousTerm, nullptr);
    sigaction(SIGINT, &previousInt, nullptr);

    ASSERT_EQ(packages.size(), 1U) << error;
    EXPECT_EQ(packages.front().version, "default,default,default,default,");
    EXPECT_EQ(packages.front().name, "unblocked");
}

TEST_F(SysInfoPackageDbParserTest, DescriptorsBelowThreeAreMovedAboveTheStandardOnes)
{
    const auto savedInput { dup(STDIN_FILENO) };
    ASSERT_GE(savedInput, 3);

    close(STDIN_FILENO);
    int low { open("/dev/null", O_RDONLY) };
    ASSERT_EQ(low, STDIN_FILENO);

    EXPECT_TRUE(PackageDb::detail::moveAboveStandard(low));
    EXPECT_GT(low, STDERR_FILENO);
    close(low);

    dup2(savedInput, STDIN_FILENO);
    close(savedInput);
}

TEST_F(SysInfoPackageDbParserTest, ABerkeleyDbIsReadWhileTwoStandardDescriptorsAreClosed)
{
    // With descriptors 0 and 1 closed, the pipe is created on them: the write end is descriptor 1, which the
    // child redirects to the null device. It only survives because both ends are moved above 2 first.
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    const auto savedInput { dup(STDIN_FILENO) };
    const auto savedOutput { dup(STDOUT_FILENO) };
    ASSERT_GE(savedInput, 3);
    ASSERT_GE(savedOutput, 3);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);

    int lowest[2];
    const auto created { pipe(lowest) };
    const auto writeEnd { created == 0 ? lowest[1] : -1 };

    if (created == 0)
    {
        close(lowest[0]);
        close(lowest[1]);
    }

    std::string error;
    const auto packages { PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error) };

    dup2(savedInput, STDIN_FILENO);
    dup2(savedOutput, STDOUT_FILENO);
    close(savedInput);
    close(savedOutput);

    // The precondition: the pipe really would have landed on the standard descriptors.
    EXPECT_EQ(writeEnd, STDOUT_FILENO);
    EXPECT_EQ(names(packages), std::vector<std::string>({"bash"})) << error;
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbLeavesNothingInTheTemporaryDirectory)
{
    ScopedTempDirectory root;
    std::string error;

    EXPECT_EQ(names(PackageDb::parseRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, error)),
              std::vector<std::string>({"bash"}));
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);

    // A read that fails after the directory exists leaves nothing either.
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    PackageDb::parseRpmBerkeleyDb(database.substr(0, 20), RPM_BDB, error);
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);

    PackageDb::parseRpmBerkeleyDb("not a database", RPM_BDB, error);
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbIsReportedWhenTheTemporaryDirectoryCannotBeUsed)
{
    ScopedTempDirectory root;
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    std::string error;

    // A directory the current user cannot create anything in.
    std::filesystem::permissions(root.path(), std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec);

    if (::access(root.path().c_str(), W_OK) == 0)
    {
        GTEST_SKIP() << "The user can write to a read-only directory, as root does.";
    }

    EXPECT_TRUE(PackageDb::parseRpmBerkeleyDb(database, RPM_BDB, error).empty());
    EXPECT_FALSE(error.empty());

    std::filesystem::permissions(root.path(), std::filesystem::perms::owner_all);
}

TEST_F(SysInfoPackageDbParserTest, TheTemporaryDirectoryIsPrivateAndRemovedWithItsOwner)
{
    std::filesystem::path path;

    {
        PackageDb::detail::PrivateDirectory directory;
        path = directory.path();

        ASSERT_TRUE(std::filesystem::is_directory(path));

        struct stat status;
        ASSERT_EQ(::stat(path.c_str(), &status), 0);
        EXPECT_EQ(status.st_mode & 0777, static_cast<mode_t>(0700));
    }

    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(SysInfoPackageDbParserTest, TheTemporaryDirectoryNamesDoNotRepeat)
{
    PackageDb::detail::PrivateDirectory first;
    PackageDb::detail::PrivateDirectory second;

    EXPECT_NE(first.path(), second.path());
}

// ---------------------------------------------------------------------------
// The child gives up its privileges, its core files and the descriptors it inherited.
// ---------------------------------------------------------------------------

namespace
{
    /// @brief What a child reports about itself, as the one package it sends back.
    PackageDb::BerkeleyDbResult readAndDescribeChild(const PackageDb::BerkeleyDbOptions& base)
    {
        auto options { base };
        options.child = [](const std::string & file, const std::string&)
        {
            uid_t real { 0 };
            uid_t effective { 0 };
            uid_t saved { 0 };
            gid_t realGroup { 0 };
            gid_t effectiveGroup { 0 };
            gid_t savedGroup { 0 };
            getresuid(&real, &effective, &saved);
            getresgid(&realGroup, &effectiveGroup, &savedGroup);

            int deathSignal { 0 };
            prctl(PR_GET_PDEATHSIG, &deathSignal);

            rlimit core;
            getrlimit(RLIMIT_CORE, &core);

            std::vector<PackageDb::Package> seen(1);
            seen[0].name = std::to_string(real) + "," + std::to_string(effective) + "," + std::to_string(saved);
            seen[0].version = std::to_string(realGroup) + "," + std::to_string(effectiveGroup) + "," + std::to_string(savedGroup);
            seen[0].architecture = std::to_string(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
            seen[0].type = std::to_string(getgroups(0, nullptr));
            seen[0].vendor = setuid(0) == 0 ? "root-regained" : "root-denied";
            seen[0].category = std::to_string(deathSignal);
            seen[0].description = std::to_string(core.rlim_cur) + "," + std::to_string(core.rlim_max);
            seen[0].source = access(file.c_str(), R_OK) == 0 ? "readable" : "unreadable";

            // Who owns the directory of the copy, and with what mode.
            struct stat directory;
            std::ostringstream owner;
            stat(std::filesystem::path { file }.parent_path().c_str(), &directory);
            owner << directory.st_uid << "," << std::oct << (directory.st_mode & 0777);
            seen[0].priority = owner.str();

            struct stat copy;
            std::ostringstream copyOwner;
            stat(file.c_str(), &copy);
            copyOwner << copy.st_uid << "," << std::oct << (copy.st_mode & 0777);
            seen[0].multiarch = copyOwner.str();
            return PackageDb::detail::serializePackages(seen);
        };
        options.deadline = std::chrono::seconds { 10 };

        return PackageDb::readRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, options);
    }

    /// @brief Run @p work in a process of its own and return its exit status, -1 when it did not exit.
    int exitStatusOf(const std::function<int()>& work)
    {
        const auto child { fork() };

        if (child < 0)
        {
            return -2;
        }

        if (child == 0)
        {
            _exit(work());
        }

        int status { 0 };
        waitpid(child, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    bool isOpen(int descriptor)
    {
        return fcntl(descriptor, F_GETFD) != -1;
    }
} // namespace

TEST_F(SysInfoPackageDbParserTest, TheChildIsGivenNoCoreFileAndKeepsItsDeathSignalAfterTheIdentityChange)
{
    const auto result { readAndDescribeChild({}) };

    ASSERT_EQ(result.packages.size(), 1U) << result.error;
    EXPECT_EQ(result.packages.front().description, "0,0");
    EXPECT_EQ(result.packages.front().category, std::to_string(SIGKILL));
}

TEST_F(SysInfoPackageDbParserTest, TheChildRunsAsTheUnprivilegedAccountWhenTheProcessIsRoot)
{
    if (geteuid() != 0)
    {
        GTEST_SKIP() << "Only a root process has privileges to drop.";
    }

    const auto* account { getpwnam(PackageDb::BERKELEY_DB_ACCOUNT) };

    if (account == nullptr)
    {
        GTEST_SKIP() << "This machine has no '" << PackageDb::BERKELEY_DB_ACCOUNT << "' account.";
    }

    ScopedTempDirectory root;
    const auto result { readAndDescribeChild({}) };

    ASSERT_EQ(result.packages.size(), 1U) << result.error;

    const auto uid { std::to_string(account->pw_uid) };
    const auto gid { std::to_string(account->pw_gid) };
    const auto& seen { result.packages.front() };

    EXPECT_EQ(seen.name, uid + "," + uid + "," + uid);
    EXPECT_EQ(seen.version, gid + "," + gid + "," + gid);
    EXPECT_EQ(seen.vendor, "root-denied");
    EXPECT_EQ(seen.architecture, "1");
    EXPECT_EQ(seen.type, "0");
    EXPECT_EQ(seen.category, std::to_string(SIGKILL));
    EXPECT_EQ(seen.description, "0,0");
    EXPECT_EQ(seen.source, "readable");
    // The directory stays this process's and is only traversable. The copy is the account's, to read.
    EXPECT_EQ(seen.priority, "0,711");
    EXPECT_EQ(seen.multiarch, uid + ",400");
    EXPECT_FALSE(result.transient);
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
    EXPECT_TRUE(noChildLeft());
}

TEST_F(SysInfoPackageDbParserTest, ARootProcessWithoutTheAccountDoesNotStartTheChild)
{
    if (geteuid() != 0)
    {
        GTEST_SKIP() << "Only a root process has privileges to drop.";
    }

    ScopedTempDirectory root;
    const auto marker { (root.sharedDirectory() / "child-ran").string() };
    PackageDb::BerkeleyDbOptions options { childThat([&marker](const std::string&, const std::string&) -> std::string
        {
            std::ofstream { marker } << "ran";
            return PackageDb::detail::serializePackages({});
        }) };
    options.account = "wazuh_no_such_account";

    const auto result { PackageDb::readRpmBerkeleyDb(berkeleyDatabase({rpmBlob("bash", "4.2.46")}), RPM_BDB, options) };

    EXPECT_TRUE(result.packages.empty());
    EXPECT_NE(result.error.find("'wazuh_no_such_account'"), std::string::npos) << result.error;
    EXPECT_TRUE(result.transient);
    EXPECT_FALSE(std::filesystem::exists(marker));
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, AnAccountThatCannotReachTheCopyIsATransientFailureAndNotADamagedDatabase)
{
    if (geteuid() != 0)
    {
        GTEST_SKIP() << "Only a root process has privileges to drop.";
    }

    if (getpwnam(PackageDb::BERKELEY_DB_ACCOUNT) == nullptr)
    {
        GTEST_SKIP() << "This machine has no '" << PackageDb::BERKELEY_DB_ACCOUNT << "' account.";
    }

    ScopedTempDirectory root;
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };

    // A temporary directory under a path only root enters.
    std::filesystem::permissions(root.path(), std::filesystem::perms::owner_all);

    const auto result { PackageDb::readRpmBerkeleyDb(database, RPM_BDB) };

    EXPECT_TRUE(result.packages.empty());
    EXPECT_EQ(result.error, "the account of the read could not open the copy of the database");
    EXPECT_TRUE(result.transient);
    EXPECT_TRUE(noChildLeft());
    EXPECT_EQ(leftoverDirectories(root.path()), 0U);
}

TEST_F(SysInfoPackageDbParserTest, AnAccountOfRootsUserOrGroupIsNotOneTheReadMayRunAs)
{
    EXPECT_FALSE(PackageDb::detail::isUnprivilegedAccount(0, 0));
    EXPECT_FALSE(PackageDb::detail::isUnprivilegedAccount(0, 1000));
    EXPECT_FALSE(PackageDb::detail::isUnprivilegedAccount(1000, 0));
    EXPECT_TRUE(PackageDb::detail::isUnprivilegedAccount(1000, 1000));
}

TEST_F(SysInfoPackageDbParserTest, TheChildRunsAsAnAccountThatIsNotTheAgentsOwn)
{
    // The agent's account can read its keys, and the child parses bytes that come from an image.
    EXPECT_STREQ(PackageDb::BERKELEY_DB_ACCOUNT, "nobody");
    EXPECT_EQ(PackageDb::BerkeleyDbOptions {}.account, "nobody");
}

TEST_F(SysInfoPackageDbParserTest, ANonRootProcessHasNoIdentityToDrop)
{
    std::optional<PackageDb::detail::ChildIdentity> identity;
    std::string error;

    if (geteuid() == 0)
    {
        EXPECT_FALSE(PackageDb::detail::resolveChildIdentity("wazuh_no_such_account", identity, error));
        EXPECT_FALSE(identity.has_value());
        EXPECT_FALSE(error.empty());
    }
    else
    {
        EXPECT_TRUE(PackageDb::detail::resolveChildIdentity("wazuh_no_such_account", identity, error));
        EXPECT_FALSE(identity.has_value());
        EXPECT_TRUE(error.empty());
    }
}

TEST_F(SysInfoPackageDbParserTest, EveryDescriptorBeyondTheOldFixedLimitIsClosedWhateverTheKernelOffers)
{
    rlimit limit;
    ASSERT_EQ(getrlimit(RLIMIT_NOFILE, &limit), 0);

    constexpr rlim_t HIGH { 9000 };

    if (limit.rlim_max < HIGH + 100)
    {
        GTEST_SKIP() << "The hard limit on descriptors is too low to open one beyond 4096 and then some.";
    }

    const std::vector<std::pair<std::string, std::function<bool(int)>>> strategies
    {
        {
            "close_range", [](int keep)
            {
                return PackageDb::detail::closeByRange(keep);
            }
        },
        {
            "listing", [](int keep)
            {
                return PackageDb::detail::closeByListing(keep);
            }
        },
        {
            "limit", [](int keep)
            {
                PackageDb::detail::closeByLimit(keep);
                return true;
            }
        },
        {
            "all", [](int keep)
            {
                PackageDb::detail::closeInheritedDescriptors(keep);
                return true;
            }
        },
    };

    for (const auto& [name, close] : strategies)
    {
        const auto status { exitStatusOf([&]()
        {
            const rlimit raised { HIGH + 100, limit.rlim_max };

            if (setrlimit(RLIMIT_NOFILE, &raised) != 0)
            {
                return 20;
            }

            const auto low { fcntl(STDIN_FILENO, F_DUPFD, 10) };
            const auto beyondFixed { fcntl(STDIN_FILENO, F_DUPFD, 5000) };
            const auto high { fcntl(STDIN_FILENO, F_DUPFD, static_cast<int>(HIGH)) };
            const auto keep { fcntl(STDIN_FILENO, F_DUPFD, 6000) };

            if (low < 0 || beyondFixed < 0 || high < 0 || keep < 0)
            {
                return 21;
            }

            if (!close(keep))
            {
                // A kernel without close_range: nothing to check for it.
                return 30;
            }

            if (isOpen(low) || isOpen(beyondFixed) || isOpen(high))
            {
                return 22;
            }

            return isOpen(keep) && isOpen(STDIN_FILENO) && isOpen(STDOUT_FILENO) && isOpen(STDERR_FILENO) ? 0 : 23;
        }) };

        if (status == 30)
        {
            EXPECT_EQ(name, "close_range");
            continue;
        }

        EXPECT_EQ(status, 0) << name;
    }
}

// ---------------------------------------------------------------------------
// Which failures are the machine's and which are the file's.
// ---------------------------------------------------------------------------

TEST_F(SysInfoPackageDbParserTest, AFailureOfTheMachineIsTransientAndOneOfTheFileIsNot)
{
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };

    const auto run = [&database](const std::function<std::string(const std::string&, const std::string&)>& work,
                                 std::chrono::milliseconds deadline = std::chrono::seconds { 10 },
                                 const std::function<bool()>& stop = {})
    {
        auto options { childThat(work, deadline) };
        options.stop = stop;
        return PackageDb::readRpmBerkeleyDb(database, RPM_BDB, options);
    };

    // The child ended from outside, or by the alarm it sets for itself, or could not report.
    for (const auto signalNumber :
            {
                SIGKILL, SIGALRM
            })
    {
        const auto result { run([signalNumber](const std::string&, const std::string&) -> std::string
            {
                std::signal(signalNumber, SIG_DFL);
                std::raise(signalNumber);
                return {};
            }) };

        EXPECT_EQ(result.error, "the read crashed with signal " + std::to_string(signalNumber));
        EXPECT_TRUE(result.transient) << signalNumber;
        // Only the alarm the child sets for itself is a deadline missed, as the parent's own timeout is.
        EXPECT_EQ(result.timedOut, signalNumber == SIGALRM) << signalNumber;
    }

    auto result { run([](const std::string&, const std::string&) -> std::string
        {
            _exit(PackageDb::detail::CHILD_EXIT_REPLY);
        }) };
    EXPECT_FALSE(result.error.empty());
    EXPECT_TRUE(result.transient);

    result = run([](const std::string&, const std::string&) -> std::string
    {
        _exit(PackageDb::detail::CHILD_EXIT_PRIVILEGES);
    });
    EXPECT_EQ(result.error, "the privileges of the read could not be dropped");
    EXPECT_TRUE(result.transient);

    result = run(withoutAlarm([](const std::string&, const std::string&) -> std::string
    {
        while (true)
        {
            pause();
        }
    }), std::chrono::milliseconds { 200 });
    EXPECT_EQ(result.error, "the read timed out after 200 ms");
    EXPECT_TRUE(result.transient);
    EXPECT_TRUE(result.timedOut);

    result = run([](const std::string&, const std::string&) -> std::string
    {
        return {};
    }, std::chrono::seconds { 10 }, []()
    {
        return true;
    });
    EXPECT_EQ(result.error, "the read was cancelled by a stop request");
    EXPECT_TRUE(result.transient);
    EXPECT_FALSE(result.timedOut);

    // What a damaged file does to libdb: crashes, reports, answers nonsense.
    for (const auto signalNumber :
            {
                SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL
            })
    {
        result = run([signalNumber](const std::string&, const std::string&) -> std::string
        {
            std::signal(signalNumber, SIG_DFL);
            std::raise(signalNumber);
            return {};
        });
        EXPECT_EQ(result.error, "the read crashed with signal " + std::to_string(signalNumber));
        EXPECT_FALSE(result.transient) << signalNumber;
    }

    result = run([](const std::string&, const std::string&) -> std::string
    {
        throw std::runtime_error { "unexpected" };
    });
    EXPECT_EQ(result.error, "the read exited with status 2");
    EXPECT_FALSE(result.transient);

    result = run([](const std::string&, const std::string&) -> std::string
    {
        return "?";
    });
    EXPECT_EQ(result.error, "the reply of the read was malformed");
    EXPECT_FALSE(result.transient);

    result = run([](const std::string&, const std::string&)
    {
        return PackageDb::detail::serializeError("libdb said no");
    });
    EXPECT_EQ(result.error, "libdb said no");
    EXPECT_FALSE(result.transient);

    result = PackageDb::readRpmBerkeleyDb("not a Berkeley DB", RPM_BDB);
    EXPECT_FALSE(result.error.empty());
    EXPECT_FALSE(result.transient);

    EXPECT_TRUE(noChildLeft());
}

namespace
{
    /// @brief Points the temporary directory of the process at @p path for the length of a scope.
    class ScopedTmpdir
    {
        public:
            explicit ScopedTmpdir(const std::string& path)
            {
                const auto* previous { std::getenv("TMPDIR") };
                m_hadPrevious = previous != nullptr;
                m_previous = m_hadPrevious ? previous : "";
                setenv("TMPDIR", path.c_str(), 1);
            }

            ~ScopedTmpdir()
            {
                m_hadPrevious ? static_cast<void>(setenv("TMPDIR", m_previous.c_str(), 1)) : static_cast<void>(unsetenv("TMPDIR"));
            }

            ScopedTmpdir(const ScopedTmpdir&) = delete;
            ScopedTmpdir& operator=(const ScopedTmpdir&) = delete;

        private:
            std::string m_previous;
            bool m_hadPrevious { false };
    };

    /// @brief True when the account the read drops to exists, or the process is not root and has none to drop to.
    bool accountOfTheReadIsUsable()
    {
        return geteuid() != 0 || getpwnam(PackageDb::BERKELEY_DB_ACCOUNT) != nullptr;
    }

    /// @brief What a failed check of a read in a process of its own says, in that process's standard error.
    int reportedAs(const PackageDb::BerkeleyDbResult& result, const std::string& expectedStart)
    {
        if (result.transient && result.error.rfind(expectedStart, 0) == 0)
        {
            return 0;
        }

        std::cerr << "transient=" << result.transient << " error='" << result.error << "', expected '" << expectedStart << "...'" << std::endl;
        return 21;
    }
}

TEST_F(SysInfoPackageDbParserTest, ADatabaseThatCannotBeCopiedBecauseTheTemporaryDirectoryIsMissingIsTransient)
{
    if (!accountOfTheReadIsUsable())
    {
        GTEST_SKIP() << "This machine has no '" << PackageDb::BERKELEY_DB_ACCOUNT << "' account, which a root process looks up first.";
    }

    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    const ScopedTmpdir missing { "/nonexistent/temporary/directory" };

    const auto result { PackageDb::readRpmBerkeleyDb(database, RPM_BDB) };

    EXPECT_EQ(result.error, "no temporary directory is available");
    EXPECT_TRUE(result.transient);
}

TEST_F(SysInfoPackageDbParserTest, ADatabaseThatCannotBeReadBecauseNoProcessCanBeStartedIsTransient)
{
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };

    // A user with more processes than the limit allows cannot fork. Root is not held to it.
    const auto status { exitStatusOf([&database]()
    {
        const rlimit none { 0, 0 };

        if (geteuid() == 0 || setrlimit(RLIMIT_NPROC, &none) != 0)
        {
            return 20;
        }

        return reportedAs(PackageDb::readRpmBerkeleyDb(database, RPM_BDB), "no process could be created");
    }) };

    if (status == 20)
    {
        GTEST_SKIP() << "A root process can fork past the limit on processes, and this one could not set it.";
    }

    EXPECT_EQ(status, 0);
}

TEST_F(SysInfoPackageDbParserTest, ADatabaseThatCannotBeReadBecauseNoPipeCanBeMadeIsTransient)
{
    if (!accountOfTheReadIsUsable())
    {
        GTEST_SKIP() << "This machine has no '" << PackageDb::BERKELEY_DB_ACCOUNT << "' account, which a root process looks up first.";
    }

    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };

    const auto status { exitStatusOf([&database]()
    {
        rlimit limit;
        getrlimit(RLIMIT_NOFILE, &limit);

        // A root process looks its account up first, and that may open files of its own: let it, before the descriptors run out.
        if (geteuid() == 0)
        {
            getpwnam(PackageDb::BERKELEY_DB_ACCOUNT);
        }

        // The runner or a sanitizer may hold descriptors of its own, so the limit is set just above the
        // highest one open rather than at a fixed number.
        int highest { STDERR_FILENO };
        std::error_code error;

        for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd", error))
        {
            highest = std::max(highest, std::atoi(entry.path().filename().c_str()));
        }

        // Every descriptor below the limit is taken but one: the copy can be written, and the pipe has no room.
        const rlimit one { static_cast<rlim_t>(highest) + 2, limit.rlim_max };

        if (setrlimit(RLIMIT_NOFILE, &one) != 0)
        {
            return 20;
        }

        int last { -1 };

        for (int next = fcntl(STDIN_FILENO, F_DUPFD, 3); next >= 0; next = fcntl(STDIN_FILENO, F_DUPFD, 3))
        {
            last = next;
        }

        if (last >= 0)
        {
            close(last);
        }

        return reportedAs(PackageDb::readRpmBerkeleyDb(database, RPM_BDB), "no pipe could be created");
    }) };

    if (status == 20)
    {
        GTEST_SKIP() << "The limit on descriptors could not be lowered.";
    }

    EXPECT_EQ(status, 0);
}

TEST_F(SysInfoPackageDbParserTest, ATemporaryDirectoryThatCannotBeUsedIsTransient)
{
    ScopedTempDirectory root;
    const auto database { berkeleyDatabase({rpmBlob("bash", "4.2.46")}) };
    std::filesystem::permissions(root.path(), std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec);

    if (::access(root.path().c_str(), W_OK) == 0)
    {
        GTEST_SKIP() << "The user can write to a read-only directory, as root does.";
    }

    const auto result { PackageDb::readRpmBerkeleyDb(database, RPM_BDB) };

    EXPECT_FALSE(result.error.empty());
    EXPECT_TRUE(result.transient);

    std::filesystem::permissions(root.path(), std::filesystem::perms::owner_all);
}

TEST_F(SysInfoPackageDbParserTest, ReadCarriesTheTransientFlagOfADatabaseToItsReport)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {RPM_BDB, berkeleyDatabase({rpmBlob("bash", "4.2.46")})}
    };

    auto options { childThat(withoutAlarm([](const std::string&, const std::string&) -> std::string
        {
            while (true)
            {
                pause();
            }
        }), std::chrono::milliseconds { 200 }) };

    auto result { PackageDb::read(files, options) };

    ASSERT_NE(reportFor(result, RPM_BDB), nullptr);
    EXPECT_TRUE(reportFor(result, RPM_BDB)->transient);
    EXPECT_TRUE(reportFor(result, RPM_BDB)->timedOut);
    EXPECT_FALSE(reportFor(result, DPKG_STATUS)->transient);

    result = PackageDb::read({{RPM_BDB, "a Berkeley DB hash file"}});
    EXPECT_FALSE(result.databases.front().error.empty());
    EXPECT_FALSE(result.databases.front().transient);
}

// ---------------------------------------------------------------------------
// A database that ends in the middle is not a shorter database.
// ---------------------------------------------------------------------------

TEST_F(SysInfoPackageDbParserTest, ADatabaseDamagedAfterItsFirstRecordsIsAnErrorAndNotAShorterList)
{
    std::vector<std::string> blobs;

    for (int i = 0; i < 400; ++i)
    {
        blobs.push_back(rpmBlob("package-" + std::to_string(1000 + i), "1.0"));
    }

    const auto database { berkeleyDatabase(blobs) };
    ASSERT_GT(database.size(), 8U * 4096);

    // Every page after the first few is turned into something that is no page of a hash database.
    auto damaged { database };
    std::fill(damaged.begin() + 4 * 4096, damaged.end(), '\xAA');

    const auto result { PackageDb::readRpmBerkeleyDb(damaged, RPM_BDB) };

    EXPECT_TRUE(result.packages.empty()) << result.packages.size();
    EXPECT_NE(result.error.find("could not be read to its end"), std::string::npos) << result.error;
    EXPECT_FALSE(result.transient);
}

#else

TEST_F(SysInfoPackageDbParserTest, BerkeleyDbIsReportedAsNotSupportedOnThisPlatform)
{
    std::string error;

    EXPECT_TRUE(PackageDb::parseRpmBerkeleyDb("a Berkeley DB hash file", RPM_BDB, error).empty());
    EXPECT_EQ(error, "rpm Berkeley DB not supported on this platform");
    EXPECT_FALSE(PackageDb::BERKELEY_DB_SUPPORTED);
}

#endif

// ---------------------------------------------------------------------------
// Choosing the databases of a filesystem.
// ---------------------------------------------------------------------------

TEST_F(SysInfoPackageDbParserTest, EveryDatabaseLocationIsATrackedPath)
{
    const std::vector<std::string> paths { DPKG_STATUS, APK_DB, APK_USR_DB, RPM_SQLITE, RPM_SQLITE_USR, RPM_NDB, RPM_NDB_USR, DPKG_STATUS_D + "base-files" };

    for (const auto& path : paths)
    {
        EXPECT_TRUE(PackageDb::isDatabasePath(path)) << path;
    }

    EXPECT_FALSE(PackageDb::isDatabasePath("var/lib/rpm/.rpm.lock"));
    EXPECT_FALSE(PackageDb::isDatabasePath("var/lib/rpm/__db.001"));
    EXPECT_FALSE(PackageDb::isDatabasePath("etc/os-release"));
    EXPECT_FALSE(PackageDb::isDatabasePath("/var/lib/dpkg/status"));

    // Only a platform that can read a Berkeley DB file keeps it.
    EXPECT_EQ(PackageDb::isDatabasePath(RPM_BDB), PackageDb::BERKELEY_DB_SUPPORTED);
    EXPECT_EQ(PackageDb::isDatabasePath(RPM_BDB_USR), PackageDb::BERKELEY_DB_SUPPORTED);
}

TEST_F(SysInfoPackageDbParserTest, ReadReportsNothingForNoFiles)
{
    const auto result { PackageDb::read({}) };

    EXPECT_TRUE(result.packages.empty());
    EXPECT_TRUE(result.databases.empty());
}

TEST_F(SysInfoPackageDbParserTest, ReadMergesDpkgStatusAndStatusDWhenBothExist)
{
    // A distroless image keeps its base packages in status.d, and a later layer can add a status file.
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {DPKG_STATUS_D + "base-files", "Package: base-files\nVersion: 12.4\nArchitecture: amd64\n"}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"base-files", "curl"}));
    ASSERT_NE(reportFor(result, DPKG_STATUS), nullptr);
    EXPECT_EQ(reportFor(result, DPKG_STATUS)->packages, 1U);
    ASSERT_NE(reportFor(result, "var/lib/dpkg/status.d"), nullptr);
    EXPECT_EQ(reportFor(result, "var/lib/dpkg/status.d")->packages, 1U);
    EXPECT_FALSE(reportFor(result, "var/lib/dpkg/status.d")->skipped);
}

TEST_F(SysInfoPackageDbParserTest, ReadReportsAPackageOfStatusAndStatusDOnceAsStatusDescribesIt)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.1")},
        {DPKG_STATUS_D + "curl", "Package: curl\nVersion: 7.0\nArchitecture: amd64\n"},
        // The same name on another architecture is another package.
        {DPKG_STATUS_D + "curl-i386", "Package: curl\nVersion: 7.0\nArchitecture: i386\n"}
    };

    const auto result { PackageDb::read(files) };

    ASSERT_EQ(result.packages.size(), 2U);
    EXPECT_EQ(reportFor(result, "var/lib/dpkg/status.d")->packages, 1U);

    for (const auto& package : result.packages)
    {
        EXPECT_EQ(package.version, package.architecture == "amd64" ? "7.1" : "7.0");
    }
}

TEST_F(SysInfoPackageDbParserTest, ReadDoesNotUndoAPackageStatusSaysIsRemovedWithAStatusDEntry)
{
    // A package `status` keeps the stanza of after it was removed: that is the word on it, whatever its state.
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0") + dpkgStanza("gone", "1.0", "deinstall ok config-files") + dpkgStanza("purged", "1.0", "purge ok not-installed")},
        {DPKG_STATUS_D + "gone", "Package: gone\nVersion: 1.0\nArchitecture: amd64\n"},
        {DPKG_STATUS_D + "purged", "Package: purged\nVersion: 1.0\nArchitecture: amd64\n"},
        {DPKG_STATUS_D + "base-files", "Package: base-files\nVersion: 12.4\nArchitecture: amd64\n"}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"base-files", "curl"}));
    EXPECT_EQ(reportFor(result, "var/lib/dpkg/status.d")->packages, 1U);
}

TEST_F(SysInfoPackageDbParserTest, ReadMatchesStatusAndStatusDByNameWhenEitherStatesNoArchitecture)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, "Package: nofield\nStatus: deinstall ok config-files\nVersion: 1\n\n" + dpkgStanza("curl", "7.1")},
        {DPKG_STATUS_D + "nofield", "Package: nofield\nVersion: 1\nArchitecture: amd64\n"},
        // The entry states none, and `status` states amd64.
        {DPKG_STATUS_D + "curl", "Package: curl\nVersion: 7.0\n"},
        // Both state one, and it is another: a multiarch package of its own.
        {DPKG_STATUS_D + "curl-i386", "Package: curl\nVersion: 7.0\nArchitecture: i386\n"}
    };

    const auto result { PackageDb::read(files) };

    ASSERT_EQ(result.packages.size(), 2U);

    for (const auto& package : result.packages)
    {
        EXPECT_EQ(package.name, "curl");
        EXPECT_EQ(package.version, package.architecture == "amd64" ? "7.1" : "7.0");
    }
}

TEST_F(SysInfoPackageDbParserTest, ReadReadsStatusDWhenThereIsNoStatus)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS_D + "base-files", "Package: base-files\nVersion: 12.4\n"},
        {DPKG_STATUS_D + "base-files.md5sums", "d41d8cd98f00b204e9800998ecf8427e  etc/issue\n"},
        {DPKG_STATUS_D + "tzdata", "Package: tzdata\nVersion: 2024a\nStatus: install ok installed\n"},
        {DPKG_STATUS_D + "removed", "Package: removed\nVersion: 1\nStatus: deinstall ok config-files\n"}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"base-files", "tzdata"}));
    ASSERT_NE(reportFor(result, "var/lib/dpkg/status.d"), nullptr);
    EXPECT_EQ(reportFor(result, "var/lib/dpkg/status.d")->packages, 2U);
    EXPECT_FALSE(reportFor(result, "var/lib/dpkg/status.d")->skipped);
}

TEST_F(SysInfoPackageDbParserTest, ReadReadsOneApkLocation)
{
    const PackageDb::Files files
    {
        {APK_DB, apkStanza("busybox", "1.36")},
        {APK_USR_DB, apkStanza("musl", "1.2.4")}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"busybox"}));
    ASSERT_NE(reportFor(result, APK_USR_DB), nullptr);
    EXPECT_TRUE(reportFor(result, APK_USR_DB)->skipped);
}

TEST_F(SysInfoPackageDbParserTest, ReadReadsTheApkDatabaseUnderUsr)
{
    const auto result { PackageDb::read({{APK_USR_DB, apkStanza("wolfi-base", "1.0")}}) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"wolfi-base"}));
}

TEST_F(SysInfoPackageDbParserTest, ReadPrefersSqliteThenNdbForRpm)
{
    const PackageDb::Files files
    {
        {RPM_SQLITE_USR, sqliteDatabase({rpmBlob("usr-sqlite", "1")})},
        {RPM_NDB, ndbDatabase({rpmBlob("ndb", "1")})},
        {RPM_NDB_USR, ndbDatabase({rpmBlob("usr-ndb", "1")})}
    };

    auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"usr-sqlite"}));
    EXPECT_TRUE(reportFor(result, RPM_NDB)->skipped);
    EXPECT_TRUE(reportFor(result, RPM_NDB_USR)->skipped);

    result = PackageDb::read({{RPM_NDB, ndbDatabase({rpmBlob("ndb", "1")})}, {RPM_NDB_USR, ndbDatabase({rpmBlob("usr-ndb", "1")})}});
    EXPECT_EQ(names(result.packages), std::vector<std::string>({"ndb"}));
}

TEST_F(SysInfoPackageDbParserTest, ReadReadsDifferentFormatsIndependently)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {APK_DB, apkStanza("busybox", "1.36")},
        {RPM_SQLITE, sqliteDatabase({rpmBlob("bash", "5.1.8")})}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"bash", "busybox", "curl"}));
    EXPECT_EQ(result.databases.size(), 3U);
}

TEST_F(SysInfoPackageDbParserTest, ReadReportsAnEmptyDatabaseWithoutAnError)
{
    const auto result { PackageDb::read({{DPKG_STATUS, ""}}) };

    EXPECT_TRUE(result.packages.empty());
    ASSERT_EQ(result.databases.size(), 1U);
    EXPECT_TRUE(result.databases.front().error.empty());
    EXPECT_FALSE(result.databases.front().skipped);
}

#if defined(__linux__)

TEST_F(SysInfoPackageDbParserTest, ReadPrefersSqliteAndNdbOverAStaleBerkeleyDb)
{
    const PackageDb::Files files
    {
        {RPM_BDB, berkeleyDatabase({rpmBlob("stale", "1")})},
        {RPM_SQLITE, sqliteDatabase({rpmBlob("bash", "5.1.8")})}
    };

    auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"bash"}));
    EXPECT_TRUE(reportFor(result, RPM_BDB)->skipped);

    result = PackageDb::read({{RPM_BDB, berkeleyDatabase({rpmBlob("stale", "1")})}, {RPM_NDB, ndbDatabase({rpmBlob("ndb", "1")})}});
    EXPECT_EQ(names(result.packages), std::vector<std::string>({"ndb"}));
}

TEST_F(SysInfoPackageDbParserTest, ReadReadsBerkeleyDbAtEitherLocation)
{
    auto result { PackageDb::read({{RPM_BDB, berkeleyDatabase({rpmBlob("bash", "4.2.46")})}}) };
    EXPECT_EQ(names(result.packages), std::vector<std::string>({"bash"}));

    result = PackageDb::read({{RPM_BDB_USR, berkeleyDatabase({rpmBlob("vim", "9.0")})}});
    EXPECT_EQ(names(result.packages), std::vector<std::string>({"vim"}));

    result = PackageDb::read({{RPM_BDB, berkeleyDatabase({rpmBlob("bash", "4.2.46")})}, {RPM_BDB_USR, berkeleyDatabase({rpmBlob("vim", "9.0")})}});
    EXPECT_EQ(names(result.packages), std::vector<std::string>({"bash"}));
    EXPECT_TRUE(reportFor(result, RPM_BDB_USR)->skipped);
}

TEST_F(SysInfoPackageDbParserTest, ReadReportsAnUnreadableBerkeleyDbAndStillReadsTheOthers)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {RPM_BDB, "a Berkeley DB hash file"}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"curl"}));
    ASSERT_NE(reportFor(result, RPM_BDB), nullptr);
    EXPECT_FALSE(reportFor(result, RPM_BDB)->error.empty());
    EXPECT_TRUE(reportFor(result, DPKG_STATUS)->error.empty());
}

#endif
