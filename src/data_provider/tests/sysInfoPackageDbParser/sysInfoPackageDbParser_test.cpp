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
#include <map>
#include <string>
#include <vector>

void SysInfoPackageDbParserTest::SetUp() {};
void SysInfoPackageDbParserTest::TearDown() {};

namespace
{
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

TEST_F(SysInfoPackageDbParserTest, RpmSkipsABlobItCannotRead)
{
    const auto packages { PackageDb::parseRpm(sqliteDatabase({std::string("\xff\xff\xff\xff\x00\x00\x00\x10", 8), rpmBlob("bash", "5.1.8")}), RPM_SQLITE) };

    EXPECT_EQ(names(packages), std::vector<std::string>({"bash"}));
}

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

    // The Berkeley DB files are not read, so a caller does not keep them.
    EXPECT_FALSE(PackageDb::isDatabasePath(RPM_BDB));
    EXPECT_FALSE(PackageDb::isDatabasePath(RPM_BDB_USR));
}

TEST_F(SysInfoPackageDbParserTest, ReadReportsNothingForNoFiles)
{
    const auto result { PackageDb::read({}) };

    EXPECT_TRUE(result.packages.empty());
    EXPECT_TRUE(result.databases.empty());
}

TEST_F(SysInfoPackageDbParserTest, ReadReadsDpkgStatusAndIgnoresStatusDWhenBothExist)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {DPKG_STATUS_D + "base-files", "Package: base-files\nVersion: 12.4\n"}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"curl"}));
    ASSERT_NE(reportFor(result, DPKG_STATUS), nullptr);
    EXPECT_EQ(reportFor(result, DPKG_STATUS)->packages, 1U);
    ASSERT_NE(reportFor(result, "var/lib/dpkg/status.d"), nullptr);
    EXPECT_TRUE(reportFor(result, "var/lib/dpkg/status.d")->skipped);
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
    EXPECT_FALSE(result.databases.front().skipped);
}

TEST_F(SysInfoPackageDbParserTest, ReadDoesNotReadABerkeleyDbFile)
{
    const PackageDb::Files files
    {
        {DPKG_STATUS, dpkgStanza("curl", "7.0")},
        {RPM_BDB, "a Berkeley DB hash file"}
    };

    const auto result { PackageDb::read(files) };

    EXPECT_EQ(names(result.packages), std::vector<std::string>({"curl"}));
    EXPECT_EQ(result.databases.size(), 1U);
}
