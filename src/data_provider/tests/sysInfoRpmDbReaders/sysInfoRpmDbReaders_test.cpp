/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * August 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoRpmDbReaders_test.h"
#include "packages/rpmDbNdbReader.hpp"
#include "packages/rpmDbSqliteReader.hpp"
#include "packages/rpmHeaderBlobParser.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

void SysInfoRpmDbReadersTest::SetUp() {};
void SysInfoRpmDbReadersTest::TearDown() {};

namespace
{
    constexpr int32_t TYPE_INT32 { 4 };
    constexpr int32_t TYPE_STRING { 6 };
    constexpr int32_t TYPE_I18NSTRING { 9 };

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

    /// @brief Write a little endian uint32 over an existing buffer.
    void appendAt(std::string& buffer, const size_t offset, const uint32_t value)
    {
        buffer[offset] = static_cast<char>(value & 0xFF);
        buffer[offset + 1] = static_cast<char>((value >> 8) & 0xFF);
        buffer[offset + 2] = static_cast<char>((value >> 16) & 0xFF);
        buffer[offset + 3] = static_cast<char>((value >> 24) & 0xFF);
    }

    /// @brief One tag as it is written into a header blob.
    struct Tag
    {
        int32_t tag;
        int32_t type;
        std::string text;  ///< Used by the string types.
        int32_t number {0}; ///< Used by the int32 type.
    };

    /// @brief Build a header blob out of the given tags.
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
    std::string completeBlob()
    {
        return headerBlob(
        {
            {1000, TYPE_STRING, "bash", 0},
            {1001, TYPE_STRING, "5.1.8", 0},
            {1002, TYPE_STRING, "9.el9", 0},
            {1003, TYPE_INT32, "", 1},
            {1004, TYPE_I18NSTRING, "The GNU Bourne Again shell", 0},
            {1008, TYPE_INT32, "", 1700000000},
            {1009, TYPE_INT32, "", 7802001},
            {1011, TYPE_STRING, "Rocky", 0},
            {1016, TYPE_I18NSTRING, "Unspecified", 0},
            {1022, TYPE_STRING, "x86_64", 0},
            {1044, TYPE_STRING, "bash-5.1.8-9.el9.src.rpm", 0}
        });
    }

    /// @brief Build an rpmdb.sqlite holding the given header blobs.
    std::string sqliteDatabase(const std::vector<std::string>& blobs, const bool withPackagesTable = true)
    {
        sqlite3* database { nullptr };
        sqlite3_open(":memory:", &database);

        if (withPackagesTable)
        {
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
        }
        else
        {
            sqlite3_exec(database, "CREATE TABLE SomethingElse (value TEXT);", nullptr, nullptr, nullptr);
        }

        sqlite3_int64 size { 0 };
        auto* bytes { sqlite3_serialize(database, "main", &size, 0) };
        std::string content { reinterpret_cast<const char*>(bytes), static_cast<size_t>(size) };

        sqlite3_free(bytes);
        sqlite3_close(database);

        return content;
    }

    /// @brief Build a Packages.db holding the given header blobs.
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

    /// @brief Collect every blob a reader hands out, parsed.
    std::vector<RpmHeaderBlob::Package> collect(const std::function<bool(const RpmHeaderBlob::BlobCallback&)>& reader,
                                                bool& read)
    {
        std::vector<RpmHeaderBlob::Package> packages;

        read = reader([&packages](const uint8_t* blob, size_t size)
        {
            packages.push_back(RpmHeaderBlob::parse(blob, size));
        });

        return packages;
    }

    /// @brief Write content to a unique temporary file and return its path.
    std::string temporaryFile(const std::string& content)
    {
        static std::atomic<unsigned> counter { 0 };
        const auto path
        {
            (std::filesystem::temp_directory_path() / ("rpmdb_reader_test_" + std::to_string(counter++))).string()
        };
        std::ofstream file { path, std::ios::binary };
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        file.close();

        return path;
    }
} // namespace

// ---------------------------------------------------------------------------
// Header blob parsing, shared by every backend.
// ---------------------------------------------------------------------------

TEST_F(SysInfoRpmDbReadersTest, ParsesEveryTagTheAgentCollects)
{
    const auto blob { completeBlob() };
    const auto package { RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(blob.data()), blob.size()) };

    ASSERT_TRUE(package.valid);
    EXPECT_EQ(package.name, "bash");
    EXPECT_EQ(package.version, "5.1.8");
    EXPECT_EQ(package.release, "9.el9");
    EXPECT_EQ(package.epoch, "1");
    EXPECT_EQ(package.description, "The GNU Bourne Again shell");
    EXPECT_EQ(package.installTime, "1700000000");
    EXPECT_EQ(package.size, "7802001");
    EXPECT_EQ(package.vendor, "Rocky");
    EXPECT_EQ(package.group, "Unspecified");
    EXPECT_EQ(package.architecture, "x86_64");
    EXPECT_EQ(package.source, "bash-5.1.8-9.el9.src.rpm");
}

TEST_F(SysInfoRpmDbReadersTest, DistinguishesAnAbsentEpochFromAZeroOne)
{
    // The epoch takes part in the version ordering, so "no epoch" and "epoch 0" are two
    // different packages and the parser must not collapse them.
    const auto withoutEpoch { headerBlob({{1000, TYPE_STRING, "bash", 0}}) };
    const auto withZero { headerBlob({{1000, TYPE_STRING, "bash", 0}, {1003, TYPE_INT32, "", 0}}) };

    EXPECT_TRUE(RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(withoutEpoch.data()), withoutEpoch.size()).epoch.empty());
    EXPECT_EQ(RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(withZero.data()), withZero.size()).epoch, "0");
}

TEST_F(SysInfoRpmDbReadersTest, RejectsABlobThatIsTooShort)
{
    const std::string blob { "\x00\x00\x00\x01", 4 };

    EXPECT_FALSE(RpmHeaderBlob::parse(nullptr, 0).valid);
    EXPECT_FALSE(RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(blob.data()), blob.size()).valid);
}

TEST_F(SysInfoRpmDbReadersTest, RejectsABlobDeclaringMoreThanItCarries)
{
    auto blob { completeBlob() };

    EXPECT_FALSE(RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(blob.data()), blob.size() / 2).valid);

    // An index count past the limit the rpm sources set.
    std::string oversized;
    appendUint32BE(oversized, 70000);
    appendUint32BE(oversized, 0);
    EXPECT_FALSE(RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(oversized.data()), oversized.size()).valid);

    // An index count of zero carries no tags at all.
    std::string empty;
    appendUint32BE(empty, 0);
    appendUint32BE(empty, 0);
    EXPECT_FALSE(RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(empty.data()), empty.size()).valid);
}

TEST_F(SysInfoRpmDbReadersTest, SkipsATagPointingOutsideTheDataSection)
{
    auto blob { headerBlob({{1000, TYPE_STRING, "bash", 0}, {1011, TYPE_STRING, "Rocky", 0}}) };

    // Push the vendor offset past the end of the data section. The blob stays readable
    // and the package keeps every tag that is still inside it.
    const size_t vendorOffsetField { 8 + 16 + 8 };
    std::string patched { blob };
    patched[vendorOffsetField + 0] = static_cast<char>(0x00);
    patched[vendorOffsetField + 1] = static_cast<char>(0x00);
    patched[vendorOffsetField + 2] = static_cast<char>(0xFF);
    patched[vendorOffsetField + 3] = static_cast<char>(0xFF);

    const auto package { RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(patched.data()), patched.size()) };

    ASSERT_TRUE(package.valid);
    EXPECT_EQ(package.name, "bash");
    EXPECT_TRUE(package.vendor.empty());
}

TEST_F(SysInfoRpmDbReadersTest, BuildsTheRowTheHostPackageParserConsumes)
{
    const auto blob { headerBlob({{1000, TYPE_STRING, "Wazuh", 0}, {1004, TYPE_I18NSTRING, "The Best EDR", 0}, {1009, TYPE_INT32, "", 1}}) };
    const auto package { RpmHeaderBlob::parse(reinterpret_cast<const uint8_t*>(blob.data()), blob.size()) };

    EXPECT_EQ(RpmHeaderBlob::toRow(package), "Wazuh\t\tThe Best EDR\t1\t\t\t\t\t\t\t\n");
}

// ---------------------------------------------------------------------------
// sqlite backend.
// ---------------------------------------------------------------------------

TEST_F(SysInfoRpmDbReadersTest, ReadsEveryPackageOfASqliteDatabaseInMemory)
{
    const auto database { sqliteDatabase({completeBlob(), completeBlob()}) };
    bool read { false };

    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbSqlite::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    ASSERT_EQ(packages.size(), 2U);
    EXPECT_EQ(packages.front().name, "bash");
}

TEST_F(SysInfoRpmDbReadersTest, ReadsADatabaseInWriteAheadLogMode)
{
    // rpm keeps its database in write-ahead log mode, which is what a real rpmdb.sqlite
    // taken out of an image layer carries. A database handed to sqlite as bytes cannot be
    // in that mode, so the reader has to account for it or every current Red Hat and
    // Fedora image reports no packages at all.
    auto database { sqliteDatabase({completeBlob()}) };
    database[18] = 2;
    database[19] = 2;

    bool read { false };
    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbSqlite::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "bash");
}

TEST_F(SysInfoRpmDbReadersTest, ReadsADatabaseWhoseReadVersionAloneSaysWriteAheadLog)
{
    // The two header version bytes are normalized on their own. A database carrying the
    // write-ahead log value in the read byte only was refused when the write byte alone
    // decided whether to normalize.
    auto database { sqliteDatabase({completeBlob()}) };
    database[18] = 1;
    database[19] = 2;

    bool read { false };
    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbSqlite::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    EXPECT_EQ(packages.size(), 1U);
}

TEST_F(SysInfoRpmDbReadersTest, RefusesAFileFormatNewerThanTheReaderKnows)
{
    // A version byte above the write-ahead log value means a format this sqlite does not
    // know. Normalizing it would read the file as something it is not.
    auto database { sqliteDatabase({completeBlob()}) };
    database[18] = 3;
    database[19] = 3;

    bool read { true };

    collect([&database](const RpmHeaderBlob::BlobCallback & callback)
    {
        return RpmDbSqlite::readFromMemory(database.data(), database.size(), callback);
    }, read);

    EXPECT_FALSE(read);
}

TEST_F(SysInfoRpmDbReadersTest, ReadsASqliteDatabaseFromALocation)
{
    const auto path { temporaryFile(sqliteDatabase({completeBlob()})) };
    bool read { false };

    const auto packages
    {
        collect([&path](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbSqlite::readFromLocation(path, callback);
        }, read)
    };

    std::remove(path.c_str());

    EXPECT_TRUE(read);
    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "bash");
}

TEST_F(SysInfoRpmDbReadersTest, RejectsContentThatIsNoSqliteDatabase)
{
    bool read { true };
    const std::string content { "not a database" };

    collect([&content](const RpmHeaderBlob::BlobCallback & callback)
    {
        return RpmDbSqlite::readFromMemory(content.data(), content.size(), callback);
    }, read);

    EXPECT_FALSE(read);
    EXPECT_FALSE(RpmDbSqlite::isDatabase(nullptr, 0));
}

TEST_F(SysInfoRpmDbReadersTest, RejectsASqliteDatabaseWithNoPackagesTable)
{
    const auto database { sqliteDatabase({}, false) };
    bool read { true };

    collect([&database](const RpmHeaderBlob::BlobCallback & callback)
    {
        return RpmDbSqlite::readFromMemory(database.data(), database.size(), callback);
    }, read);

    EXPECT_FALSE(read);
}

TEST_F(SysInfoRpmDbReadersTest, RejectsAMissingSqliteLocation)
{
    bool read { true };

    collect([](const RpmHeaderBlob::BlobCallback & callback)
    {
        return RpmDbSqlite::readFromLocation("/nonexistent/path/rpmdb.sqlite", callback);
    }, read);

    EXPECT_FALSE(read);
}

// ---------------------------------------------------------------------------
// ndb backend.
// ---------------------------------------------------------------------------

TEST_F(SysInfoRpmDbReadersTest, ReadsEveryPackageOfAnNdbDatabaseInMemory)
{
    const auto database { ndbDatabase({completeBlob(), completeBlob(), completeBlob()}) };
    bool read { false };

    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbNdb::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    ASSERT_EQ(packages.size(), 3U);
    EXPECT_EQ(packages.front().name, "bash");
    EXPECT_EQ(packages.back().version, "5.1.8");
}

TEST_F(SysInfoRpmDbReadersTest, ReadsAnNdbDatabaseFromALocation)
{
    const auto path { temporaryFile(ndbDatabase({completeBlob()})) };
    bool read { false };

    const auto packages
    {
        collect([&path](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbNdb::readFromLocation(path, callback);
        }, read)
    };

    std::remove(path.c_str());

    EXPECT_TRUE(read);
    ASSERT_EQ(packages.size(), 1U);
}

TEST_F(SysInfoRpmDbReadersTest, RejectsContentThatIsNoNdbDatabase)
{
    bool read { true };
    const auto sqlite { sqliteDatabase({completeBlob()}) };

    collect([&sqlite](const RpmHeaderBlob::BlobCallback & callback)
    {
        return RpmDbNdb::readFromMemory(sqlite.data(), sqlite.size(), callback);
    }, read);

    EXPECT_FALSE(read);
}

TEST_F(SysInfoRpmDbReadersTest, SkipsAFreeSlot)
{
    auto database { ndbDatabase({completeBlob(), completeBlob()}) };

    // Clear the package index of the first slot, which is how ndb marks it free.
    database[32 + 4] = '\0';
    database[32 + 5] = '\0';
    database[32 + 6] = '\0';
    database[32 + 7] = '\0';

    bool read { false };
    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbNdb::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    EXPECT_EQ(packages.size(), 1U);
}

TEST_F(SysInfoRpmDbReadersTest, SkipsASlotWhoseBlobIsNotWellFormed)
{
    auto database { ndbDatabase({completeBlob(), completeBlob()}) };

    // Break the magic of the first blob. The walk keeps going and the second package is
    // still reported, so one damaged slot costs its own package only.
    database[4096] = 'X';

    bool read { false };
    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbNdb::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    EXPECT_EQ(packages.size(), 1U);
}

TEST_F(SysInfoRpmDbReadersTest, SkipsABlobDeclaringMoreThanTheDatabaseHolds)
{
    auto database { ndbDatabase({completeBlob()}) };

    // A blob length running past the end of the file, which a crafted image could carry.
    database[4096 + 12] = static_cast<char>(0xFF);
    database[4096 + 13] = static_cast<char>(0xFF);
    database[4096 + 14] = static_cast<char>(0xFF);
    database[4096 + 15] = static_cast<char>(0x0F);

    bool read { false };
    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbNdb::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    EXPECT_TRUE(packages.empty());
}

TEST_F(SysInfoRpmDbReadersTest, NeverHandsOutMoreThanTheDatabaseHolds)
{
    // A crafted slot whose block offset, multiplied by the block size, wraps a 32-bit
    // size_t: on an i386 agent the product lands back inside the buffer and every bounds
    // check passes, so the reader used to hand the parser a length of nearly 4 GiB over a
    // 96-byte file.
    //
    // On a 64-bit build this input is rejected by the size comparison alone, so this case
    // cannot fail here even with the fix reverted: it pins the invariant, not the bug. The
    // bug itself is only reachable on a 32-bit build, and the reproducer that shows it is
    // in the review probes of the issue folder. What makes it unreachable is that the
    // reader now bounds the block offset by division before it multiplies, so the
    // arithmetic cannot wrap at any width.
    std::string database(96, '\0');
    std::memcpy(&database[0], "RpmP", 4);
    appendAt(database, 12, 1);            // one slot page
    appendAt(database, 16, 2);            // next package index

    std::memcpy(&database[32], "Slot", 4);
    appendAt(database, 36, 1);            // package index
    appendAt(database, 40, 268435459u);   // block offset: 268435459 * 16 == 2^32 + 48
    appendAt(database, 44, 1);            // block count

    std::memcpy(&database[48], "BlbS", 4);
    appendAt(database, 52, 1);
    appendAt(database, 56, 0);
    appendAt(database, 60, 0xFFFFFFF0u);  // a blob length that wraps when the header is added

    bool read { false };
    std::vector<size_t> handed;

    read = RpmDbNdb::readFromMemory(database.data(), database.size(),
                                    [&handed](const uint8_t*, size_t size)
    {
        handed.push_back(size);
    });

    EXPECT_TRUE(read);

    for (const auto size : handed)
    {
        EXPECT_LE(size, database.size()) << "a blob larger than the database was handed out";
    }
}

TEST_F(SysInfoRpmDbReadersTest, SkipsASlotWhoseBlobNamesAnotherPackage)
{
    // Every blob records the package it belongs to. Without that check a crafted slot
    // table can point a million slots at one large blob, and a small database turns into
    // an unbounded number of packages.
    auto database { ndbDatabase({completeBlob()}) };

    // Add a second slot, pointing at the same blob under a different package index.
    std::memcpy(&database[48], "Slot", 4);
    std::memcpy(&database[48 + 4], &database[32 + 4], 4);
    std::memcpy(&database[48 + 8], &database[32 + 8], 4);
    std::memcpy(&database[48 + 12], &database[32 + 12], 4);
    database[48 + 4] = 2;

    bool read { false };
    const auto packages
    {
        collect([&database](const RpmHeaderBlob::BlobCallback & callback)
        {
            return RpmDbNdb::readFromMemory(database.data(), database.size(), callback);
        }, read)
    };

    EXPECT_TRUE(read);
    EXPECT_EQ(packages.size(), 1U) << "the same blob was reported under two package indices";
}

TEST_F(SysInfoRpmDbReadersTest, StopsOnceThePayloadWouldExceedTheDatabase)
{
    // The blobs of a real database sit inside it, so the payload handed out can never
    // exceed its size. Repeating one slot cannot make the reader produce more than that.
    auto database { ndbDatabase({completeBlob()}) };
    const auto slot { database.substr(32, 16) };

    for (size_t copy = 1; copy < 200; ++copy)
    {
        database.replace(32 + copy * 16, 16, slot);
    }

    bool read { false };
    size_t handed { 0 };

    read = RpmDbNdb::readFromMemory(database.data(), database.size(),
                                    [&handed](const uint8_t*, size_t size)
    {
        handed += size;
    });

    EXPECT_TRUE(read);
    EXPECT_LE(handed, database.size());
}

TEST_F(SysInfoRpmDbReadersTest, RejectsAnNdbDatabaseDeclaringNoSlotPages)
{
    auto database { ndbDatabase({completeBlob()}) };
    database[12] = '\0';

    bool read { true };

    collect([&database](const RpmHeaderBlob::BlobCallback & callback)
    {
        return RpmDbNdb::readFromMemory(database.data(), database.size(), callback);
    }, read);

    EXPECT_FALSE(read);
}
