/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMAGE_FIXTURES_HPP
#define _IMAGE_FIXTURES_HPP

#include <zlib.h>
#include <zstd.h>

#include "sqlite3.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/// @brief Builders for the image inputs the extraction tests read.
///
/// Everything is built here rather than checked in as a binary: the tests then state the
/// tar variant and the layer order they exercise, instead of hiding them in a fixture
/// file nobody can read.
namespace imagefixtures
{
    constexpr std::size_t TAR_BLOCK {512};

    /// @brief tar type flags used by the fixtures.
    constexpr char TYPE_REGULAR {'0'};
    constexpr char TYPE_DIRECTORY {'5'};
    constexpr char TYPE_PAX_EXTENDED {'x'};
    constexpr char TYPE_GNU_LONG_NAME {'L'};

    /// @brief Write an octal field, NUL-terminated, the way tar writers do.
    inline void writeOctal(char* field, const std::size_t width, const std::uint64_t value)
    {
        std::string text;
        auto remaining {value};

        do
        {
            text.insert(text.begin(), static_cast<char>('0' + (remaining & 7U)));
            remaining >>= 3;
        }
        while (remaining > 0);

        if (text.size() > width - 1)
        {
            throw std::runtime_error("octal field overflow in the tar fixture");
        }

        text.insert(text.begin(), width - 1 - text.size(), '0');
        std::copy(text.begin(), text.end(), field);
        field[width - 1] = '\0';
    }

    /// @brief One tar member: a 512-byte header plus the padded content.
    ///
    /// @param name Entry name, written to the name field (and the prefix field when a
    ///             `prefix` is given, which is the ustar way of holding a long path).
    /// @param content Entry content.
    /// @param typeFlag tar type flag.
    /// @param prefix ustar prefix field, prepended to the name by a reader.
    inline std::string tarMember(const std::string& name,
                                 const std::string& content,
                                 const char typeFlag = TYPE_REGULAR,
                                 const std::string& prefix = {})
    {
        std::array<char, TAR_BLOCK> header {};

        if (name.size() > 100 || prefix.size() > 155)
        {
            throw std::runtime_error("name does not fit the tar fixture header");
        }

        std::copy(name.begin(), name.end(), header.data());
        writeOctal(header.data() + 100, 8, 0644);   // mode
        writeOctal(header.data() + 108, 8, 0);      // uid
        writeOctal(header.data() + 116, 8, 0);      // gid
        writeOctal(header.data() + 124, 12, content.size());
        writeOctal(header.data() + 136, 12, 0);     // mtime
        header[156] = typeFlag;
        std::copy_n("ustar", 5, header.data() + 257);
        header[263] = '0';
        header[264] = '0';
        std::copy(prefix.begin(), prefix.end(), header.data() + 345);

        // The checksum is computed with the checksum field read as spaces, and stored as six
        // octal digits followed by a NUL and a space, which is what tar writers do.
        std::fill_n(header.data() + 148, 8, ' ');
        std::uint64_t checksum {0};

        for (const auto byte : header)
        {
            checksum += static_cast<unsigned char>(byte);
        }

        writeOctal(header.data() + 148, 7, checksum);
        header[155] = ' ';

        std::string member {header.data(), header.size()};
        member += content;

        const auto padding {(TAR_BLOCK - (content.size() % TAR_BLOCK)) % TAR_BLOCK};
        member.append(padding, '\0');

        return member;
    }

    /// @brief The two zero blocks that close a tar archive.
    inline std::string tarEnd()
    {
        return std::string(2 * TAR_BLOCK, '\0');
    }

    /// @brief A pax extended header carrying one "<key>=<value>" record for the entry
    /// that follows it.
    inline std::string paxRecord(const std::string& key, const std::string& value)
    {
        // A pax record is "<length> <key>=<value>\n", where length counts the digits of
        // the length itself, so it is solved by iterating until it stops changing.
        const std::string body {key + "=" + value + "\n"};
        std::size_t length {body.size() + 2};

        while (std::to_string(length).size() + 1 + body.size() != length)
        {
            length = std::to_string(length).size() + 1 + body.size();
        }

        return tarMember("PaxHeaders/entry", std::to_string(length) + " " + body, TYPE_PAX_EXTENDED);
    }

    /// @brief A pax extended header carrying the name of the entry that follows it.
    inline std::string paxLongName(const std::string& path)
    {
        return paxRecord("path", path);
    }

    /// @brief A GNU long name header carrying the name of the entry that follows it.
    inline std::string gnuLongName(const std::string& path)
    {
        return tarMember("././@LongLink", path + std::string(1, '\0'), TYPE_GNU_LONG_NAME);
    }

    /// @brief Compress a buffer as a gzip member, the way layer blobs are stored.
    inline std::string gzip(const std::string& content)
    {
        z_stream stream {};

        if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            throw std::runtime_error("could not initialize the gzip fixture");
        }

        std::string output;
        output.resize(content.size() + 1024);

        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(content.data()));
        stream.avail_in = static_cast<uInt>(content.size());
        stream.next_out = reinterpret_cast<Bytef*>(output.data());
        stream.avail_out = static_cast<uInt>(output.size());

        const auto result {deflate(&stream, Z_FINISH)};
        const auto produced {output.size() - stream.avail_out};
        deflateEnd(&stream);

        if (result != Z_STREAM_END)
        {
            throw std::runtime_error("could not compress the gzip fixture");
        }

        output.resize(produced);
        return output;
    }

    /// @brief Compress a buffer as a zstd frame, the other compression the OCI image
    ///        specification defines for a layer.
    inline std::string zstd(const std::string& content)
    {
        std::string output;
        output.resize(ZSTD_compressBound(content.size()));

        const auto produced {ZSTD_compress(output.data(), output.size(), content.data(), content.size(), 3)};

        if (ZSTD_isError(produced))
        {
            throw std::runtime_error("could not compress the zstd fixture");
        }

        output.resize(produced);
        return output;
    }

    /// @brief A dpkg status stanza for one installed package.
    inline std::string dpkgStanza(const std::string& name,
                                  const std::string& version,
                                  const std::string& architecture = "amd64",
                                  const std::string& status = "install ok installed")
    {
        return "Package: " + name + "\n"
               "Status: " + status + "\n"
               "Priority: optional\n"
               "Section: utils\n"
               "Installed-Size: 100\n"
               "Maintainer: Debian " + name + " Maintainers <team@debian.org>\n"
               "Architecture: " + architecture + "\n"
               "Multi-Arch: same\n"
               "Source: " + name + "-source\n"
               "Version: " + version + "\n"
               "Description: short description of " + name + "\n"
               " a continuation line that is not part of the short description\n"
               "\n";
    }

    /// @brief An apk installed-database stanza for one package.
    inline std::string apkStanza(const std::string& name,
                                 const std::string& version,
                                 const std::string& architecture = "x86_64")
    {
        return "C:Q1exampleexampleexampleexampleexample=\n"
               "P:" + name + "\n"
               "V:" + version + "\n"
               "A:" + architecture + "\n"
               "S:1000\n"
               "I:2048\n"
               "T:short description of " + name + "\n"
               "U:https://example.invalid/" + name + "\n"
               "L:MIT\n"
               "o:" + name + "-origin\n"
               "m:Alpine " + name + " Maintainers <team@alpinelinux.org>\n"
               "\n";
    }

    // -----------------------------------------------------------------------
    // rpm databases.
    // -----------------------------------------------------------------------

    /// @brief One package as it is written into an rpm header blob.
    struct RpmPackage
    {
        std::string name;
        std::string version;
        std::string release {"1.el9"};
        std::string architecture {"x86_64"};
        std::string summary {"short description"};
        std::string vendor {"Wazuh Inc."};
        std::string group {"Unspecified"};
        std::string sourceRpm {};
        std::int32_t size {2048};
        std::int32_t installTime {1700000000};
        bool hasEpoch {false};
        std::int32_t epoch {0};
    };

    /// @brief Append a big endian uint32, the order the rpm header index uses.
    inline void appendUint32BE(std::string& output, const std::uint32_t value)
    {
        output += static_cast<char>((value >> 24) & 0xFF);
        output += static_cast<char>((value >> 16) & 0xFF);
        output += static_cast<char>((value >> 8) & 0xFF);
        output += static_cast<char>(value & 0xFF);
    }

    /// @brief Append a little endian uint32, the order the ndb database uses.
    inline void appendUint32LE(std::string& output, const std::uint32_t value)
    {
        output += static_cast<char>(value & 0xFF);
        output += static_cast<char>((value >> 8) & 0xFF);
        output += static_cast<char>((value >> 16) & 0xFF);
        output += static_cast<char>((value >> 24) & 0xFF);
    }

    /// @brief Build one rpm header blob, the structure every rpm backend stores.
    inline std::string rpmHeaderBlob(const RpmPackage& package)
    {
        constexpr std::int32_t TYPE_INT32 {4};
        constexpr std::int32_t TYPE_STRING {6};
        constexpr std::int32_t TYPE_I18NSTRING {9};

        std::string section;
        std::string index;
        std::size_t entries {0};

        const auto addString
        {
            [&section, &index, &entries](const std::int32_t tag, const std::int32_t type, const std::string & value)
            {
                appendUint32BE(index, static_cast<std::uint32_t>(tag));
                appendUint32BE(index, static_cast<std::uint32_t>(type));
                appendUint32BE(index, static_cast<std::uint32_t>(section.size()));
                appendUint32BE(index, 1);
                section += value;
                section += '\0';
                ++entries;
            }
        };

        const auto addInt32
        {
            [&section, &index, &entries](const std::int32_t tag, const std::int32_t value)
            {
                appendUint32BE(index, static_cast<std::uint32_t>(tag));
                appendUint32BE(index, static_cast<std::uint32_t>(TYPE_INT32));
                appendUint32BE(index, static_cast<std::uint32_t>(section.size()));
                appendUint32BE(index, 1);
                appendUint32BE(section, static_cast<std::uint32_t>(value));
                ++entries;
            }
        };

        addString(1000, TYPE_STRING, package.name);
        addString(1001, TYPE_STRING, package.version);
        addString(1002, TYPE_STRING, package.release);

        if (package.hasEpoch)
        {
            addInt32(1003, package.epoch);
        }

        // The summary is an internationalized string in a real database, which is a
        // different type carrying the same bytes.
        addString(1004, TYPE_I18NSTRING, package.summary);
        addInt32(1008, package.installTime);
        addInt32(1009, package.size);
        addString(1011, TYPE_STRING, package.vendor);
        addString(1016, TYPE_I18NSTRING, package.group);
        addString(1022, TYPE_STRING, package.architecture);

        if (!package.sourceRpm.empty())
        {
            addString(1044, TYPE_STRING, package.sourceRpm);
        }

        std::string blob;
        appendUint32BE(blob, static_cast<std::uint32_t>(entries));
        appendUint32BE(blob, static_cast<std::uint32_t>(section.size()));
        blob += index;
        blob += section;

        return blob;
    }

    /// @brief Build an `rpmdb.sqlite` holding the given header blobs.
    ///
    /// Written through sqlite itself and serialized back out, so the fixture is a real
    /// database file rather than a hand-made approximation of one.
    inline std::string rpmSqliteDatabase(const std::vector<std::string>& blobs)
    {
        sqlite3* database {nullptr};

        if (sqlite3_open(":memory:", &database) != SQLITE_OK)
        {
            sqlite3_close(database);
            throw std::runtime_error {"could not create the sqlite fixture"};
        }

        sqlite3_exec(database, "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL);", nullptr,
                     nullptr, nullptr);

        sqlite3_stmt* statement {nullptr};
        sqlite3_prepare_v2(database, "INSERT INTO Packages (blob) VALUES (?);", -1, &statement, nullptr);

        for (const auto& blob : blobs)
        {
            sqlite3_bind_blob(statement, 1, blob.data(), static_cast<int>(blob.size()), SQLITE_STATIC);
            sqlite3_step(statement);
            sqlite3_reset(statement);
        }

        sqlite3_finalize(statement);

        sqlite3_int64 size {0};
        auto* bytes {sqlite3_serialize(database, "main", &size, 0)};
        std::string content {reinterpret_cast<const char*>(bytes), static_cast<std::size_t>(size)};

        sqlite3_free(bytes);
        sqlite3_close(database);

        return content;
    }

    /// @brief Build a `Packages.db` holding the given header blobs.
    ///
    /// One slot page, the slot table right behind the 32-byte header, and the blobs laid
    /// out from the second page on, each behind its own 16-byte header.
    inline std::string rpmNdbDatabase(const std::vector<std::string>& blobs)
    {
        constexpr std::size_t BLOCK {16};
        constexpr std::size_t PAGE {4096};
        constexpr std::size_t SLOT_TABLE_OFFSET {32};

        std::string slots;
        std::string payloads;

        for (std::size_t package = 0; package < blobs.size(); ++package)
        {
            const auto blockOffset {(PAGE + payloads.size()) / BLOCK};
            const auto blockCount {(BLOCK + blobs[package].size() + BLOCK - 1) / BLOCK};

            slots += "Slot";
            appendUint32LE(slots, static_cast<std::uint32_t>(package + 1));
            appendUint32LE(slots, static_cast<std::uint32_t>(blockOffset));
            appendUint32LE(slots, static_cast<std::uint32_t>(blockCount));

            payloads += "BlbS";
            appendUint32LE(payloads, static_cast<std::uint32_t>(package + 1));
            appendUint32LE(payloads, 1);
            appendUint32LE(payloads, static_cast<std::uint32_t>(blobs[package].size()));
            payloads += blobs[package];
            payloads.resize(((payloads.size() + BLOCK - 1) / BLOCK) * BLOCK, '\0');
        }

        std::string database;
        database += "RpmP";
        appendUint32LE(database, 0);                                       // version
        appendUint32LE(database, 1);                                       // generation
        appendUint32LE(database, 1);                                       // slot pages
        appendUint32LE(database, static_cast<std::uint32_t>(blobs.size() + 1)); // next package index
        database.resize(SLOT_TABLE_OFFSET, '\0');

        database += slots;
        database.resize(PAGE, '\0');
        database += payloads;

        return database;
    }
} // namespace imagefixtures

#endif // _IMAGE_FIXTURES_HPP
