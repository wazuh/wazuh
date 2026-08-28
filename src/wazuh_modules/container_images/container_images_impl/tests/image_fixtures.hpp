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
} // namespace imagefixtures

#endif // _IMAGE_FIXTURES_HPP
