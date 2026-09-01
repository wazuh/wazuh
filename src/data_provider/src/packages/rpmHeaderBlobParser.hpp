/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * August 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RPM_HEADER_BLOB_PARSER_HPP
#define _RPM_HEADER_BLOB_PARSER_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>

/// @brief Parsing of a single RPM header blob.
///
/// Every RPM database backend stores its packages as the same structure: a header blob
/// holding an index of tags and a data section the tags point into. Only the retrieval
/// differs between Berkeley DB, sqlite and ndb, so this parser is shared by all of them
/// and is the only place that knows the blob layout.
///
/// The blob is:
///
///     [ 0.. 3] uint32 BE  number of 16-byte index entries
///     [ 4.. 7] uint32 BE  size of the data section
///     [ 8..  ] index entries, each one tag, type, offset and count as uint32 BE
///     [     ] data section, the offsets are relative to its start
namespace RpmHeaderBlob
{
    constexpr int32_t HEADER_TAG_NAME       { 1000 };
    constexpr int32_t HEADER_TAG_VERSION    { 1001 };
    constexpr int32_t HEADER_TAG_RELEASE    { 1002 };
    constexpr int32_t HEADER_TAG_EPOCH      { 1003 };
    constexpr int32_t HEADER_TAG_SUMMARY    { 1004 };
    constexpr int32_t HEADER_TAG_ITIME      { 1008 };
    constexpr int32_t HEADER_TAG_SIZE       { 1009 };
    constexpr int32_t HEADER_TAG_VENDOR     { 1011 };
    constexpr int32_t HEADER_TAG_GROUP      { 1016 };
    constexpr int32_t HEADER_TAG_ARCH       { 1022 };
    constexpr int32_t HEADER_TAG_SOURCERPM  { 1044 };

    constexpr int32_t HEADER_TYPE_INT32        { 4 };
    constexpr int32_t HEADER_TYPE_STRING       { 6 };
    constexpr int32_t HEADER_TYPE_STRING_ARRAY { 8 };
    constexpr int32_t HEADER_TYPE_I18NSTRING   { 9 };

    constexpr std::size_t HEADER_FIRST_ENTRY_OFFSET { 8 };
    constexpr std::size_t HEADER_ENTRY_SIZE { 16 };

    /// This limit is defined with this value in the RPM source code (header.c).
    constexpr int64_t HEADER_TAGS_MAX { 65535 };

    /// @brief Handed one header blob at a time by a backend reader.
    using BlobCallback = std::function<void(const uint8_t*, std::size_t)>;

    /// @brief The tags the agent collects, as they are written in the blob.
    ///
    /// Every value is kept as text, including the numeric tags, so a tag that is not
    /// present stays distinguishable from one holding zero. That distinction is what
    /// decides whether a version carries an epoch.
    struct Package
    {
        std::string name;
        std::string architecture;
        std::string description; ///< SUMMARY.
        std::string size;        ///< Installed size in bytes.
        std::string epoch;       ///< Empty when the package carries no epoch.
        std::string release;
        std::string version;
        std::string vendor;
        std::string installTime; ///< Unix timestamp in seconds.
        std::string group;
        std::string source;      ///< SOURCERPM, the source package file name.
        bool valid { false };    ///< False when the blob could not be read.
    };

    /// @brief Read a big endian uint32 without assuming the host alignment or order.
    static inline uint32_t toUint32BE(const uint8_t* bytes)
    {
        return (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]);
    }

    /// @brief Parse one header blob.
    /// @param data Start of the blob.
    /// @param size Bytes available from @p data.
    /// @return The tags that were present. `valid` is false when the blob is malformed,
    ///         in which case the caller should skip the package rather than trust it.
    ///
    /// Every offset the blob declares is checked against the data section before it is
    /// read, so a crafted or truncated database costs the packages it holds and nothing
    /// else.
    static inline Package parse(const uint8_t* data, std::size_t size)
    {
        Package package;

        if (data == nullptr || size < HEADER_FIRST_ENTRY_OFFSET)
        {
            return package;
        }

        const int64_t indexSize { toUint32BE(data) };
        const int64_t dataSize { toUint32BE(data + sizeof(uint32_t)) };

        if (indexSize <= 0 || indexSize >= HEADER_TAGS_MAX || dataSize < 0)
        {
            return package;
        }

        const int64_t blobSize =
            static_cast<int64_t>(HEADER_FIRST_ENTRY_OFFSET) + indexSize * static_cast<int64_t>(HEADER_ENTRY_SIZE) + dataSize;

        if (blobSize > static_cast<int64_t>(size))
        {
            return package;
        }

        const auto* section { data + HEADER_FIRST_ENTRY_OFFSET + indexSize * HEADER_ENTRY_SIZE };
        package.valid = true;

        enum FieldIndex
        {
            FIELD_NAME, FIELD_ARCHITECTURE, FIELD_DESCRIPTION, FIELD_SIZE, FIELD_EPOCH, FIELD_RELEASE,
            FIELD_VERSION, FIELD_VENDOR, FIELD_INSTALL_TIME, FIELD_GROUP, FIELD_SOURCE, FIELD_COUNT
        };

        std::string* const fields[FIELD_COUNT]
        {
            &package.name, &package.architecture, &package.description, &package.size, &package.epoch,
            &package.release, &package.version, &package.vendor, &package.installTime, &package.group,
            &package.source
        };

        // The first occurrence of a tag is the one the rpm tooling reports. It is tracked
        // rather than inferred from the field being empty, so a repeated tag cannot
        // overwrite a first occurrence whose value is an empty string.
        bool seen[FIELD_COUNT] {};

        for (int64_t entry = 0; entry < indexSize; ++entry)
        {
            const auto* index { data + HEADER_FIRST_ENTRY_OFFSET + entry * HEADER_ENTRY_SIZE };
            const auto tag { static_cast<int32_t>(toUint32BE(index)) };
            const auto type { static_cast<int32_t>(toUint32BE(index + 4)) };
            const int64_t offset { toUint32BE(index + 8) };

            int fieldIndex { -1 };

            switch (tag)
            {
                case HEADER_TAG_NAME:
                    fieldIndex = FIELD_NAME;
                    break;

                case HEADER_TAG_ARCH:
                    fieldIndex = FIELD_ARCHITECTURE;
                    break;

                case HEADER_TAG_SUMMARY:
                    fieldIndex = FIELD_DESCRIPTION;
                    break;

                case HEADER_TAG_SIZE:
                    fieldIndex = FIELD_SIZE;
                    break;

                case HEADER_TAG_EPOCH:
                    fieldIndex = FIELD_EPOCH;
                    break;

                case HEADER_TAG_RELEASE:
                    fieldIndex = FIELD_RELEASE;
                    break;

                case HEADER_TAG_VERSION:
                    fieldIndex = FIELD_VERSION;
                    break;

                case HEADER_TAG_VENDOR:
                    fieldIndex = FIELD_VENDOR;
                    break;

                case HEADER_TAG_ITIME:
                    fieldIndex = FIELD_INSTALL_TIME;
                    break;

                case HEADER_TAG_GROUP:
                    fieldIndex = FIELD_GROUP;
                    break;

                case HEADER_TAG_SOURCERPM:
                    fieldIndex = FIELD_SOURCE;
                    break;

                default:
                    continue;
            }

            if (seen[fieldIndex])
            {
                continue;
            }

            // Claimed by its first occurrence, whatever that occurrence turns out to hold.
            seen[fieldIndex] = true;
            auto* const field { fields[fieldIndex] };

            if (offset >= dataSize)
            {
                continue;
            }

            if (HEADER_TYPE_STRING == type || HEADER_TYPE_I18NSTRING == type || HEADER_TYPE_STRING_ARRAY == type)
            {
                // A string array is stored as its elements one after another; the first
                // one is the value the agent reports.
                const auto* start { section + offset };
                const auto* terminator { static_cast<const uint8_t*>(std::memchr(start, '\0', static_cast<std::size_t>(dataSize - offset))) };

                if (terminator != nullptr)
                {
                    field->assign(reinterpret_cast<const char*>(start), static_cast<std::size_t>(terminator - start));
                }
            }
            else if (HEADER_TYPE_INT32 == type && offset + static_cast<int64_t>(sizeof(uint32_t)) <= dataSize)
            {
                *field = std::to_string(static_cast<int32_t>(toUint32BE(section + offset)));
            }
        }

        return package;
    }

    /// @brief The tab separated row the host rpm package parser consumes.
    ///
    /// The field order is the one `RPMFields` declares. Kept here so every backend feeds
    /// the host parser through the same shape.
    static inline std::string toRow(const Package& package)
    {
        return package.name + "\t" + package.architecture + "\t" + package.description + "\t" + package.size + "\t" +
               package.epoch + "\t" + package.release + "\t" + package.version + "\t" + package.vendor + "\t" +
               package.installTime + "\t" + package.group + "\t\n";
    }
} // namespace RpmHeaderBlob

#endif // _RPM_HEADER_BLOB_PARSER_HPP
