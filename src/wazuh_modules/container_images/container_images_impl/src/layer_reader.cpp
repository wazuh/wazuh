/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "layer_reader.hpp"
#include "ci_logging_helper.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>

namespace
{
    constexpr std::size_t TAR_BLOCK {512};

    // Field offsets and widths of the tar header, shared by the ustar, pax and GNU
    // variants: everything this reader needs sits in the same place in all three.
    constexpr std::size_t NAME_OFFSET {0};
    constexpr std::size_t NAME_LENGTH {100};
    constexpr std::size_t SIZE_OFFSET {124};
    constexpr std::size_t SIZE_LENGTH {12};
    constexpr std::size_t CHECKSUM_OFFSET {148};
    constexpr std::size_t CHECKSUM_LENGTH {8};
    constexpr std::size_t TYPE_OFFSET {156};
    constexpr std::size_t PREFIX_OFFSET {345};
    constexpr std::size_t PREFIX_LENGTH {155};

    // Ceiling on one entry's size field. Real layer entries never approach this; the
    // point is to reject a header before paddedSize(size) can overflow on a corrupt or
    // crafted base-256 value, which would otherwise desync the reader onto the entry's
    // own content instead of failing.
    constexpr std::uint64_t MAX_ENTRY_SIZE {64ULL * 1024 * 1024 * 1024};

    constexpr char TYPE_REGULAR {'0'};
    constexpr char TYPE_REGULAR_OLD {'\0'};
    constexpr char TYPE_CONTIGUOUS {'7'};      ///< Historic spelling of a regular file.
    constexpr char TYPE_PAX_EXTENDED {'x'};    ///< pax metadata for the entry that follows.
    constexpr char TYPE_PAX_GLOBAL {'g'};      ///< pax metadata for the whole archive.
    constexpr char TYPE_GNU_LONG_NAME {'L'};   ///< GNU long name for the entry that follows.
    constexpr char TYPE_GNU_LONG_LINK {'K'};   ///< GNU long link target, metadata only.

    // OverlayFS deletion markers, as written into image layers.
    const std::string WHITEOUT_PREFIX {".wh."};
    const std::string OPAQUE_MARKER {".wh..wh..opq"};

    // Ceiling for the metadata this reader buffers: a pax header or a GNU long name is a
    // few hundred bytes, so anything past this is not metadata and is refused rather
    // than allocated.
    constexpr std::uint64_t MAX_METADATA_SIZE {1024 * 1024};

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    /// @brief Parse a tar numeric field: octal ASCII, or GNU base-256 when the high bit
    /// of the first byte is set (used for values that do not fit the octal width).
    std::uint64_t parseNumericField(const char* field, std::size_t length)
    {
        if (length == 0)
        {
            return 0;
        }

        if ((static_cast<unsigned char>(field[0]) & 0x80) != 0)
        {
            std::uint64_t value {static_cast<std::uint64_t>(static_cast<unsigned char>(field[0]) & 0x7F)};

            for (std::size_t i = 1; i < length; ++i)
            {
                value = (value << 8) | static_cast<unsigned char>(field[i]);
            }

            return value;
        }

        std::uint64_t value {0};

        for (std::size_t i = 0; i < length; ++i)
        {
            const char character {field[i]};

            if (character >= '0' && character <= '7')
            {
                value = (value << 3) + static_cast<std::uint64_t>(character - '0');
            }
            else if (character == ' ' || character == '\0')
            {
                // Padding, which tar writers place at either end of the field.
                continue;
            }
            else
            {
                // Not a number: treat the field as zero rather than as a partial value.
                return 0;
            }
        }

        return value;
    }

    /// @brief Strip leading "./" segments and leading slashes so entry paths from
    /// different writers compare equal.
    std::string normalizePath(std::string path)
    {
        // The two prefixes can alternate ("/./var/..." strips to "./var/..." after one
        // slash and needs another "./" pass), so this keeps stripping until neither
        // applies instead of running each loop once.
        bool changed {true};

        while (changed)
        {
            changed = false;

            if (path.rfind("./", 0) == 0)
            {
                path.erase(0, 2);
                changed = true;
            }

            while (!path.empty() && path.front() == '/')
            {
                path.erase(0, 1);
                changed = true;
            }
        }

        return path;
    }

    /// @brief Read a fixed-width, NUL-padded string field.
    std::string readStringField(const char* field, std::size_t length)
    {
        return std::string(field, strnlen(field, length));
    }

    /// @brief True if every byte of the block is zero, which marks the end of the archive.
    bool isEndOfArchive(const std::array<char, TAR_BLOCK>& block)
    {
        return std::all_of(block.begin(), block.end(), [](const char character) { return character == '\0'; });
    }

    /// @brief True if the header's checksum field matches the header bytes.
    ///
    /// The checksum is the unsigned byte sum of the whole 512-byte block, computed with
    /// the checksum field itself treated as eight ASCII spaces, per the ustar format.
    /// Nothing before this validated that a block claiming to be a header actually is
    /// one: a corrupt or crafted block was parsed as whatever its bytes happened to
    /// decode to, which is how a resync (a phantom entry from an out-of-range size, or
    /// one from an ignored pax `size` record) could look like success instead of failure.
    bool checksumValid(const std::array<char, TAR_BLOCK>& header)
    {
        std::uint64_t expected {0};
        bool any {false};

        for (std::size_t i = 0; i < CHECKSUM_LENGTH; ++i)
        {
            const char character {header[CHECKSUM_OFFSET + i]};

            if (character >= '0' && character <= '7')
            {
                expected = (expected << 3) + static_cast<std::uint64_t>(character - '0');
                any = true;
            }
            else if (character != ' ' && character != '\0')
            {
                return false;
            }
        }

        if (!any)
        {
            return false;
        }

        std::uint64_t sum {0};

        for (std::size_t i = 0; i < TAR_BLOCK; ++i)
        {
            const auto byte {(i >= CHECKSUM_OFFSET && i < CHECKSUM_OFFSET + CHECKSUM_LENGTH)
                              ? static_cast<unsigned char>(' ')
                              : static_cast<unsigned char>(header[i])};
            sum += byte;
        }

        return sum == expected;
    }

    /// @brief Number of bytes the content of an entry occupies, padded to a whole block.
    std::uint64_t paddedSize(std::uint64_t size)
    {
        return ((size + TAR_BLOCK - 1) / TAR_BLOCK) * TAR_BLOCK;
    }

    /// @brief The `path` and `size` records of a pax extended header, when present.
    struct PaxOverrides
    {
        std::string path;
        bool hasSize {false};
        std::uint64_t size {0};
    };

    /// @brief Extract the `path` and `size` records of a pax extended header.
    ///
    /// A pax header is a sequence of "<length> <key>=<value>\n" records, where length
    /// counts the whole record. `path` carries names that do not fit the ustar fields.
    /// `size` overrides the ustar size field, which a pax writer may leave at zero for an
    /// entry whose size does not fit it (the ustar field itself already carries sizes up
    /// to 8 EiB via GNU base-256, which is what real oversized layer entries use in
    /// practice; a zero ustar size next to a pax `size` record is the case this exists
    /// for). Leaving `size` unhandled would read such an entry as zero bytes and desync
    /// on its real content, which the next loop iteration would misread as a header.
    PaxOverrides parsePaxHeader(const std::string& header)
    {
        PaxOverrides overrides;
        std::size_t offset {0};

        while (offset < header.size())
        {
            const auto space {header.find(' ', offset)};

            if (space == std::string::npos)
            {
                break;
            }

            std::uint64_t recordLength {0};

            try
            {
                recordLength = std::stoull(header.substr(offset, space - offset));
            }
            catch (const std::exception&)
            {
                break;
            }

            if (recordLength <= (space - offset) || offset + recordLength > header.size())
            {
                break;
            }

            const auto contentStart {space + 1};
            const auto contentLength {offset + recordLength - contentStart};
            const auto record {header.substr(contentStart, contentLength)};
            const auto equals {record.find('=')};

            if (equals != std::string::npos)
            {
                const auto key {record.substr(0, equals)};
                auto value {record.substr(equals + 1)};

                // The record ends with the newline that closes it.
                if (!value.empty() && value.back() == '\n')
                {
                    value.pop_back();
                }

                if (key == "path")
                {
                    overrides.path = std::move(value);
                }
                else if (key == "size")
                {
                    try
                    {
                        overrides.size = std::stoull(value);
                        overrides.hasSize = true;
                    }
                    catch (const std::exception&)
                    {
                        // An unparsable size record is ignored; the ustar field is used.
                    }
                }
            }

            offset += recordLength;
        }

        return overrides;
    }

    /// @brief Fill in the OverlayFS deletion-marker fields of an entry.
    void applyWhiteoutMarkers(containerimages::LayerEntry& entry)
    {
        const auto lastSlash {entry.path.find_last_of('/')};
        const std::string directory {lastSlash == std::string::npos ? "" : entry.path.substr(0, lastSlash + 1)};
        const std::string base {lastSlash == std::string::npos ? entry.path : entry.path.substr(lastSlash + 1)};

        // The opaque marker also starts with ".wh.", so it is checked first. An opaque
        // marker at the image root legitimately has an empty target: OverlayFS defines
        // that as "the whole root is opaque", hiding everything from earlier layers.
        if (base == OPAQUE_MARKER)
        {
            entry.isOpaqueDirectory = true;
            // The marker hides the earlier content of its own directory. The trailing
            // separator is dropped so the target is the directory path itself.
            entry.whiteoutTarget = directory.empty() ? "" : directory.substr(0, directory.size() - 1);
        }
        else if (base.rfind(WHITEOUT_PREFIX, 0) == 0)
        {
            auto target {base.substr(WHITEOUT_PREFIX.size())};

            // Unlike the opaque marker, a bare ".wh." names no target at all: it is not
            // a valid per-file marker, and treating it as one would set an empty
            // whiteoutTarget, which isUnderDirectory matches against every tracked path,
            // deleting the whole composed inventory instead of nothing.
            if (!target.empty())
            {
                entry.isWhiteout = true;
                entry.whiteoutTarget = directory + std::move(target);
            }
        }
    }
} // namespace

namespace containerimages
{
    bool LayerReader::read(IByteStream& stream, const EntryCallback& onEntry)
    {
        // Name and size carried by a pax or GNU header, which apply to the entry that
        // follows it.
        std::string pendingName;
        bool pendingSizeSet {false};
        std::uint64_t pendingSize {0};

        while (true)
        {
            std::array<char, TAR_BLOCK> header {};
            const auto got {readExact(stream, header.data(), header.size())};

            if (got == 0)
            {
                // End of stream. A layer written without the two closing zero blocks is
                // still complete as far as its entries go.
                return true;
            }

            if (got != header.size())
            {
                logDebug("Truncated tar header, stopping the layer.");
                return false;
            }

            if (isEndOfArchive(header))
            {
                return true;
            }

            if (!checksumValid(header))
            {
                logDebug("Tar header checksum mismatch, stopping the layer.");
                return false;
            }

            const char typeFlag {header[TYPE_OFFSET]};
            auto size {parseNumericField(header.data() + SIZE_OFFSET, SIZE_LENGTH)};

            auto name {readStringField(header.data() + NAME_OFFSET, NAME_LENGTH)};
            const auto prefix {readStringField(header.data() + PREFIX_OFFSET, PREFIX_LENGTH)};

            if (!prefix.empty())
            {
                name = prefix + "/" + name;
            }

            // A pax or GNU header takes precedence over the truncated name and size in
            // the fields.
            if (!pendingName.empty())
            {
                name = pendingName;
                pendingName.clear();
            }

            if (pendingSizeSet)
            {
                size = pendingSize;
                pendingSizeSet = false;
            }

            if (size > MAX_ENTRY_SIZE)
            {
                logDebug("Tar entry size out of range, stopping the layer.");
                return false;
            }

            // Metadata entries carry the name and/or size of the next entry instead of
            // file content.
            if (typeFlag == TYPE_GNU_LONG_NAME || typeFlag == TYPE_PAX_EXTENDED)
            {
                if (size > MAX_METADATA_SIZE)
                {
                    logDebug("Tar metadata entry larger than the supported size, stopping the layer.");
                    return false;
                }

                std::string metadata;
                metadata.resize(static_cast<std::size_t>(size));

                if (size > 0 && readExact(stream, metadata.data(), metadata.size()) != metadata.size())
                {
                    logDebug("Truncated tar metadata entry, stopping the layer.");
                    return false;
                }

                if (!skipBytes(stream, paddedSize(size) - size))
                {
                    return false;
                }

                if (typeFlag == TYPE_GNU_LONG_NAME)
                {
                    // The GNU long name is a NUL-terminated string.
                    const auto terminator {metadata.find('\0')};
                    pendingName = terminator == std::string::npos ? metadata : metadata.substr(0, terminator);
                }
                else
                {
                    const auto overrides {parsePaxHeader(metadata)};
                    pendingName = overrides.path;

                    if (overrides.hasSize)
                    {
                        pendingSize = overrides.size;
                        pendingSizeSet = true;
                    }
                }

                continue;
            }

            // Metadata that says nothing about the entry name: skip it and keep going.
            if (typeFlag == TYPE_PAX_GLOBAL || typeFlag == TYPE_GNU_LONG_LINK)
            {
                if (!skipBytes(stream, paddedSize(size)))
                {
                    return false;
                }

                continue;
            }

            LayerEntry entry;
            entry.path = normalizePath(name);
            entry.size = size;
            entry.isRegularFile = typeFlag == TYPE_REGULAR || typeFlag == TYPE_REGULAR_OLD || typeFlag == TYPE_CONTIGUOUS;
            applyWhiteoutMarkers(entry);

            BoundedByteStream content {stream, size};
            const auto keepReading {onEntry(entry, content)};

            // Whatever the callback did not read, plus the padding to the next block
            // boundary, is skipped here: the caller never has to know the tar layout.
            if (!skipBytes(stream, content.remaining() + (paddedSize(size) - size)))
            {
                logDebug("Truncated tar entry content, stopping the layer.");
                return false;
            }

            if (!keepReading)
            {
                return true;
            }
        }
    }
} // namespace containerimages
