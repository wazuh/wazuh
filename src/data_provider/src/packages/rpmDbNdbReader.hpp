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

#ifndef _RPM_DB_NDB_READER_HPP
#define _RPM_DB_NDB_READER_HPP

#include "rpmHeaderBlobParser.hpp"

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

/// @brief Retrieval of RPM header blobs from the ndb backend.
///
/// ndb is rpm's own database format and is what the SUSE family ships. The package store
/// is `Packages.db`; the `Index.db` next to it only holds secondary indices and is not
/// needed to enumerate packages.
///
/// `Packages.db` is a slot table pointing at variable length blobs, all little endian:
///
///     [ 0.. 3] magic "RpmP"
///     [ 4.. 7] version
///     [ 8..11] generation
///     [12..15] number of slot pages
///     [16..19] next package index
///     [32..  ] slot table, 16 bytes per slot: magic "Slot", package index, block
///              offset, block count
///
/// A populated slot points at a blob living at its block offset times the 16 byte block
/// size. The blob starts with its own 16 byte header, magic "BlbS", package index,
/// generation and payload length, and the RPM header blob follows it.
namespace RpmDbNdb
{
    constexpr auto DATABASE_MAGIC { "RpmP" };
    constexpr auto SLOT_MAGIC { "Slot" };
    constexpr auto BLOB_MAGIC { "BlbS" };

    constexpr std::size_t MAGIC_SIZE { 4 };
    constexpr std::size_t BLOCK_SIZE { 16 };
    constexpr std::size_t SLOT_SIZE { 16 };
    constexpr std::size_t SLOT_TABLE_OFFSET { 32 };
    constexpr std::size_t BLOB_HEADER_SIZE { 16 };
    constexpr std::size_t PAGE_SIZE { 4096 };

    /// The first two slots of the first page are taken by the database header.
    constexpr std::size_t SLOTS_USED_BY_HEADER { 2 };

    /// A ceiling on the slot table a database may declare. Well past what a real
    /// distribution produces, and it keeps a crafted page count from being trusted.
    constexpr std::size_t MAX_SLOT_PAGES { 4096 };

    /// @brief Read a little endian uint32 without assuming the host alignment or order.
    static inline uint32_t toUint32LE(const uint8_t* bytes)
    {
        return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
               (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
    }

    /// @brief True when the bytes are an ndb package store.
    static inline bool isDatabase(const void* data, std::size_t size)
    {
        return data != nullptr && size >= SLOT_TABLE_OFFSET && std::memcmp(data, DATABASE_MAGIC, MAGIC_SIZE) == 0;
    }

    /// @brief Read a package store held in memory.
    /// @param data Full content of `Packages.db`.
    /// @param size Bytes available from @p data.
    /// @param callback Called once per header blob.
    /// @return False when the bytes are not an ndb package store.
    ///
    /// Every offset the database declares is checked against the buffer before it is
    /// followed, and a slot that does not lead to a well formed blob is skipped rather
    /// than aborting the walk, so one damaged slot costs its own package only.
    static inline bool readFromMemory(const void* data, std::size_t size, const RpmHeaderBlob::BlobCallback& callback)
    {
        if (!isDatabase(data, size))
        {
            return false;
        }

        const auto* bytes { static_cast<const uint8_t*>(data) };
        const uint64_t available { size };
        const uint64_t slotPages { toUint32LE(bytes + 12) };

        if (slotPages == 0 || slotPages > MAX_SLOT_PAGES)
        {
            return false;
        }

        const uint64_t slots = slotPages * (PAGE_SIZE / SLOT_SIZE) - SLOTS_USED_BY_HEADER;

        // The blobs of a real database sit inside the database, so the payload handed out
        // cannot exceed its size. A crafted slot table pointing many slots at one large
        // blob would otherwise turn a small file into an unbounded number of packages.
        uint64_t remaining { available };

        // Every offset is computed in 64 bits and checked against the size before it is
        // followed. The values come from the database being read, so on a 32-bit agent
        // the same arithmetic in size_t would wrap and turn a bounds check into a pass.
        for (uint64_t slot = 0; slot < slots; ++slot)
        {
            const auto slotOffset { SLOT_TABLE_OFFSET + slot * SLOT_SIZE };

            if (slotOffset + SLOT_SIZE > available)
            {
                break;
            }

            const auto* entry { bytes + slotOffset };

            if (std::memcmp(entry, SLOT_MAGIC, MAGIC_SIZE) != 0)
            {
                continue;
            }

            const uint64_t packageIndex { toUint32LE(entry + 4) };
            const uint64_t blockOffset { toUint32LE(entry + 8) };

            // A free slot carries no package and points nowhere.
            if (packageIndex == 0 || blockOffset == 0)
            {
                continue;
            }

            // Checked by division before the multiplication, and by subtraction before
            // the addition, so neither can wrap whatever width the platform gives these
            // types. Both operands come from the database being read.
            if (blockOffset > (available - BLOB_HEADER_SIZE) / BLOCK_SIZE)
            {
                continue;
            }

            const auto blobOffset { blockOffset * BLOCK_SIZE };

            if (blobOffset > available - BLOB_HEADER_SIZE ||
                    std::memcmp(bytes + blobOffset, BLOB_MAGIC, MAGIC_SIZE) != 0)
            {
                continue;
            }

            // A blob records the package it belongs to. A slot pointing at a blob that
            // names a different package is not a package of this database.
            if (toUint32LE(bytes + blobOffset + 4) != packageIndex)
            {
                continue;
            }

            const uint64_t blobSize { toUint32LE(bytes + blobOffset + 12) };
            const auto payloadOffset { blobOffset + BLOB_HEADER_SIZE };

            if (blobSize == 0 || payloadOffset > available || blobSize > available - payloadOffset)
            {
                continue;
            }

            if (blobSize > remaining)
            {
                break;
            }

            remaining -= blobSize;

            callback(bytes + static_cast<std::size_t>(payloadOffset), static_cast<std::size_t>(blobSize));
        }

        return true;
    }

    /// @brief Read a package store at a location.
    /// @param path Path of `Packages.db`.
    /// @param callback Called once per header blob.
    /// @return False when the file cannot be read as an ndb package store.
    static inline bool readFromLocation(const std::string& path, const RpmHeaderBlob::BlobCallback& callback)
    {
        std::ifstream file { path, std::ios::binary };

        if (!file.is_open())
        {
            return false;
        }

        const std::vector<uint8_t> content { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };

        return readFromMemory(content.data(), content.size(), callback);
    }
} // namespace RpmDbNdb

#endif // _RPM_DB_NDB_READER_HPP
