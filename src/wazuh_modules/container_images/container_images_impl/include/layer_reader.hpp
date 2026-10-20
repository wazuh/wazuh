/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _LAYER_READER_HPP
#define _LAYER_READER_HPP

#include "byte_stream.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace containerimages
{
    /// @brief One member of a tar stream.
    struct LayerEntry
    {
        std::string path;             ///< Normalized path: no leading "./" and no leading "/".
        std::uint64_t size {0};       ///< Content length in bytes.
        bool isRegularFile {false};   ///< True for regular files, the only entries with content worth reading.
        bool isWhiteout {false};      ///< True for a per-file OverlayFS deletion marker (".wh." prefix).
        bool isOpaqueDirectory {false}; ///< True for the opaque directory marker (".wh..wh..opq").
        std::string whiteoutTarget;   ///< For a deletion marker, the path it removes (a directory for the opaque marker).
    };

    /// @brief Streams the entries of a tar archive, which is what an image layer is.
    ///
    /// Nothing is extracted to disk and no entry is buffered by the reader itself: the
    /// callback receives a stream bounded to the entry content and decides whether to
    /// read it. Whatever the callback leaves unread is skipped.
    ///
    /// The reader takes a byte stream rather than a path, so the same code reads a layer
    /// from a file on disk, from inside a saved image archive, and from a remote blob
    /// once registries are supported.
    class LayerReader
    {
        public:
            /// @brief Invoked once per entry. Return false to stop reading the archive.
            /// @param entry Entry metadata.
            /// @param content Entry content, bounded to `entry.size`. Reading it is optional.
            using EntryCallback = std::function<bool(const LayerEntry& entry, IByteStream& content)>;

            /// @brief Read every entry of the tar stream.
            /// @param stream The tar bytes, already decompressed if needed.
            /// @param onEntry Per-entry callback.
            /// @return True if the archive was read to its end or the callback stopped it,
            ///         false if the stream was malformed or truncated.
            static bool read(IByteStream& stream, const EntryCallback& onEntry);
    };
} // namespace containerimages

#endif // _LAYER_READER_HPP
