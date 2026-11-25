/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IIMAGE_READER_HPP
#define _IIMAGE_READER_HPP

#include "image_inventory_types.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace containerimages
{
    /// @brief Whether a source could be read, and what that means for what it holds.
    enum class ReadStatus
    {
        Success,   ///< The source was read. The records are its current contents.
        Failed,    ///< The source could not be read. Nothing is known about it this time.
        Unchanged, ///< The source holds the image already stored, so it was not read again.
    };

    /// @brief The name and tags an image is known by.
    struct ImageNames
    {
        std::string name;
        std::vector<std::string> tags;
    };

    /// @brief The outcome of reading one source.
    struct ImageReadResult
    {
        ReadStatus status {ReadStatus::Success};
        std::vector<ImageReferenceRecord> records {};
        /// For an unchanged source: the digests the image is known by now, when the reader
        /// has them. The index above an image can change while its configuration does not.
        std::vector<std::string> digests {};
        /// For an unchanged source: the name and tags the image is known by now, when the reader
        /// has them. An image can be retagged while its configuration does not change. Unlike the
        /// digests, an empty name and list are a value here (the image lost its names).
        std::optional<ImageNames> names {};
        /// For a failed read: the image was read, but a package database of it could not be, for a reason
        /// that says nothing about the database. What is stored is kept and the image is read again by the
        /// next scan, with no wait: nothing was wrong with getting it. That goes on until the same image has
        /// failed this way MAX_TRANSIENT_READS scans in a row. Then a database that hangs libdb is recorded
        /// as unreadable (a normal result), and any other cause leaves the image alone, still failed and
        /// kept, until this process restarts or its configuration changes.
        bool transient {false};

        /// @brief A successful read of @p records.
        static ImageReadResult success(std::vector<ImageReferenceRecord> records)
        {
            return {ReadStatus::Success, std::move(records)};
        }

        /// @brief A read that could not be completed.
        static ImageReadResult failed()
        {
            return {ReadStatus::Failed, {}};
        }

        /// @brief A read whose package databases could not be read now, which the next scan tries again
        /// unless this process has given up on the image.
        static ImageReadResult transientFailure()
        {
            return {ReadStatus::Failed, {}, {}, std::nullopt, true};
        }

        /// @brief The source still holds the image the caller already has stored.
        /// @param digests The digests the image is known by now, so the caller can refresh
        ///                its stored list without reading the image again.
        /// @param names   The name and tags it is known by now, for the same purpose.
        static ImageReadResult unchanged(std::vector<std::string> digests = {},
                                         std::optional<ImageNames> names = std::nullopt)
        {
            return {ReadStatus::Unchanged, {}, std::move(digests), std::move(names)};
        }
    };

    /// @brief Source-agnostic image reference reader.
    ///
    /// Each concrete reader knows how to enumerate image references from one kind of
    /// source (local on-disk layout, a runtime socket, a remote registry, ...). New
    /// source types are added by implementing this interface; callers never depend on
    /// a concrete reader.
    class IImageReader
    {
        public:
            virtual ~IImageReader() = default;

            /// @brief Enumerate the image references available at this source.
            /// @return The outcome of the read, and one record per image reference when it
            ///         succeeded.
            ///
            /// A reader must report a read it could not complete, because an empty result
            /// and a failed read mean opposite things to the caller: the first says the
            /// source holds nothing, the second says nothing is known about it this time.
            virtual ImageReadResult discover() = 0;

            /// @brief Identifier of the source type, used for references and logs.
            virtual std::string sourceType() const = 0;
    };
} // namespace containerimages

#endif // _IIMAGE_READER_HPP
