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

    /// @brief The outcome of reading one source.
    struct ImageReadResult
    {
        ReadStatus status {ReadStatus::Success};
        std::vector<ImageReferenceRecord> records {};
        /// For an unchanged source: the digests the image is known by now, when the reader
        /// has them. The index above an image can change while its configuration does not.
        std::vector<std::string> digests {};

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

        /// @brief The source still holds the image the caller already has stored.
        /// @param digests The digests the image is known by now, so the caller can refresh
        ///                its stored list without reading the image again.
        static ImageReadResult unchanged(std::vector<std::string> digests = {})
        {
            return {ReadStatus::Unchanged, {}, std::move(digests)};
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
