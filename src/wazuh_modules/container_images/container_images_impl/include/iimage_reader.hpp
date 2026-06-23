/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
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
#include <vector>

namespace containerimages
{
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
            /// @return One record per discovered image reference.
            virtual std::vector<ImageReferenceRecord> discover() = 0;

            /// @brief Identifier of the source type, used for references and logs.
            virtual std::string sourceType() const = 0;
    };
} // namespace containerimages

#endif // _IIMAGE_READER_HPP
