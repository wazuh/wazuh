/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENGINE_IMAGE_SOURCE_HPP
#define _ENGINE_IMAGE_SOURCE_HPP

#include "registry_byte_stream.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief One image held by a container engine, as the engine lists it.
    struct EngineImage
    {
        std::string id;                       ///< Image id, `sha256:<hex>`. For Docker this is the configuration digest.
        std::vector<std::string> repoTags;    ///< Names the image carries, `repository:tag`. Empty or `<none>:<none>` when it has none.
        std::vector<std::string> repoDigests; ///< Names pinned by content, `repository@algorithm:digest`.
        std::uint64_t size {0};               ///< Size in bytes the engine reports for the image. Zero when it does not say.
    };

    /// @brief What the module needs of a container engine: the images it holds, and one of them exported.
    ///
    /// Narrow on purpose, so the Docker client can later be replaced by the one runtime security
    /// shares, or by another engine, without touching the reader that inventories the images.
    class IEngineImageSource
    {
        public:
            virtual ~IEngineImageSource() = default;

            /// @brief List the images the engine holds.
            /// @param images Filled in on success.
            /// @param error  Why the engine could not be asked, on failure. An engine that holds
            ///               no image is a success with an empty list.
            virtual bool listImages(std::vector<EngineImage>& images, std::string& error) = 0;

            /// @brief Export one image as a saved image archive (the `docker save` tar).
            /// @param id       Id of the image, as listed.
            /// @param maxBytes Ceiling on the bytes the stream may deliver.
            /// @param error    Why no stream was produced, when that is the outcome.
            /// @return The archive, or null when the export could not start. A transfer that
            ///         fails later is reported by the stream itself (`failed()`).
            virtual std::unique_ptr<IBlobStream> exportImage(const std::string& id,
                                                             std::uint64_t maxBytes,
                                                             std::string& error) = 0;
    };
} // namespace containerimages

#endif // _ENGINE_IMAGE_SOURCE_HPP
