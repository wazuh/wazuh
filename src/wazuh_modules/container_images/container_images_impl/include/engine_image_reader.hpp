/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENGINE_IMAGE_READER_HPP
#define _ENGINE_IMAGE_READER_HPP

#include "engine_image_source.hpp"
#include "iimage_reader.hpp"
#include "registry_image_reader.hpp"

#include <memory>
#include <optional>
#include <string>

namespace containerimages
{
    /// @brief Reads every image a container engine holds: the `<local>` reference.
    ///
    /// One configured reference yields one record per image. The record is keyed
    /// `<engine>/<image id>`, so an image keeps its row when it is retagged, a rebuilt image is a
    /// new row, and an image the engine no longer lists is not in the result, which is how the
    /// storage layer comes to report it as deleted.
    ///
    /// The engine reports the names, tags and digests of an image, and its id is the configuration
    /// digest, so an image whose id is already stored is not exported again. The others are exported
    /// as a saved image archive and read by the archive reader, streamed and never written to disk.
    class EngineImageReader final : public IImageReader
    {
        public:
            /// @param engine   Name of the engine, the location of the reference (`docker`).
            /// @param source   The engine.
            /// @param context  Limits, the stop flag, the scan's byte count and what is stored for the engine.
            EngineImageReader(std::string engine, std::shared_ptr<IEngineImageSource> source, ReaderContext context);

            /// @brief Failed when the engine cannot be asked or the module is stopping. Otherwise a
            /// success holding the current set of images: one that could not be read this time keeps
            /// the record already stored for it, and has none when nothing is.
            ImageReadResult discover() override;

            std::string sourceType() const override;

        private:
            /// @brief The record of one image, read or carried over, or nothing.
            std::optional<ImageReferenceRecord> readImage(const EngineImage& image,
                                                          const std::string& key,
                                                          const ImageReferenceRecord* stored);

            std::string m_engine;
            std::shared_ptr<IEngineImageSource> m_source;
            ReaderContext m_context;
            bool m_scanAllowanceLogged {false};
    };
} // namespace containerimages

#endif // _ENGINE_IMAGE_READER_HPP
