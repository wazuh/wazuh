/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ARCHIVE_IMAGE_READER_HPP
#define _ARCHIVE_IMAGE_READER_HPP

#include "iimage_reader.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Reads image references, and the packages they contain, from an image on disk.
    ///
    /// Two inputs are supported, and both end up describing their layers the same way
    /// once the metadata is parsed:
    ///
    /// - An OCI image layout directory: `index.json` lists the manifests, and each
    ///   manifest points to a configuration blob and to the layer blobs.
    /// - A saved image archive, that is the output of `docker save`: a tar file holding
    ///   either an OCI layout or the older `manifest.json` layout. The extracted form of
    ///   that layout is read as a directory.
    ///
    /// Layers are streamed and only the package databases are kept, so no image is
    /// extracted to disk and the image filesystem is never reconstructed.
    class ArchiveImageReader final : public IImageReader
    {
        public:
            /// @param location            Path this reader reads.
            /// @param knownConfigDigest    Configuration digest already stored for this
            ///                             location, empty when there is none. When the
            ///                             image at the location still reports that digest
            ///                             its layers are not read again, because its
            ///                             contents cannot have changed.
            explicit ArchiveImageReader(std::string location, std::string knownConfigDigest = {});

            ImageReadResult discover() override;
            std::string sourceType() const override;

        private:
            /// @brief Read an image layout held in a directory.
            ImageReadResult readDirectory(const std::filesystem::path& path);

            /// @brief Read a saved image archive.
            ImageReadResult readSavedArchive(const std::filesystem::path& path);

            std::string m_location;
            std::string m_knownConfigDigest;
    };
} // namespace containerimages

#endif // _ARCHIVE_IMAGE_READER_HPP
