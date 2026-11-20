/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ARCHIVE_IMAGE_READER_HPP
#define _ARCHIVE_IMAGE_READER_HPP

#include "byte_stream.hpp"
#include "iimage_reader.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Opens one pass over a saved image archive that does not live on disk, such as an
    /// image a container engine exports. A tar is read twice, so it is called twice.
    ///
    /// Returns null when the archive cannot be opened. A stream that is an @ref IBlobStream is also
    /// asked whether its transfer completed, so a connection that drops mid-image is not read as a
    /// short archive.
    using ArchiveOpener = std::function<std::unique_ptr<IByteStream>()>;

    /// @brief The name and tags an image is known by, from the references listed for it.
    ///
    /// Applies the rule saved archives use for `RepoTags`: the first reference that normalises fixes
    /// the name, the tag of every reference to that name is kept once, other names and `<none>:<none>`
    /// are left out, and at most 64 references are read.
    ImageNames imageNamesOf(const std::vector<std::string>& references);

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
            /// @param stopRequested        Set when the module is asked to stop. Not owned.
            ///                             Cancels a package database read that is running.
            explicit ArchiveImageReader(std::string location,
                                        std::string knownConfigDigest = {},
                                        const std::atomic<bool>* stopRequested = nullptr);

            /// @brief Read a saved image archive supplied by @p opener rather than found at a path.
            /// @param location     Name the image goes by in the log and in its records.
            ArchiveImageReader(std::string location,
                               std::string knownConfigDigest,
                               const std::atomic<bool>* stopRequested,
                               ArchiveOpener opener);

            ImageReadResult discover() override;
            std::string sourceType() const override;

        private:
            /// @brief Read an image layout held in a directory.
            ImageReadResult readDirectory(const std::filesystem::path& path);

            /// @brief Read a saved image archive, opened once per pass.
            ImageReadResult readSavedArchive(const ArchiveOpener& open);

            std::string m_location;
            std::string m_knownConfigDigest;
            const std::atomic<bool>* m_stopRequested;
            ArchiveOpener m_opener;
    };
} // namespace containerimages

#endif // _ARCHIVE_IMAGE_READER_HPP
