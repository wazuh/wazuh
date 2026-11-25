/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _LAYER_COMPOSER_HPP
#define _LAYER_COMPOSER_HPP

#include "byte_stream.hpp"
#include "image_inventory_types.hpp"

#include <atomic>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace PackageDb
{
    struct BerkeleyDbOptions;
}

namespace containerimages
{
    /// Consecutive reads of one image in which a Berkeley DB database could not be read for a reason that is
    /// not its own (a timeout, no process, an account that cannot read), before the image is given up. A file
    /// that hangs libdb hangs it every time, and a machine that cannot drop privileges cannot on the next
    /// scan either, so each scan would pay for it again.
    ///
    /// A deadline missed is a property of the image: the database is recorded as unreadable, stored with the
    /// image's digest, and stays so until the image changes. Any other cause is a property of the host, which
    /// can be fixed: the image is only left alone for the life of the process, what is stored for it stays,
    /// and a restart or a configuration change reads it again.
    constexpr unsigned MAX_TRANSIENT_READS {3};

    /// @brief Consecutive transient failures of the Berkeley DB read of each image, by reference and configuration digest.
    ///
    /// An image is its reference and its digest, so the images of one reference (an archive that holds
    /// several) do not reset one another, and an image that changed starts again. Lives with the module, so
    /// it is lost at a restart.
    struct ReadFailures
    {
        struct Entry
        {
            unsigned count {0};
            bool givenUp {false}; ///< The image is not read again by this process, see @ref MAX_TRANSIENT_READS.
        };

        /// The key is `source:reference@configDigest`, see @ref imageKey. The source type is part of it, so that a
        /// registry reference that reads `docker/getting-started` is not taken for an image of the Docker engine.
        std::map<std::string, Entry> entries;

        /// @brief True when a read of the image under @p key was given up by this process.
        bool givenUp(const std::string& key) const
        {
            const auto entry {entries.find(key)};
            return entry != entries.end() && entry->second.givenUp;
        }

        /// @brief True when an image whose key starts with @p prefix was given up by this process.
        bool anyGivenUpWithPrefix(const std::string& prefix) const
        {
            const auto first {entries.lower_bound(prefix)};
            return first != entries.end() && first->first.rfind(prefix, 0) == 0 && first->second.givenUp;
        }

        static std::string imageKey(const std::string& source, const std::string& reference, const std::string& configDigest)
        {
            return source + ":" + reference + "@" + configDigest;
        }
    };

    /// @brief What a reader hands the composer besides the layers.
    struct PackageReadControls
    {
        ReadFailures* failures {nullptr}; ///< Not owned. Null: failures are never counted.
        /// Not owned. Tests give a read of their own (a stand-in child, a short deadline); null is the real read.
        const PackageDb::BerkeleyDbOptions* options {nullptr};
        /// The source type the images read are counted under, when a reader reads on behalf of another (the
        /// engine reader gives its images to an archive reader). Empty: the type of the reader itself.
        std::string source {};
    };

    /// @brief Which image a read of its packages is for, so its failures can be counted.
    struct ReadAttempt
    {
        std::string source;       ///< Source type of the reference (`archive`, `ref`, `local`).
        std::string reference;    ///< As the reference is stored.
        std::string configDigest; ///< Of the image read. Another digest is another image.
        PackageReadControls controls;
    };

    /// @brief What one layer contributes to the package databases of an image.
    ///
    /// Only the tracked database paths are kept: the image filesystem is never
    /// reconstructed, so an image with thousands of files costs the size of its package
    /// databases and nothing else.
    struct LayerSnapshot
    {
        std::map<std::string, std::string> databases; ///< Tracked database path to its content in this layer.
        std::map<std::string, std::string> osReleases; ///< `os-release` path to its content in this layer.
        /// `os-release` paths this layer provides as any kind of entry. A symlink, a hardlink
        /// or a file too large to read is no content, but it still replaces what the earlier
        /// layers held at that path.
        std::set<std::string> osReleasesReplaced;
        /// Databases of this layer that were dropped for being larger than supported. A directory
        /// database (`status.d`) is named by its directory, and nothing of it is in `databases`.
        std::set<std::string> oversizedDatabases;
        std::set<std::string> whiteouts;              ///< Paths this layer deletes.
        std::set<std::string> opaqueDirectories;      ///< Directories whose earlier content this layer hides.
        /// Path of a recognized-but-unimplemented database to its format, seen in this
        /// layer. Kept by path, like `databases`, so a later whiteout or opaque marker can
        /// retract it the same way it retracts a tracked database.
        std::map<std::string, std::string> unsupportedFormats;
        bool complete {true};                         ///< False when the layer was truncated or malformed.
    };

    /// @brief Read one layer and keep only what the package inventory needs.
    /// @param layer Tar stream of the layer, compressed or not.
    /// @return The layer contribution. `complete` is false for a malformed layer, and
    ///         whatever was read before the failure is still returned.
    LayerSnapshot readLayerSnapshot(IByteStream& layer);

    /// @brief Composes the layers of one image into the final state of its package
    /// databases and of its `os-release` file.
    ///
    /// Layers are applied in manifest order, so a database present in several layers is
    /// read from the last one that provides it, and one deleted in a later layer is not
    /// reported at all. Within a layer the OverlayFS rules are applied in the order the
    /// filesystem applies them: opaque directories hide the accumulated content first,
    /// then the per-file deletion markers, then the files the layer itself carries.
    class LayerComposer
    {
        public:
            /// @brief Apply the next layer. Must be called in manifest order.
            void apply(const LayerSnapshot& snapshot);

            /// @brief Final content of every tracked database that survived composition.
            const std::map<std::string, std::string>& databases() const;

            /// @brief Recognized but unimplemented formats still present after composition.
            std::set<std::string> unsupportedFormats() const;

            /// @brief Parse every composed database into package records.
            /// @param image Where the image comes from, named in the warning when a database cannot be read.
            /// @param stop Polled while a database is read in a child process; true cancels the read.
            /// @param transientFailure Set when a database could not be read for a reason that says nothing
            ///        about it (cancelled, timed out, no process or file), so the packages returned are not the
            ///        image's and must not be stored as if they were. Left false otherwise.
            /// @param attempt The image being read. With it, a database that cannot be read for a transient reason
            ///        @ref MAX_TRANSIENT_READS reads in a row is given up: recorded as unreadable when it is the
            ///        deadline that was missed, and otherwise left alone by this process, with the read still
            ///        reported through @p transientFailure so that nothing is stored for the image.
            /// @param unreadable Set when a database of the image was found and could not be read, whatever
            ///        the reason, so the caller does not say the image has none.
            std::vector<ImagePackageRecord> packages(const std::string& image = {},
                                                     const std::atomic<bool>* stop = nullptr,
                                                     bool* transientFailure = nullptr,
                                                     const ReadAttempt* attempt = nullptr,
                                                     bool* unreadable = nullptr) const;

            /// @brief The operating system the composed image states in its `os-release`.
            ///
            /// `etc/os-release` is preferred and `usr/lib/os-release` is the fallback, as
            /// os-release(5) says, after the whiteouts of every layer were applied. Empty
            /// when the image carries neither, which is an image with no operating system.
            ImageOperatingSystem operatingSystem() const;

        private:
            void eraseOversizedUnder(const std::string& directory);

            std::map<std::string, std::string> m_databases;
            std::map<std::string, std::string> m_osReleases; ///< Path to content, tracked like m_databases.
            std::map<std::string, std::string> m_unsupportedFormats; ///< Path to format, tracked like m_databases.
            std::set<std::string> m_oversizedDatabases; ///< Dropped for their size, tracked like m_databases.
    };
} // namespace containerimages

#endif // _LAYER_COMPOSER_HPP
