/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
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

#include <map>
#include <set>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief What one layer contributes to the package databases of an image.
    ///
    /// Only the tracked database paths are kept: the image filesystem is never
    /// reconstructed, so an image with thousands of files costs the size of its package
    /// databases and nothing else.
    struct LayerSnapshot
    {
        std::map<std::string, std::string> databases; ///< Tracked database path to its content in this layer.
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
    /// databases.
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
            std::vector<ImagePackageRecord> packages() const;

        private:
            std::map<std::string, std::string> m_databases;
            std::map<std::string, std::string> m_unsupportedFormats; ///< Path to format, tracked like m_databases.
    };
} // namespace containerimages

#endif // _LAYER_COMPOSER_HPP
