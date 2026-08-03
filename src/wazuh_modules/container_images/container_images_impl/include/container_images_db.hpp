/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_DB_HPP
#define _CONTAINER_IMAGES_DB_HPP

#include "idbsync.hpp"
#include "image_inventory_types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Names of the two DBSync tables (reference-based model).
    constexpr auto REFERENCES_TABLE {"dbsync_container_image_references"};
    constexpr auto PACKAGES_TABLE {"dbsync_container_image_packages"};

    /// @brief Delta reported for a single row, with everything already extracted.
    ///
    /// The row JSON is unwrapped, the document id computed and the payload serialized inside
    /// the database layer (the translation unit that talks to DBSync), so no `nlohmann::json`
    /// crosses into the caller. This avoids any cross-module representation mismatch and keeps
    /// the row-shape knowledge in one place.
    ///
    /// @param operation One of INSERTED / MODIFIED / DELETED.
    /// @param table The table the row belongs to.
    /// @param id Stable document id (sha1 over the table and the primary-key fields).
    /// @param data Serialized row payload (the current row state).
    /// @param version DBSync document version.
    using DeltaCallback = std::function<void(ReturnTypeCallback operation,
                                             const std::string& table,
                                             const std::string& id,
                                             const std::string& data,
                                             std::uint64_t version)>;

    /// @brief Owns the local SQLite database for the container image inventory.
    ///
    /// Mirrors the storage approach used by SCA and Syscollector: a DBSync instance with
    /// inline CREATE TABLE statements, written through transactions that emit
    /// create/modify/delete deltas. Holds the two reference-based tables.
    class ContainerImagesDB final
    {
        public:
            /// @param dbPath Path to the SQLite database file.
            /// @param dbSync Optional DBSync instance (overridable for tests).
            explicit ContainerImagesDB(const std::string& dbPath, std::shared_ptr<IDBSync> dbSync = nullptr);

            /// @brief Synchronize the set of discovered references into the references table.
            ///        Rows not present in @p references are reported as DELETED.
            void syncReferences(const std::vector<ImageReferenceRecord>& references, const DeltaCallback& onDelta);

            /// @brief Synchronize the packages found across all discovered references.
            ///
            /// All package rows from every reference are synced in a single transaction so
            /// the whole packages table is reconciled at once: a package that disappears
            /// from any reference is reported as DELETED. (DBSync transaction deletion is
            /// table-scoped, so packages must be synced as one set, not per reference.)
            void syncPackages(const std::vector<ImageReferenceRecord>& references, const DeltaCallback& onDelta);

            /// @brief The CREATE TABLE statements for both tables (exposed for tests/inspection).
            static std::string getCreateStatement();

            /// @brief The ordered schema migrations handed to DBSync.
            ///
            /// DBSync records the schema version in `PRAGMA user_version` and treats the
            /// current version as `size() + 1`, replaying the pending entries when an existing
            /// database is behind. Empty while the schema is on its first revision.
            static const std::vector<std::string>& getUpgradeStatements();

            /// @brief Remove every inventory row from both tables, keeping the schema.
            ///
            /// For module disable / uninstall, so the inventory this module owns does not
            /// survive as stale state.
            void dropTables();

        private:
            std::shared_ptr<IDBSync> m_dbSync;
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_DB_HPP
