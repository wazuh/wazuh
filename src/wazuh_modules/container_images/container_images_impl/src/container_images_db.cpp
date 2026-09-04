/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_images_db.hpp"
#include "ci_logging_helper.hpp"

#include "dbsync.hpp"
#include "hashHelper.h"
#include "stringHelper.h"

#include <cstdint>
#include <string>
#include <vector>

namespace
{
    constexpr unsigned int DBSYNC_QUEUE_SIZE {4096};

    // Reference table: PK is (reference_type, reference_value). The config digest is a
    // change signal and is carried as a column, not as part of the identity.
    constexpr auto REFERENCES_SQL
    {
        R"(CREATE TABLE IF NOT EXISTS dbsync_container_image_references (
        reference_type TEXT,
        reference_value TEXT,
        image_config_digest TEXT,
        manifest_digest TEXT,
        image_name TEXT,
        tag TEXT,
        tags TEXT,
        platform_os TEXT,
        platform_architecture TEXT,
        platform_variant TEXT,
        platform_os_version TEXT,
        checksum TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        sync INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (reference_type, reference_value)) WITHOUT ROWID;)"
    };

    // Packages table: PK is the owning reference plus the package identity fields.
    constexpr auto PACKAGES_SQL
    {
        R"(CREATE TABLE IF NOT EXISTS dbsync_container_image_packages (
        reference_type TEXT,
        reference_value TEXT,
        name TEXT,
        version_ TEXT,
        architecture TEXT,
        type TEXT,
        vendor TEXT,
        installed TEXT,
        path TEXT,
        category TEXT,
        description TEXT,
        size BIGINT,
        priority TEXT,
        multiarch TEXT,
        source TEXT,
        package_db_path TEXT,
        checksum TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        sync INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (reference_type, reference_value, name, version_, architecture, type)) WITHOUT ROWID;)"
    };

    // Schema migrations, applied in order to an existing database whose recorded version is
    // behind the current one. DBSync tracks the version in `PRAGMA user_version` and treats
    // the current version as `upgradeStatements.size() + 1`, so appending one statement here
    // is what bumps the schema. The list is empty while the schema is on its first revision.
    //
    // Rule for any future schema change: append the migrating statement, never edit or
    // reorder the existing entries, or already-deployed agents will skip a step. The CREATE
    // statements above must be updated in the same change: a database with no recorded
    // version is built from them, while an existing one is migrated from this list, so
    // updating only one of the two makes fresh and upgraded agents diverge.
    const std::vector<std::string> UPGRADE_STATEMENTS {};

    // Per-row checksum, stored like every other inventory table keeps one. DBSync compares
    // every non-ignored column to detect a modification, so the checksum is one more column
    // and excluding a field from it does not hide that field from change detection.
    std::string rowChecksum(const nlohmann::json& row)
    {
        const auto content {row.dump()};
        Utils::HashData hash;
        hash.update(content.c_str(), content.size());
        return Utils::asciiToHex(hash.hash());
    }

    /// @brief A string column of a selected row, empty when absent or null.
    std::string stringOf(const nlohmann::json& row, const char* field)
    {
        const auto value {row.find(field)};
        return value != row.end() && value->is_string() ? value->get<std::string>() : std::string {};
    }

    nlohmann::json referenceRow(const containerimages::ImageReferenceRecord& reference)
    {
        nlohmann::json row;
        row["reference_type"] = reference.source.sourceType;
        row["reference_value"] = reference.source.location;
        row["image_config_digest"] = reference.configDigest;
        row["manifest_digest"] = reference.manifestDigest;
        row["image_name"] = reference.tag; // display name; refined when real readers land
        row["tag"] = reference.tag;
        // Every tag the image answers to, serialized as a JSON array. One reference can be
        // reachable under several tags; the single `tag` above stays the display name.
        row["tags"] = nlohmann::json(reference.tags).dump();
        row["platform_os"] = reference.os;
        row["platform_architecture"] = reference.architecture;
        row["platform_variant"] = reference.variant;
        row["platform_os_version"] = reference.osVersion;
        row["checksum"] = rowChecksum(row);
        return row;
    }

    nlohmann::json packageRow(const containerimages::ImageReferenceRecord& reference,
                              const containerimages::ImagePackageRecord& package)
    {
        nlohmann::json row;
        row["reference_type"] = reference.source.sourceType;
        row["reference_value"] = reference.source.location;
        row["name"] = package.name;
        row["version_"] = package.version;
        row["architecture"] = package.architecture;
        row["type"] = package.type;
        row["vendor"] = package.vendor;
        row["installed"] = package.installed;
        row["path"] = package.path;
        row["category"] = package.category;
        row["description"] = package.description;
        row["size"] = package.size;
        row["priority"] = package.priority;
        row["multiarch"] = package.multiarch;
        row["source"] = package.source;
        row["package_db_path"] = package.packageDbPath;
        row["checksum"] = rowChecksum(row);
        return row;
    }

    // DBSync delivers the current row as a plain object for INSERTED/DELETED, and as
    // {"new": ..., "old": ...} for MODIFIED. Return the current row object.
    //
    // The object is accessed the same way Syscollector consumes its callback (direct field
    // access on the DBSync-provided json). Re-parsing or type-introspecting it is avoided on
    // purpose: DBSync exports its own nlohmann template instantiation, which interposes at
    // link time and makes a round-trip (dump()+parse()) misreport the value's type.
    const nlohmann::json& unwrapRow(ReturnTypeCallback operation, const nlohmann::json& data)
    {
        if (operation == MODIFIED && data.contains("new"))
        {
            return data["new"];
        }

        return data;
    }

    // Stable document id: sha1 over the table name and the row's primary-key fields. The
    // reference fields are always part of the key (the reference owns the inventory).
    std::string documentId(const std::string& table, const nlohmann::json& row)
    {
        std::vector<std::string> idFields;

        if (table == containerimages::PACKAGES_TABLE)
        {
            idFields = {"reference_type", "reference_value", "name", "version_", "architecture", "type"};
        }
        else
        {
            idFields = {"reference_type", "reference_value"};
        }

        Utils::HashData hash;
        hash.update(table.c_str(), table.size());

        for (const auto& field : idFields)
        {
            if (row.contains(field) && row[field].is_string())
            {
                const auto value {row[field].get<std::string>()};
                hash.update(value.c_str(), value.size());
            }
        }

        return Utils::asciiToHex(hash.hash());
    }

    // DBSync writes the version as a signed integer on every path (insert, modify and the
    // rows read back for deletion), so the guard must accept any number, not only an
    // unsigned one, or every delta would report version 0.
    std::uint64_t rowVersion(const nlohmann::json& row)
    {
        return (row.contains("version") && row["version"].is_number())
               ? row["version"].get<std::uint64_t>()
               : 0ULL;
    }

    // Extract everything from the DBSync row here and hand the caller only plain values.
    void emitDelta(const containerimages::DeltaCallback& onDelta,
                   ReturnTypeCallback result,
                   const std::string& table,
                   const nlohmann::json& data)
    {
        if (result != INSERTED && result != MODIFIED && result != DELETED)
        {
            // DBSync reports a row it could not write through this same callback. Dropping it
            // silently would let a scan report success while part of the inventory was lost.
            LoggingHelper::getInstance().log(LOG_ERROR, "Row not stored in " + table + ": " + data.dump());
            return;
        }

        const auto& row {unwrapRow(result, data)};
        onDelta(result, table, documentId(table, row), row.dump(), rowVersion(row));
    }
} // namespace

namespace containerimages
{
    ContainerImagesDB::ContainerImagesDB(const std::string& dbPath, std::shared_ptr<IDBSync> dbSync)
        : m_dbSync(dbSync ? std::move(dbSync)
                   : std::make_shared<DBSync>(HostType::AGENT,
                                              DbEngineType::SQLITE3,
                                              dbPath,
                                              getCreateStatement(),
                                              DbManagement::PERSISTENT,
                                              UPGRADE_STATEMENTS))
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Container images database initialized at " + dbPath + ".");
    }

    std::string ContainerImagesDB::getCreateStatement()
    {
        return std::string {REFERENCES_SQL} + "\n" + std::string {PACKAGES_SQL};
    }

    const std::vector<std::string>& ContainerImagesDB::getUpgradeStatements()
    {
        return UPGRADE_STATEMENTS;
    }

    void ContainerImagesDB::dropTables()
    {
        // Meant for the module disable / uninstall path, so the inventory this module owns
        // does not survive as stale state. That path is a follow-up issue and does not call
        // this yet. Deleting the rows (rather than the tables) keeps the
        // schema and its recorded version intact, so a later re-enable reuses the same
        // database instead of triggering a recreate.
        for (const auto& table : {REFERENCES_TABLE, PACKAGES_TABLE})
        {
            // DBSync rejects an empty row filter, so an always-true condition is what
            // expresses "every row" here.
            auto query = DeleteQuery::builder().table(table).rowFilter("1=1").build();
            m_dbSync->deleteRows(query.query());
        }

        LoggingHelper::getInstance().log(LOG_DEBUG, "Container images inventory cleared.");
    }

    std::optional<ImageReferenceRecord> ContainerImagesDB::loadStored(const std::string& sourceType,
                                                                      const std::string& location)
    {
        // The values come from the module's own configuration, not from an image, but they
        // still reach a SQL string here, so anything that could end the quoted literal is
        // refused rather than escaped.
        if (sourceType.find('\'') != std::string::npos || location.find('\'') != std::string::npos)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Refusing to read back a source whose name is not quotable.");
            return std::nullopt;
        }

        const auto filter {"WHERE reference_type = '" + sourceType + "' AND reference_value = '" + location + "'"};

        ImageReferenceRecord record;
        bool found {false};

        const auto referenceCallback = [&record, &found](ReturnTypeCallback, const nlohmann::json & row)
        {
            found = true;
            record.source = {stringOf(row, "reference_type"), stringOf(row, "reference_value")};
            record.configDigest = stringOf(row, "image_config_digest");
            record.manifestDigest = stringOf(row, "manifest_digest");
            record.tag = stringOf(row, "tag");
            record.os = stringOf(row, "platform_os");
            record.architecture = stringOf(row, "platform_architecture");
            record.variant = stringOf(row, "platform_variant");
            record.osVersion = stringOf(row, "platform_os_version");

            // Copy-initialized on purpose. Brace-initializing a json from a json selects its
            // initializer-list constructor, and a two-element array whose first element is a
            // string is then read as a key and a value: ["1.4","latest"] became the object
            // {"1.4":"latest"}, is_array() was false, and every stored tag was silently lost.
            const auto tags = nlohmann::json::parse(stringOf(row, "tags"), nullptr, false);

            if (tags.is_array())
            {
                for (const auto& tag : tags)
                {
                    if (tag.is_string())
                    {
                        record.tags.push_back(tag.get<std::string>());
                    }
                }
            }
        };

        auto referenceQuery = SelectQuery::builder()
                              .table(REFERENCES_TABLE)
                              .columnList({"reference_type", "reference_value", "image_config_digest",
                                           "manifest_digest", "image_name", "tag", "tags", "platform_os",
                                           "platform_architecture", "platform_variant", "platform_os_version"})
                              .rowFilter(filter)
                              .build();
        m_dbSync->selectRows(referenceQuery.query(), referenceCallback);

        if (!found)
        {
            return std::nullopt;
        }

        const auto packageCallback = [&record](ReturnTypeCallback, const nlohmann::json & row)
        {
            ImagePackageRecord package;
            package.name = stringOf(row, "name");
            package.version = stringOf(row, "version_");
            package.architecture = stringOf(row, "architecture");
            package.type = stringOf(row, "type");
            package.vendor = stringOf(row, "vendor");
            package.installed = stringOf(row, "installed");
            package.path = stringOf(row, "path");
            package.category = stringOf(row, "category");
            package.description = stringOf(row, "description");
            package.size = row.contains("size") && row.at("size").is_number() ? row.at("size").get<std::int64_t>() : 0;
            package.priority = stringOf(row, "priority");
            package.multiarch = stringOf(row, "multiarch");
            package.source = stringOf(row, "source");
            package.packageDbPath = stringOf(row, "package_db_path");
            record.packages.push_back(std::move(package));
        };

        auto packageQuery = SelectQuery::builder()
                            .table(PACKAGES_TABLE)
                            .columnList({"name", "version_", "architecture", "type", "vendor", "installed", "path",
                                         "category", "description", "size", "priority", "multiarch", "source",
                                         "package_db_path"})
                            .rowFilter(filter)
                            .build();
        m_dbSync->selectRows(packageQuery.query(), packageCallback);

        return record;
    }

    void ContainerImagesDB::syncReferences(const std::vector<ImageReferenceRecord>& references,
                                           const DeltaCallback& onDelta)
    {
        nlohmann::json rows = nlohmann::json::array();

        for (const auto& reference : references)
        {
            rows.push_back(referenceRow(reference));
        }

        const auto callback = [&onDelta](ReturnTypeCallback result, const nlohmann::json & data)
        {
            emitDelta(onDelta, result, REFERENCES_TABLE, data);
        };

        DBSyncTxn txn {m_dbSync->handle(), nlohmann::json {REFERENCES_TABLE}, 0, DBSYNC_QUEUE_SIZE, callback};

        nlohmann::json input;
        input["table"] = REFERENCES_TABLE;
        input["data"] = rows;
        input["options"]["return_old_data"] = true;

        txn.syncTxnRow(input);
        txn.getDeletedRows(callback);
    }

    void ContainerImagesDB::syncPackages(const std::vector<ImageReferenceRecord>& references,
                                         const DeltaCallback& onDelta)
    {
        nlohmann::json rows = nlohmann::json::array();

        for (const auto& reference : references)
        {
            for (const auto& package : reference.packages)
            {
                rows.push_back(packageRow(reference, package));
            }
        }

        const auto callback = [&onDelta](ReturnTypeCallback result, const nlohmann::json & data)
        {
            emitDelta(onDelta, result, PACKAGES_TABLE, data);
        };

        DBSyncTxn txn {m_dbSync->handle(), nlohmann::json {PACKAGES_TABLE}, 0, DBSYNC_QUEUE_SIZE, callback};

        nlohmann::json input;
        input["table"] = PACKAGES_TABLE;
        input["data"] = rows;
        input["options"]["return_old_data"] = true;

        txn.syncTxnRow(input);
        txn.getDeletedRows(callback);
    }
} // namespace containerimages
