/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <istream>
#include <string>
#include <unordered_set>
#include <vector>
#include "idbus_wrapper.hpp"
#include "json.hpp"

/// @brief Structure to hold information about a systemd unit.
struct SystemdUnit
{
    std::string id;
    std::string description;
    std::string loadState;
    std::string activeState;
    std::string subState;
    std::string following;
    std::string objectPath;
    uint32_t jobId;
    std::string jobType;
    std::string jobPath;

    // Extra properties
    std::string fragmentPath;
    std::string sourcePath;
    std::string user;
    std::string unitFileState;
};

/// @brief Values read from a unit file for units systemd has not loaded.
struct UnitFileValues
{
    std::string description;
    std::string user;
    std::string sourcePath;
};

/// @brief Structure to describe a property query for D-Bus.
struct PropertyQueryDesc
{
    std::string propertyName;
    std::string columnName;
    std::string interface;
};

/// @brief Class to collect systemd units information from the systemd service manager.
/// This class uses D-Bus to query systemd for unit information and formats it into a
/// JSON object for easy consumption.
class SystemdUnitsProvider
{
    public:
        /// @brief Constructor that initializes the SystemdUnitsProvider with D-Bus wrapper.
        /// @param dbusWrapper Pointer to the D-Bus wrapper for system operations.
        explicit SystemdUnitsProvider(std::shared_ptr<IDBusWrapper> dbusWrapper);

        /// @brief Constructor with the directories searched for drop-ins, for tests.
        /// @param dbusWrapper Pointer to the D-Bus wrapper for system operations.
        /// @param unitSearchPaths Unit directories, highest priority first.
        SystemdUnitsProvider(std::shared_ptr<IDBusWrapper> dbusWrapper, std::vector<std::string> unitSearchPaths);

        /// @brief Default constructor.
        SystemdUnitsProvider();

        /// @brief Collects systemd units information.
        /// @return A JSON object containing the collected systemd units information.
        /// @throws std::runtime_error if the units were listed but the unit files could not be,
        /// so the caller keeps its previous inventory instead of dropping the unloaded units.
        nlohmann::json collect();

        /// @brief Reads [Unit] Description and SourcePath, and [Service] User, from a unit file.
        /// @param input Stream with the unit file contents.
        /// @param values Values from previously parsed files (the fragment before its drop-ins).
        /// @return The values updated with this file; the last assignment wins.
        static UnitFileValues parseUnitFile(std::istream& input, UnitFileValues values = {});

        /// @brief Builds the D-Bus object path systemd uses for a unit name.
        /// @param unitName Full unit name, e.g. "cron.service".
        /// @return The object path, e.g. "/org/freedesktop/systemd1/unit/cron_2eservice".
        static std::string unitObjectPath(const std::string& unitName);

    private:
        /// @brief Pointer to the D-Bus wrapper for system operations.
        std::shared_ptr<IDBusWrapper> m_dbusWrapper;

        /// @brief Unit directories searched for drop-ins, highest priority first.
        std::vector<std::string> m_unitSearchPaths;

        /// @brief List of property queries to be executed on D-Bus.
        /// Each entry specifies the property name, the column name to use in the output,
        /// and the D-Bus interface to query.
        const std::vector<PropertyQueryDesc> m_propertyQueryList =
        {
            {"FragmentPath", "fragment_path", "org.freedesktop.systemd1.Unit"},
            {"SourcePath", "source_path", "org.freedesktop.systemd1.Unit"},
            {"User", "user", "org.freedesktop.systemd1.Service"},
            {"UnitFileState", "unit_file_state", "org.freedesktop.systemd1.Unit"},
        };

        /// @brief Retrieves systemd units from the system using D-Bus.
        /// @param output A vector to store the retrieved systemd units.
        /// @return True if the units were successfully retrieved, false otherwise.
        bool getSystemdUnits(std::vector<SystemdUnit>& output);

        /// @brief Appends the service unit files systemd has not loaded.
        /// ListUnits only returns loaded units, so without this a stopped unit that systemd
        /// unloads would vanish from the inventory although its unit file is still installed.
        /// @param conn Open system bus connection.
        /// @param loadedIds Ids (without ".service") already reported from ListUnits.
        /// @param output A vector to append the unloaded units to.
        /// @return False if the unit files could not be listed.
        bool appendUnloadedUnitFiles(DBusConnection* conn,
                                     const std::unordered_set<std::string>& loadedIds,
                                     std::vector<SystemdUnit>& output);
};
