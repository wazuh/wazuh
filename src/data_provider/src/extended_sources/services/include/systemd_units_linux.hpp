/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <istream>
#include <memory>
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

/// @brief Host-dependent settings of SystemdUnitsProvider, replaceable in tests.
struct SystemdUnitsSettings
{
    /// @brief Unit directories searched for drop-ins, highest priority first.
    std::vector<std::string> unitSearchPaths;

    /// @brief Directory that exists only when systemd is the running init, as sd_booted() checks.
    std::string runtimeDirectory;

    /// @brief Consecutive failed collections. Shared because a provider is created per scan.
    std::shared_ptr<std::atomic<unsigned int>> consecutiveFailures;
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

        /// @brief Constructor with host-dependent settings, for tests.
        /// @param dbusWrapper Pointer to the D-Bus wrapper for system operations.
        /// @param settings Unit directories, systemd runtime directory and failure counter.
        SystemdUnitsProvider(std::shared_ptr<IDBusWrapper> dbusWrapper, SystemdUnitsSettings settings);

        /// @brief Default constructor.
        SystemdUnitsProvider();

        /// @brief Collects systemd units information.
        /// @return A JSON object containing the collected systemd units information.
        /// @throws std::runtime_error if systemd is running but its units or unit files could not
        /// be listed, so the caller keeps its previous inventory instead of reporting the missing
        /// units as deleted. After MAX_CONSECUTIVE_FAILURES failed collections in a row it returns
        /// what could be listed instead (the loaded units, or none), so a persistent failure does
        /// not freeze the inventory; the last failure that throws says so.
        nlohmann::json collect();

        /// @brief Failed collections in a row that throw before collect() reports what it can.
        static constexpr unsigned int MAX_CONSECUTIVE_FAILURES {3};

        /// @brief Reads [Unit] Description and SourcePath, and [Service] User, from a unit file.
        /// @param input Stream with the unit file contents.
        /// @param values Values from previously parsed files (the fragment before its drop-ins).
        /// @param expand Expands the specifiers of a value in place; returning false ignores the
        /// assignment, as systemd does when it cannot resolve them. Empty: values kept literal.
        /// @return The values updated with this file; the last assignment wins.
        static UnitFileValues parseUnitFile(std::istream& input,
                                            UnitFileValues values = {},
                                            const std::function<bool(std::string&)>& expand = {});

        /// @brief Unit file state systemd reports for an instance enabled through a link.
        /// @param linkPath Path of the link in a .wants, .requires or .upholds directory.
        /// @return "enabled" under /etc, "enabled-runtime" under /run, "static" elsewhere (a
        /// link shipped in a vendor directory).
        static std::string instanceLinkState(const std::string& linkPath);

        /// @brief Builds the D-Bus object path systemd uses for a unit name.
        /// @param unitName Full unit name, e.g. "cron.service".
        /// @return The object path, e.g. "/org/freedesktop/systemd1/unit/cron_2eservice".
        static std::string unitObjectPath(const std::string& unitName);

    private:
        /// @brief Pointer to the D-Bus wrapper for system operations.
        std::shared_ptr<IDBusWrapper> m_dbusWrapper;

        /// @brief Host-dependent settings.
        SystemdUnitsSettings m_settings;

        /// @brief How far a collection got.
        enum class CollectionStatus
        {
            Complete,   ///< Loaded units and unit files listed.
            LoadedOnly, ///< Loaded units listed, unit files not.
            Failed      ///< Nothing listed.
        };

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
        /// @return How much could be listed.
        CollectionStatus getSystemdUnits(std::vector<SystemdUnit>& output);

        /// @brief Reads the systemd major version from the manager, e.g. 255 for "255.4-1ubuntu8".
        /// @param conn Open system bus connection.
        /// @return The version, or 0 if it cannot be read.
        unsigned int readSystemdVersion(DBusConnection* conn);

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
