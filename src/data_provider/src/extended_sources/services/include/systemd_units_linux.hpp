/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>
#include <vector>
#include "isdbus_wrapper.hpp"
#include "isystem_wrapper.hpp"
#include "json.hpp"

/// @brief Class to collect systemd units information from the systemd service manager.
/// This class uses D-Bus to query systemd for unit information and formats it into a
/// JSON object for easy consumption.
class SystemdUnitsProvider
{
    public:
        /// @brief Constructor that initializes the SystemdUnitsProvider with D-Bus and system wrappers.
        /// @param dbusWrapper Pointer to the D-Bus wrapper for system operations.
        /// @param systemWrapper Pointer to the system wrapper for system calls.
        explicit SystemdUnitsProvider(std::shared_ptr<ISDBusWrapper> dbusWrapper,
                                      std::shared_ptr<ISystemWrapper> systemWrapper);

        /// @brief Default constructor.
        SystemdUnitsProvider();

        /// @brief Collects systemd units information.
        /// @return A JSON object containing the collected systemd units information.
        nlohmann::json collect();

    private:
        /// @brief Pointer to the D-Bus wrapper for system operations.
        std::shared_ptr<ISDBusWrapper> m_dbusWrapper;

        /// @brief Pointer to the system wrapper for system calls.
        std::shared_ptr<ISystemWrapper> m_systemWrapper;

        /// @brief Structure to describe a property query for D-Bus.
        struct PropertyQueryDesc
        {
            std::string propertyName;
            std::string columnName;
            std::string interface;
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
        /// @return True if the units were successfully retrieved, false otherwise.
        bool getSystemdUnits(std::vector<SystemdUnit>& output);
};
