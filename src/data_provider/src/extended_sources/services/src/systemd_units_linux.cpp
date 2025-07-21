/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "sdbus_wrapper.hpp"
#include "system_wrapper.hpp"
#include "systemd_units_linux.hpp"

SystemdUnitsProvider::SystemdUnitsProvider(std::shared_ptr<ISDBusWrapper> dbusWrapper,
                                           std::shared_ptr<ISystemWrapper> systemWrapper)
    : m_dbusWrapper(std::move(dbusWrapper))
    , m_systemWrapper(std::move(systemWrapper))
{
}

SystemdUnitsProvider::SystemdUnitsProvider()
    : m_dbusWrapper(std::make_shared<SDBusWrapper>())
    , m_systemWrapper(std::make_shared<SystemWrapper>())
{
}

nlohmann::json SystemdUnitsProvider::collect()
{
    nlohmann::json result = nlohmann::json::array();
    std::vector<SystemdUnit> units;

    if (!getSystemdUnits(units))
    {
        std::cerr << "Error getting systemd units" << std::endl;
        return result;
    }

    for (const auto& unit : units)
    {
        nlohmann::json row;
        row["id"] = unit.id;
        row["description"] = unit.description;
        row["loadState"] = unit.loadState;
        row["activeState"] = unit.activeState;
        row["subState"] = unit.subState;
        row["following"] = unit.following;
        row["objectPath"] = unit.objectPath;
        row["jobId"] = unit.jobId;
        row["jobType"] = unit.jobType;
        row["jobPath"] = unit.jobPath;
        row["fragmentPath"] = unit.fragmentPath;
        row["sourcePath"] = unit.sourcePath;
        row["user"] = unit.user;
        row["unitFileState"] = unit.unitFileState;

        result.push_back(std::move(row));
    }

    return result;
}

bool SystemdUnitsProvider::getSystemdUnits(std::vector<SystemdUnit>& output)
{
    sd_bus* bus = nullptr;
    int ret = m_dbusWrapper->sd_bus_open_system(&bus);

    if (ret < 0)
    {
        std::cerr << "Failed to connect to system bus: " << m_systemWrapper->strerror(-ret) << std::endl;
        return false;
    }

    sd_bus_message* reply = nullptr;
    ret = m_dbusWrapper->sd_bus_call_method(
              bus,
              "org.freedesktop.systemd1",             // service
              "/org/freedesktop/systemd1",            // path
              "org.freedesktop.systemd1.Manager",     // interface
              "ListUnits",                            // method
              nullptr,                                // input signature
              &reply,                                 // reply
              "");                                    // no input parameters

    if (ret < 0)
    {
        std::cerr << "Failed to call ListUnits: " << m_systemWrapper->strerror(-ret) << std::endl;
        m_dbusWrapper->sd_bus_unref(bus);
        return false;
    }

    ret = m_dbusWrapper->sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");

    if (ret < 0)
    {
        std::cerr << "Failed to enter array: " << m_systemWrapper->strerror(-ret) << std::endl;
        m_dbusWrapper->sd_bus_message_unref(reply);
        m_dbusWrapper->sd_bus_unref(bus);
        return false;
    }

    while ((ret = m_dbusWrapper->sd_bus_message_enter_container(reply, SD_BUS_TYPE_STRUCT, "ssssssouso")) > 0)
    {
        SystemdUnit unit;

        const char* id;
        const char* description;
        const char* loadState;
        const char* activeState;
        const char* subState;
        const char* following;
        const char* path;
        uint32_t jobId;
        const char* jobType;
        const char* jobPath;

        ret = m_dbusWrapper->sd_bus_message_read(
                  reply, "ssssssouso",
                  &id,
                  &description,
                  &loadState,
                  &activeState,
                  &subState,
                  &following,
                  &path,
                  &jobId,
                  &jobType,
                  &jobPath);

        if (ret < 0)
        {
            std::cerr << "Failed to read unit struct: " << m_systemWrapper->strerror(-ret) << std::endl;
            break;
        }

        unit.id = id;
        unit.description = description;
        unit.loadState = loadState;
        unit.activeState = activeState;
        unit.subState = subState;
        unit.following = following;
        unit.objectPath = path;
        unit.jobId = jobId;
        unit.jobType = jobType;
        unit.jobPath = jobPath;

        // Reading additional properties via D-Bus
        for (const auto& query : m_propertyQueryList)
        {
            char* propValueCstring = nullptr;
            ret = m_dbusWrapper->sd_bus_get_property_string(
                      bus,
                      "org.freedesktop.systemd1",
                      unit.objectPath.c_str(),
                      query.interface.c_str(),
                      query.propertyName.c_str(),
                      nullptr,
                      &propValueCstring);

            if (ret < 0 && query.propertyName != "User")
            {
                std::cerr << "Error reading property "
                          << query.propertyName << " from "
                          << unit.objectPath << ": " << m_systemWrapper->strerror(-ret) << std::endl;
            }

            std::string propValue = "";

            if (ret >= 0)
            {
                propValue = propValueCstring;
                free(propValueCstring);
            }

            if (query.columnName == "fragmentPath")
            {
                unit.fragmentPath = propValue;
            }
            else if (query.columnName == "sourcePath")
            {
                unit.sourcePath = propValue;
            }
            else if (query.columnName == "user")
            {
                unit.user = propValue;
            }
            else if (query.columnName == "unitFileState")
            {
                unit.unitFileState = propValue;
            }
        }

        output.emplace_back(std::move(unit));
        m_dbusWrapper->sd_bus_message_exit_container(reply);
    }

    m_dbusWrapper->sd_bus_message_exit_container(reply);
    m_dbusWrapper->sd_bus_message_unref(reply);
    m_dbusWrapper->sd_bus_unref(bus);

    return true;
}
