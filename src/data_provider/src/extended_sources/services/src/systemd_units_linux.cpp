/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "dbus_wrapper.hpp"
#include "systemd_units_linux.hpp"
#include "stringHelper.h"

SystemdUnitsProvider::SystemdUnitsProvider(std::shared_ptr<IDBusWrapper> dbusWrapper)
    : m_dbusWrapper(std::move(dbusWrapper))
{
}

SystemdUnitsProvider::SystemdUnitsProvider()
    : m_dbusWrapper(std::make_shared<DBusWrapper>())
{
}

nlohmann::json SystemdUnitsProvider::collect()
{
    nlohmann::json result = nlohmann::json::array();
    std::vector<SystemdUnit> units;

    if (!getSystemdUnits(units))
    {
        // std::cerr << "Error getting systemd units" << std::endl;
        return result;
    }

    for (const auto& unit : units)
    {
        nlohmann::json row;
        row["id"] = unit.id;
        row["description"] = unit.description;
        row["load_state"] = unit.loadState;
        row["active_state"] = unit.activeState;
        row["sub_state"] = unit.subState;
        row["following"] = unit.following;
        row["object_path"] = unit.objectPath;
        row["job_id"] = unit.jobId;
        row["job_type"] = unit.jobType;
        row["job_path"] = unit.jobPath;
        row["fragment_path"] = unit.fragmentPath;
        row["source_path"] = unit.sourcePath;
        row["user"] = unit.user;
        row["unit_file_state"] = unit.unitFileState;

        result.push_back(std::move(row));
    }

    return result;
}

bool SystemdUnitsProvider::getSystemdUnits(std::vector<SystemdUnit>& output)
{
    DBusError err;
    m_dbusWrapper->error_init(&err);

    DBusConnection* conn = m_dbusWrapper->bus_get(DBUS_BUS_SYSTEM, &err);

    if (!conn || m_dbusWrapper->error_is_set(&err))
    {
        // std::cerr << "Failed to connect to system bus: " << err.message << std::endl;
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessage* msg = m_dbusWrapper->message_new_method_call(
                           "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "ListUnits");

    if (!msg)
    {
        // std::cerr << "Failed to create message" << std::endl;
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessage* reply = m_dbusWrapper->connection_send_with_reply_and_block(conn, msg, -1, &err);
    m_dbusWrapper->message_unref(msg);

    if (!reply || m_dbusWrapper->error_is_set(&err))
    {
        // std::cerr << "Failed to send message: " << err.message << std::endl;
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessageIter iter;

    if (!m_dbusWrapper->message_iter_init(reply, &iter))
    {
        // std::cerr << "Reply has no arguments." << std::endl;
        m_dbusWrapper->message_unref(reply);
        m_dbusWrapper->error_free(&err);
        return false;
    }

    if (DBUS_TYPE_ARRAY != m_dbusWrapper->message_iter_get_arg_type(&iter))
    {
        // std::cerr << "Expected an array." << std::endl;
        m_dbusWrapper->message_unref(reply);
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessageIter arrayIter;
    m_dbusWrapper->message_iter_recurse(&iter, &arrayIter);

    while (m_dbusWrapper->message_iter_get_arg_type(&arrayIter) == DBUS_TYPE_STRUCT)
    {
        DBusMessageIter structIter;
        m_dbusWrapper->message_iter_recurse(&arrayIter, &structIter);

        SystemdUnit unit;
        const char* str = nullptr;
        uint32_t jobId;

        // ssssssou → 8 elements
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.id = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.description = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.loadState = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.activeState = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.subState = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.following = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.objectPath = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &jobId);
        unit.jobId = jobId;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.jobType = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.jobPath = str;

        // Extra properties
        for (const auto& query : m_propertyQueryList)
        {
            std::string value;

            if (m_dbusWrapper->getProperty(
                        conn, "org.freedesktop.systemd1", unit.objectPath, query.interface, query.propertyName, value))
            {
                if (query.columnName == "fragment_path")
                {
                    unit.fragmentPath = std::move(value);
                }
                else if (query.columnName == "source_path")
                {
                    unit.sourcePath = std::move(value);
                }
                else if (query.columnName == "user")
                {
                    unit.user = std::move(value);
                }
                else if (query.columnName == "unit_file_state")
                {
                    unit.unitFileState = std::move(value);
                }
            }
        }

        if (Utils::endsWith(unit.id, ".service") && Utils::replaceLast(unit.id, ".service", ""))
        {
            output.emplace_back(std::move(unit));
        }

        m_dbusWrapper->message_iter_next(&arrayIter);
    }

    m_dbusWrapper->message_unref(reply);
    m_dbusWrapper->error_free(&err);
    return true;
}
