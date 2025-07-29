/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "isdbus_wrapper.hpp"

/// @brief Wrapper class for D-Bus operations.
/// Provides an interface for D-Bus operations, allowing easier mocking and testing.
class SDBusWrapper : public ISDBusWrapper
{
    public:
        /// @brief Opens a connection to the system D-Bus.
        /// @param ret Pointer to store the bus connection.
        /// @return 0 on success, or an error number on failure.
        int sd_bus_open_system(sd_bus** ret) override
        {
            return ::sd_bus_open_system(ret);
        }

        /// @brief Unreferences a D-Bus connection.
        /// @param bus Pointer to the bus connection to unreference.
        /// @return The unreferenced bus connection.
        sd_bus* sd_bus_unref(sd_bus* bus) override
        {
            return ::sd_bus_unref(bus);
        }

        /// @brief Unreferences a D-Bus message.
        /// @param m Pointer to the message to unreference.
        /// @return The unreferenced message.
        sd_bus_message* sd_bus_message_unref(sd_bus_message* m) override
        {
            return ::sd_bus_message_unref(m);
        }

        /// @brief Enters a container in a D-Bus message.
        /// @param m Pointer to the message.
        /// @param type The type of the container to enter (e.g., SD_BUS_TYPE_ARRAY).
        /// @param contents Format string describing the contents of the container.
        /// @return 0 on success, or an error number on failure.
        int sd_bus_message_enter_container(sd_bus_message* m, char type, const char* contents) override
        {
            return ::sd_bus_message_enter_container(m, type, contents);
        }

        /// @brief Exits a container in a D-Bus message.
        /// @param m Pointer to the message.
        /// @return 0 on success, or an error number on failure.
        int sd_bus_message_exit_container(sd_bus_message* m) override
        {
            return ::sd_bus_message_exit_container(m);
        }

        /// @brief Gets a property from a D-Bus object.
        /// @param bus Pointer to the bus connection.
        /// @param destination The D-Bus service name.
        /// @param path The object path to query.
        /// @param interface The D-Bus interface containing the property.
        /// @param member The name of the property to get.
        /// @param retError Pointer to store any error that occurs.
        /// @param ret Pointer to store the property value.
        /// @return 0 on success, or an error number on failure.
        int sd_bus_get_property_string(sd_bus* bus,
                                       const char* destination,
                                       const char* path,
                                       const char* interface,
                                       const char* member,
                                       sd_bus_error* retError,
                                       char** ret) override
        {
            return ::sd_bus_get_property_string(bus, destination, path, interface, member,
                                                retError, ret);
        }

        /// @brief Calls the ListUnits method on the systemd D-Bus interface.
        /// @param bus Pointer to the bus connection.
        /// @param reply Pointer to store the reply message.
        /// @param error Pointer to store any error that occurs.
        /// @return 0 on success, or an error number on failure.
        /// @note This method is used to retrieve a list of systemd units.
        int callListUnits(sd_bus* bus, sd_bus_message** reply, sd_bus_error* error) override
        {
            return ::sd_bus_call_method(bus,
                                        "org.freedesktop.systemd1",
                                        "/org/freedesktop/systemd1",
                                        "org.freedesktop.systemd1.Manager",
                                        "ListUnits",
                                        error,
                                        reply,
                                        "");
        }

        /// @brief Parses a systemd unit from a D-Bus message.
        /// @param m Pointer to the message containing the unit data.
        /// @param outData Reference to a SystemdUnit structure to store the parsed data.
        /// @return 0 on success, or an error number on failure.
        /// @note This method extracts various properties of the unit from the message.
        int parseSystemdUnit(sd_bus_message* m, SystemdUnit& outData) override
        {
            const char* id;
            const char* description;
            const char* loadState;
            const char* activeState;
            const char* subState;
            const char* following;
            const char* objectPath;
            uint32_t jobId;
            const char* jobType;
            const char* jobPath;

            int ret = ::sd_bus_message_read(m,
                                            "ssssssouso",
                                            &id,
                                            &description,
                                            &loadState,
                                            &activeState,
                                            &subState,
                                            &following,
                                            &objectPath,
                                            &jobId,
                                            &jobType,
                                            &jobPath);

            if (ret < 0)
            {
                return ret;
            }

            outData.id = id;
            outData.description = description;
            outData.loadState = loadState;
            outData.activeState = activeState;
            outData.subState = subState;
            outData.following = following;
            outData.objectPath = objectPath;
            outData.jobId = jobId;
            outData.jobType = jobType;
            outData.jobPath = jobPath;

            return 0;
        }
};
