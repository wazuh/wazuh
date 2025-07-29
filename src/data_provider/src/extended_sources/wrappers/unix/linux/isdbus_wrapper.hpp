/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <systemd/sd-bus.h>

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

/// @brief Interface for the D-Bus wrapper.
class ISDBusWrapper
{
    public:
        /// @brief Destructor.
        virtual ~ISDBusWrapper() = default;

        /// @brief Opens a connection to the system D-Bus.
        /// @param ret Pointer to store the bus connection.
        /// @return 0 on success, or an error number on failure.
        virtual int sd_bus_open_system(sd_bus** ret) = 0;

        /// @brief Unreferences a D-Bus connection.
        /// @param bus Pointer to the bus connection to unreference.
        /// @return The unreferenced bus connection.
        virtual sd_bus* sd_bus_unref(sd_bus* bus) = 0;

        /// @brief Unreferences a D-Bus message.
        /// @param m Pointer to the message to unreference.
        /// @return The unreferenced message.
        virtual sd_bus_message* sd_bus_message_unref(sd_bus_message* m) = 0;

        /// @brief Enters a container in a D-Bus message.
        /// @param m Pointer to the message.
        /// @param type The type of the container to enter (e.g., SD_BUS_TYPE_ARRAY).
        /// @param contents Format string describing the contents of the container.
        /// @return 0 on success, or an error number on failure.
        virtual int sd_bus_message_enter_container(sd_bus_message* m, char type, const char* contents) = 0;

        /// @brief Exits a container in a D-Bus message.
        /// @param m Pointer to the message.
        /// @return 0 on success, or an error number on failure.
        virtual int sd_bus_message_exit_container(sd_bus_message* m) = 0;

        /// @brief Gets a property from a D-Bus object.
        /// @param bus Pointer to the bus connection.
        /// @param destination The D-Bus service name.
        /// @param path The object path to query.
        /// @param interface The D-Bus interface containing the property.
        /// @param member The name of the property to get.
        /// @param retError Pointer to store any error that occurs.
        /// @param ret Pointer to store the property value.
        /// @return 0 on success, or an error number on failure.
        virtual int sd_bus_get_property_string(sd_bus* bus,
                                               const char* destination,
                                               const char* path,
                                               const char* interface,
                                               const char* member,
                                               sd_bus_error* retError,
                                               char** ret) = 0;

        /// @brief Calls the ListUnits method on the systemd D-Bus interface.
        /// @param bus Pointer to the bus connection.
        /// @param reply Pointer to store the reply message.
        /// @param error Pointer to store any error that occurs.
        /// @return 0 on success, or an error number on failure.
        /// @note This method is used to retrieve a list of systemd units.
        virtual int callListUnits(sd_bus* bus, sd_bus_message** reply, sd_bus_error* error) = 0;

        /// @brief Parses a systemd unit from a D-Bus message.
        /// @param m Pointer to the message containing the unit data.
        /// @param outData Reference to a SystemdUnit structure to store the parsed data.
        /// @return 0 on success, or an error number on failure.
        /// @note This method extracts various properties of the unit from the message.
        virtual int parseSystemdUnit(sd_bus_message* m, SystemdUnit& outData) = 0;
};
