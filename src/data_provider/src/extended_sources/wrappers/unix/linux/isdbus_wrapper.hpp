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

        /// @brief Reads a D-Bus message.
        /// @param m Pointer to the message to read.
        /// @param types Format string describing the expected types.
        virtual int sd_bus_message_read(sd_bus_message* m, const char* types, ...) = 0;

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

        /// @brief Calls a method on a D-Bus service.
        /// @param bus Pointer to the bus connection.
        /// @param destination The D-Bus service name.
        /// @param path The object path to call the method on.
        /// @param interface The D-Bus interface containing the method.
        /// @param member The name of the method to call.
        /// @param retError Pointer to store any error that occurs.
        /// @param reply Pointer to store the reply message.
        /// @param types Format string describing the input parameters.
        /// @return 0 on success, or an error number on failure.
        virtual int sd_bus_call_method(sd_bus* bus,
                                       const char* destination,
                                       const char* path,
                                       const char* interface,
                                       const char* member,
                                       sd_bus_error* retError,
                                       sd_bus_message** reply,
                                       const char* types,
                                       ...) = 0;

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
};
