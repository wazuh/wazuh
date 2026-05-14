/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <dbus/dbus.h>
#include <string>

/// @brief Interface for the D-Bus wrapper.
class IDBusWrapper
{
    public:
        /// @brief Destructor.
        virtual ~IDBusWrapper() = default;

        /// @brief Initializes a D-Bus error.
        /// @param error Pointer to the DBusError structure.
        virtual void error_init(DBusError* error) = 0;

        /// @brief Checks if a D-Bus error is set.
        /// @param error Pointer to the DBusError structure.
        /// @return True if the error is set, false otherwise.
        virtual bool error_is_set(const DBusError* error) = 0;

        /// @brief Frees a D-Bus error.
        /// @param error Pointer to the DBusError structure.
        virtual void error_free(DBusError* error) = 0;

        /// @brief Gets a D-Bus connection for the specified bus type.
        /// @param type The type of bus (session, system, etc.).
        /// @param error Pointer to the DBusError structure.
        /// @return Pointer to the DBusConnection, or nullptr on failure.
        virtual DBusConnection* bus_get(DBusBusType type, DBusError* error) = 0;

        /// @brief Creates a new D-Bus method call message.
        /// @param destination The destination bus name.
        /// @param path The object path.
        /// @param interface The interface name.
        /// @param method The method name.
        /// @return Pointer to the DBusMessage, or nullptr on failure.
        virtual DBusMessage* message_new_method_call(const std::string& destination,
                                                     const std::string& path,
                                                     const std::string& interface,
                                                     const std::string& method) = 0;

        /// @brief Sends a D-Bus message and waits for a reply.
        /// @param connection Pointer to the DBusConnection.
        /// @param message Pointer to the DBusMessage to send.
        /// @param timeout_milliseconds Timeout in milliseconds.
        /// @param error Pointer to the DBusError structure.
        /// @return Pointer to the DBusMessage reply, or nullptr on failure.
        virtual DBusMessage* connection_send_with_reply_and_block(DBusConnection* connection,
                                                                  DBusMessage* message,
                                                                  int timeout_milliseconds,
                                                                  DBusError* error) = 0;

        /// @brief Unreferences a D-Bus message.
        /// @param message Pointer to the DBusMessage to unreference.
        /// This function decrements the reference count of the message and frees it if the count reaches zero.
        /// It is safe to call this function with a nullptr.
        /// @note This function does not check if the message is valid before unreferencing it
        virtual void message_unref(DBusMessage* message) = 0;

        /// @brief Initializes a D-Bus message iterator.
        /// @param message Pointer to the DBusMessage to initialize the iterator for.
        /// @param iter Pointer to the DBusMessageIter to initialize.
        /// @return True if the iterator was successfully initialized, false otherwise.
        /// @note This function does not check if the message is valid before initializing the iterator.
        /// It is the caller's responsibility to ensure that the message is valid and has arguments.
        /// If the message is not valid, the behavior of this function is undefined.
        virtual bool message_iter_init(DBusMessage* message, DBusMessageIter* iter) = 0;

        /// @brief Gets the argument type of the current element in the D-Bus message iterator.
        /// @param iter Pointer to the DBusMessageIter.
        /// @return The argument type as an integer, or -1 if the iterator is not initialized or has no arguments.
        virtual int message_iter_get_arg_type(DBusMessageIter* iter) = 0;

        /// @brief Recurses into a D-Bus message iterator to get a sub-iterator.
        /// @param iter Pointer to the DBusMessageIter to recurse into.
        /// @param subIter Pointer to the DBusMessageIter to fill with the sub-iterator.
        /// This function initializes the sub-iterator to point to the first element of the current iterator.
        virtual void message_iter_recurse(DBusMessageIter* iter, DBusMessageIter* subIter) = 0;

        /// @brief Gets the basic value of the current element in the D-Bus message iterator.
        /// @param iter Pointer to the DBusMessageIter.
        /// @param value Pointer to the location where the value will be stored.
        /// This function retrieves the value of the current element in the iterator and stores it in the provided location.
        /// The type of the value is determined by the current argument type of the iterator.
        virtual void message_iter_get_basic(DBusMessageIter* iter, void* value) = 0;

        /// @brief Advances the D-Bus message iterator to the next element.
        /// @param iter Pointer to the DBusMessageIter.
        /// @return True if the iterator was successfully advanced to the next element, false if there are no more elements.
        /// This function checks if the iterator has more elements and advances it to the next element if available.
        /// If there are no more elements, it returns false and does not modify the iterator.
        virtual bool message_iter_next(DBusMessageIter* iter) = 0;

        /// @brief Gets a property from a D-Bus connection.
        /// @param conn Pointer to the DBusConnection.
        /// @param busName The bus name of the service.
        /// @param objectPath The object path of the service.
        /// @param interfaceName The interface name of the property.
        /// @param propertyName The name of the property to retrieve.
        /// @param outValue Reference to a string where the property value will be stored.
        /// @return True if the property was successfully retrieved, false otherwise.
        virtual bool getProperty(DBusConnection* conn,
                                 const std::string& busName,
                                 const std::string& objectPath,
                                 const std::string& interfaceName,
                                 const std::string& propertyName,
                                 std::string& outValue) = 0;
};
