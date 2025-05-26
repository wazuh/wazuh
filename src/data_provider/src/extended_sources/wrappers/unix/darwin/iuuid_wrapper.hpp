/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <uuid/uuid.h>

// Interface for the uuid wrapper
class IUUIDWrapper
{
    public:
        /// Destructor
        virtual ~IUUIDWrapper() = default;

        /// @brief Converts a UID to a UUID.
        /// @param uid The user ID to convert.
        /// @param uuid Output parameter that will contain the corresponding UUID.
        virtual void uidToUUID(uid_t uid, uuid_t& uuid) = 0;

        /// @brief Converts a UUID to its string representation.
        /// @param uuid The UUID to convert.
        /// @param str Output buffer that will contain the string representation.
        virtual void uuidToString(const uuid_t& uuid, uuid_string_t& str) = 0;
};
