/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <map>
#include <string>

// Interface for the open directory utils wrapper
class IODUtilsWrapper
{
    public:
        /// Destructor
        virtual ~IODUtilsWrapper() = default;

        /// @brief Queries local OpenDirectory records.
        ///
        /// Searches the local OpenDirectory node for user or group records based on `record_type`.
        /// If `record` is provided, filters by that name. Fills `names` with record names and
        /// a boolean indicating if each is hidden.
        ///
        /// @param record_type Type of record to search (e.g., users or groups).
        /// @param record Optional record name to filter the search.
        /// @param names Output map of record names to hidden status.
        virtual void genEntries(const std::string& recordType,
                                const std::string* record,
                                std::map<std::string, bool>& names) = 0;
};
