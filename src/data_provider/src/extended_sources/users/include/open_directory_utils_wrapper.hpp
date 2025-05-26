/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "iopen_directory_utils_wrapper.hpp"
#include "od_wrapper.hpp"

/// @brief Wrapper class for querying OpenDirectory records.
///
/// Provides an implementation of the `IODUtilsWrapper` interface to query user or group
/// records from the local OpenDirectory node.
class ODUtilsWrapper : public IODUtilsWrapper
{
    public:
        /// @brief Queries local OpenDirectory records.
        ///
        /// Searches the local OpenDirectory node for user or group records based on `record_type`.
        /// If `record` is provided, filters by that name. Fills `names` with record names and
        /// a boolean indicating if each is hidden.
        ///
        /// @param record_type Type of record to search (e.g., users or groups).
        /// @param record Optional record name to filter the search.
        /// @param names Output map of record names to hidden status.
        void genEntries(const std::string& recordType,
                        const std::string* record,
                        std::map<std::string, bool>& names) override
        {
            od::genEntries(recordType, record, names);
        }
};
