/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

// Objective-C++ only: shared by the .mm files that read the local OpenDirectory node.

#import <OpenDirectory/OpenDirectory.h>
#import <Foundation/Foundation.h>

#include <string>

namespace od
{
    /// @brief Runs a query against the local OpenDirectory node.
    ///
    /// @return The matching records, or nil when the directory could not be read. An empty array
    ///         means the query succeeded and matched nothing, which is not a failure.
    NSArray* queryLocalNode(ODRecordType recordType, ODAttributeType attribute, id queryValues, id returnAttributes);

    /// @brief Converts an Objective-C string, which yields null when it cannot be encoded as UTF-8.
    std::string toStdString(NSString* value);
} // namespace od
