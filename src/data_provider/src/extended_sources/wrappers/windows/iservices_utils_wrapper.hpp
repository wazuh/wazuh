/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <windows.h>
#include <optional>
#include <string>

// Interface for the windows services helper wrapper
class IServicesHelper
{
    public:
        /// Destructor
        virtual ~IServicesHelper() = default;

        /// @brief Expands environment variables in a given string.
        /// @param input The input string potentially containing environment variables.
        /// @return A string with environment variables expanded, or std::nullopt if expansion fails
        virtual std::optional<std::wstring> expandEnvStringW(const std::wstring& input) = 0;

        /// @brief Reads the ServiceDll value from the service parameters registry key.
        /// @param serviceName The name of the service to read the ServiceDll from.
        /// @return The ServiceDll path as a std::wstring if found, or std::nullopt if not found or an error occurs.
        virtual std::optional<std::wstring> readServiceDllFromParameters(const std::wstring& serviceName) = 0;
};
