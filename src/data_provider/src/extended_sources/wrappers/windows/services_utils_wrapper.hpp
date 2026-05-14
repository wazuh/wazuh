/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "iservices_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"

/// @brief Helper class for Windows services operations.
class ServicesHelper : public IServicesHelper
{
    private:
        /// @brief Windows API wrapper instance used for system calls.
        std::shared_ptr<IWindowsApiWrapper> m_winapiWrapper;

    public:
        /// @brief Constructs a ServicesHelper.
        /// @param winapiWrapper Shared pointer to an `IWindowsApiWrapper`.
        explicit ServicesHelper(std::shared_ptr<IWindowsApiWrapper> winapiWrapper);

        /// @brief Default constructor.
        ServicesHelper();

        /// @brief Expands environment variables in a given string.
        /// @param input The input string potentially containing environment variables.
        /// @return A string with environment variables expanded, or std::nullopt if expansion fails
        std::optional<std::wstring> expandEnvStringW(const std::wstring& input) override;

        /// @brief Reads the ServiceDll value from the service parameters registry key.
        /// @param serviceName The name of the service to read the ServiceDll from.
        /// @return The ServiceDll path as a std::wstring if found, or std::nullopt if not found or an error occurs.
        std::optional<std::wstring> readServiceDllFromParameters(const std::wstring& serviceName) override;
};
