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
#include <winsvc.h>
#include "json.hpp"

class ServicesProvider
{
    public:
        /// @brief Default constructor.
        ServicesProvider();

        /// @brief Collects services information.
        /// @return A JSON object containing the collected services information.
        nlohmann::json collect();

    private:
        /// @brief Retrieves details of a specific service.
        /// @param scmHandle Handle to the Service Control Manager.
        /// @param svc The service status to retrieve details for.
        /// @param results The JSON array to append the service details to.
        /// @return True if successful, false otherwise.
        bool getService(SC_HANDLE scmHandle, const ENUM_SERVICE_STATUS_PROCESSW& svc, nlohmann::json& results);

};