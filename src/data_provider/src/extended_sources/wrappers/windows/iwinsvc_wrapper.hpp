/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <winsvc.h>

/// @brief Interface for Windows Service Control Manager (SCM) operations.
////// Provides methods to interact with the SCM, such as opening the service control manager,
/// opening services, querying service configurations, and enumerating services.
class IWinSvcWrapper
{
    public:
        /// @brief Default destructor.
        virtual ~IWinSvcWrapper() = default;

        /// @brief Opens a service control manager database.
        /// @param lpMachineName Name of the machine to connect to.
        /// @param dwDesiredAccess Access rights for the service control manager.
        /// @return Handle to the opened service control manager database.
        virtual SC_HANDLE OpenSCManagerWrapper(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) = 0;

        /// @brief Enumerates services in the service control manager database.
        /// @details This function retrieves information about services in the specified service control manager database.
        /// @note The function is a wrapper for the Windows API EnumServicesStatusExW.
        /// @param hSCManager Handle to the service control manager database.
        /// @param dwInfoLevel Information level to retrieve.
        /// @param dwServiceType Type of services to be enumerated
        /// @param dwServiceState State of services to be enumerated
        /// @param lpServices Pointer to a buffer that receives the service information.
        /// @param cbBufSize Size of the buffer pointed to by lpServices.
        /// @param pcbBytesNeeded Pointer to a variable that receives the size of the data returned in lpServices.
        /// @param lpServicesReturned Pointer to a variable that receives the number of services returned in lpServices.
        /// @param lpResumeHandle Pointer to a variable that receives a resume handle for the enumeration.
        /// @param pszGroupName Name of the group to which the services belong.
        /// @return TRUE if successful, FALSE otherwise.
        virtual BOOL EnumServicesStatusExWWrapper(
            SC_HANDLE hSCManager,
            SC_ENUM_TYPE dwInfoLevel,
            DWORD dwServiceType,
            DWORD dwServiceState,
            LPBYTE lpServices,
            DWORD cbBufSize,
            LPDWORD pcbBytesNeeded,
            LPDWORD lpServicesReturned,
            LPDWORD lpResumeHandle,
            LPCWSTR pszGroupName) = 0;

        /// @brief Opens a service in the service control manager database.
        /// @param hSCManager Handle to the service control manager database.
        /// @param lpServiceName Name of the service to open.
        /// @param dwDesiredAccess Access rights for the service.
        /// @return Handle to the opened service.
        virtual SC_HANDLE OpenServiceWWrapper(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess) = 0;

        /// @brief Queries the configuration of a service.
        /// @param hService Handle to the service.
        /// @param lpServiceConfig Pointer to a buffer that receives the service configuration.
        /// @param cbBufSize Size of the buffer pointed to by lpServiceConfig.
        /// @param pcbBytesNeeded Pointer to a variable that receives the size of the data returned
        /// @return TRUE if successful, FALSE otherwise.
        virtual BOOL QueryServiceConfigWWrapper(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig,
                                                DWORD cbBufSize, LPDWORD pcbBytesNeeded) = 0;

        /// @brief Queries the configuration of a service with additional information.
        /// @param hService Handle to the service.
        /// @param dwInfoLevel Information level to retrieve.
        /// @param lpBuffer Pointer to a buffer that receives the service configuration.
        /// @param cbBufSize Size of the buffer pointed to by lpBuffer.
        /// @param pcbBytesNeeded Pointer to a variable that receives the size of the data returned
        /// @return TRUE if successful, FALSE otherwise.
        virtual BOOL QueryServiceConfig2WWrapper(SC_HANDLE hService, DWORD dwInfoLevel,
                                                 LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded) = 0;

        /// @brief Closes a handle to a service control manager database.
        /// @param hSCManager Handle to the service control manager database.
        /// @return TRUE if successful, FALSE otherwise.
        virtual BOOL CloseServiceHandleWrapper(SC_HANDLE hSCManager) = 0;
};
