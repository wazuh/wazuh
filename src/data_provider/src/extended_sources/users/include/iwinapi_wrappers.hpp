/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
 
 #pragma once

#include <winsock2.h>
#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>

// Interface for the TWSapiWrapper
class ITWSapiWrapper
{
    public:
        // Destructor
        virtual ~ITWSapiWrapper() = default;

        /// @brief WTSEnumerateSessionsW enumerates the sessions on a specified server
        /// @param hServer: Handle to the server
        /// @param pLevel: Level of information to be returned
        /// @param Filter: Filter for the sessions to be enumerated
        /// @param ppSessionInfo: Pointer to a buffer that receives the session information
        /// @param pCount: Pointer to a variable that receives the number of sessions
        /// @return Returns true if successful, false otherwise
        virtual bool WTSEnumerateSessionsW(HANDLE hServer,
                                           DWORD pLevel,
                                           DWORD Filter,
                                           PWTS_SESSION_INFOW* ppSessionInfo,
                                           DWORD* pCount) = 0;

        /// @brief WTSQuerySessionInformationW queries information about a session
        /// @param hServer: Handle to the server
        /// @param SessionId: ID of the session to query
        /// @param WTSInfoClass: Class of information to query
        /// @param ppBuffer: Pointer to a buffer that receives the information
        /// @param pBytesReturned: Pointer to a variable that receives the size of the information
        /// @return Returns true if successful, false otherwise
        virtual bool WTSQuerySessionInformationW(HANDLE hServer,
                                                 DWORD SessionId,
                                                 WTS_INFO_CLASS WTSInfoClass,
                                                 LPWSTR* ppBuffer,
                                                 DWORD* pBytesReturned) = 0;
        
        /// @brief WTSFreeMemory frees memory allocated by WTS functions
        /// @param pMemory: Pointer to the memory to be freed
        virtual void WTSFreeMemory(PVOID pMemory) = 0;

};

// Interface for the WinBaseApiWrapper
class IWinBaseApiWrapper
{
    public:
        // Destructor
        virtual ~IWinBaseApiWrapper() = default;

        /// @brief LookupAccountNameW retrieves the security identifier (SID) for a specified account name
        /// @param lpSystemName: Name of the system
        /// @param lpAccountName: Name of the account
        /// @param Sid: Pointer to a buffer that receives the SID
        /// @param cbSid: Size of the SID buffer
        /// @param ReferencedDomainName: Pointer to a buffer that receives the name of the domain
        /// @param cchReferencedDomainName: Size of the domain name buffer
        /// @param peUse: Pointer to a variable that receives the type of the SID
        /// @return Returns true if successful, false otherwise
        virtual bool LookupAccountNameW(LPCWSTR lpSystemName,
                                        LPCWSTR lpAccountName,
                                        PSID Sid,
                                        LPDWORD cbSid,
                                        LPWSTR ReferencedDomainName,
                                        LPDWORD cchReferencedDomainName,
                                        PSID_NAME_USE peUse) = 0;
};

// Interface for the WinSDDLWrapper
class IWinSDDLWrapper
{
    public:
        /// @brief Destructor
        virtual ~IWinSDDLWrapper() = default;

        /// @brief ConvertSidToStringSidW converts a SID to a string format
        /// @param Sid: Pointer to the SID to be converted
        /// @param StringSid: Pointer to a buffer that receives the string SID
        /// @return Returns true if successful, false otherwise
        virtual bool ConvertSidToStringSidW(PSID Sid, LPWSTR* StringSid) = 0;
};

// Interface for the WinSecurityBaseApiWrapper
class IWinSecurityBaseApiWrapper
{
    public:
        /// @brief Destructor
        virtual ~IWinSecurityBaseApiWrapper() = default;

        /// @brief IsValidSid checks if a SID is valid
        /// @param pSid: Pointer to the SID to be checked
        /// @return Returns true if the SID is valid, false otherwise
        virtual bool IsValidSid(PSID pSid) = 0;
};
