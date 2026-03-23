/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>
#include "ibrowser_extensions_wrapper.hpp"
#include <windows.h>
#include <sddl.h>
#include "stringHelper.h"

#define APP_PATH ""
#define HOME_PATH "C:\\Users"

class BrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        std::string getApplicationsPath() override
        {
            return std::string(APP_PATH);
        }

        std::string getHomePath() override
        {
            return std::string(HOME_PATH);
        }

        std::string getUserId(std::string user) override
        {
            std::string uid = "";
            LPCSTR accountName = user.c_str();

            BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
            DWORD sidSize = sizeof(sidBuffer);
            char domainName[256];
            DWORD domainNameSize = sizeof(domainName);
            SID_NAME_USE sidType;

            if (LookupAccountNameA(
                        NULL,              // System name (NULL = local computer)
                        accountName,       // Account name
                        sidBuffer,         // SID buffer
                        &sidSize,          // Size of SID buffer
                        domainName,        // Domain name buffer
                        &domainNameSize,   // Size of domain buffer
                        &sidType           // SID type
                    ))
            {
                LPSTR stringSid = nullptr;

                if (ConvertSidToStringSidA((PSID)sidBuffer, &stringSid))
                {
                    uid = Utils::split(std::string(stringSid), '-').back(); // Return the RID part of the SID
                    LocalFree(stringSid);
                }
            }

            return uid;
        }
};
