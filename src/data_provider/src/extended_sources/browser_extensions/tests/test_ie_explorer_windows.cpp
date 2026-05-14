/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "iie_extensions_wrapper.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "filesystemHelper.h"
#include "ie_explorer.hpp"

class MockIEExtensionsWrapper : public IIEExtensionsWrapper
{
    public:
        MOCK_METHOD(LSTATUS, RegCloseKeyWrapper, (HKEY hKey), (override));

        MOCK_METHOD(LSTATUS, RegEnumValueAWrapper,
                    (HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName,
                     LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData),
                    (override));

        MOCK_METHOD(LSTATUS, RegQueryValueExAWrapper,
                    (HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType,
                     LPBYTE lpData, LPDWORD lpcbData),
                    (override));

        MOCK_METHOD(LSTATUS, RegOpenKeyExAWrapper,
                    (HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired,
                     PHKEY phkResult),
                    (override));

        MOCK_METHOD(LSTATUS, RegEnumKeyExAWrapper,
                    (HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName,
                     LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass,
                     PFILETIME lpftLastWriteTime),
                    (override));

        MOCK_METHOD(DWORD, GetFileVersionInfoSizeWWrapper,
                    (LPCWSTR lptstrFilename, LPDWORD lpdwHandle),
                    (override));

        MOCK_METHOD(BOOL, GetFileVersionInfoWWrapper,
                    (LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData),
                    (override));

        MOCK_METHOD(BOOL, VerQueryValueWWrapper,
                    (LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen),
                    (override));
};

void setupWrapper(std::shared_ptr<MockIEExtensionsWrapper>& ieExtensionsWrapper)
{
    EXPECT_CALL(*ieExtensionsWrapper,
                RegEnumKeyExAWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                     ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly([](HKEY hKey, DWORD dwIndex, char* lpName, DWORD * lpcchName,
                       LPDWORD, LPSTR, LPDWORD, PFILETIME)
    {
        if (hKey == HKEY_USERS)
        {
            const char* names[] =
            {
                "S-1-5-19",
                "S-1-5-20",
                "S-1-5-21-873499442-690455868-1617690636-1001"
            };

            if (dwIndex < 3)
            {
                size_t len = strlen(names[dwIndex]);
                memcpy(lpName, names[dwIndex], len);
                lpName[len] = '\0';
                *lpcchName = static_cast<DWORD>(len);
                return ERROR_SUCCESS;
            }

            return ERROR_NO_MORE_ITEMS;
        }
        else if (hKey == (HKEY)0x128)
        {
            const char* name = "{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}";

            if (dwIndex == 0)
            {
                size_t len = strlen(name);
                memcpy(lpName, name, len);
                lpName[len] = '\0';
                *lpcchName = static_cast<DWORD>(len);
                return ERROR_SUCCESS;
            }

            return ERROR_NO_MORE_ITEMS;
        }
        else if (hKey == (HKEY)0x130)
        {
            const char* name = "";

            if (dwIndex == 0)
            {
                size_t len = strlen(name);
                memcpy(lpName, name, len);
                lpName[len] = '\0';
                *lpcchName = static_cast<DWORD>(len);
                return ERROR_SUCCESS;
            }

            return ERROR_NO_MORE_ITEMS;
        }

        // Catch-all for any other hKey to suppress warnings
        if (lpcchName && lpName)
        {
            lpName[0] = '\0';
            *lpcchName = 0;
        }

        return ERROR_NO_MORE_ITEMS;
    });


    EXPECT_CALL(*ieExtensionsWrapper, RegOpenKeyExAWrapper(::testing::_, ::testing::_, 0, KEY_READ, ::testing::_))
    .WillRepeatedly([](HKEY, LPCSTR lpSubKey, DWORD, REGSAM,
                       PHKEY phkResult)
    {

        if (strcmp(lpSubKey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x128);
            return ERROR_SUCCESS;
        }
        else if (strcmp(lpSubKey, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x128);
            return ERROR_SUCCESS;
        }
        else if (strcmp(lpSubKey, "S-1-5-21-873499442-690455868-1617690636-1001\\SOFTWARE\\Microsoft\\Internet Explorer\\URLSearchHooks") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x130);
            return ERROR_SUCCESS;
        }
        else if (strcmp(lpSubKey, "SOFTWARE\\Classes\\CLSID\\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}\\InProcServer32") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x132);
            return ERROR_SUCCESS;
        }
        else if (strcmp(lpSubKey, "SOFTWARE\\Classes\\CLSID\\{CFBFAE00-17A6-11D0-99CB-00C04FD64497}\\InProcServer32") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x134);
            return ERROR_SUCCESS;
        }
        else if (strcmp(lpSubKey, "CLSID\\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x136);
            return ERROR_SUCCESS;
        }
        else if (strcmp(lpSubKey, "CLSID\\{CFBFAE00-17A6-11D0-99CB-00C04FD64497}") == 0)
        {
            *phkResult = reinterpret_cast<HKEY>(0x138);
            return ERROR_SUCCESS;
        }

        // Catch-all for any other keys
        if (phkResult)
        {
            *phkResult = nullptr;
        }

        return ERROR_NO_MORE_ITEMS;
    });

    EXPECT_CALL(*ieExtensionsWrapper,
                RegEnumValueAWrapper(::testing::_, 0, ::testing::_, ::testing::_,
                                     ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly([](HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName,
                       LPDWORD, LPDWORD, LPBYTE, LPDWORD)
    {
        if (hKey == (HKEY)0x130 && dwIndex == 0)
        {
            const char* guid = "{CFBFAE00-17A6-11D0-99CB-00C04FD64497}";
            size_t len = strlen(guid);

            memcpy(lpValueName, guid, len);
            lpValueName[len] = '\0';                // null terminate

            if (lpcchValueName)
            {
                *lpcchValueName = static_cast<DWORD>(len);
            }

            return ERROR_SUCCESS;
        }

        return ERROR_NO_MORE_ITEMS;  // default if not matching
    });

    EXPECT_CALL(*ieExtensionsWrapper,
                RegQueryValueExAWrapper(::testing::_, ::testing::StrEq(""), ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly([](HKEY hKey, LPCSTR lpValueName, LPDWORD,
                       LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
    {
        if (strcmp(lpValueName, "") != 0)
        {
            return ERROR_FILE_NOT_FOUND;  // not querying default value
        }

        const char* value = nullptr;

        if (hKey == (HKEY)0x132)
        {
            value = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\139.0.3405.111\\BHO\\ie_to_edge_bho.dll";
        }
        else if (hKey == (HKEY)0x134)
        {
            value = "C:\\Windows\\SysWOW64\\ieframe.dll";
        }
        else if (hKey == (HKEY)0x136)
        {
            value = "IEToEdge BHO";
        }
        else if (hKey == (HKEY)0x138)
        {
            value = "Microsoft Url Search Hook";
        }
        else
        {
            return ERROR_FILE_NOT_FOUND;  // no value for other keys
        }

        size_t len = strlen(value) + 1;  // include null terminator

        if (lpType)
        {
            *lpType = REG_SZ;
        }

        if (lpcbData)
        {
            *lpcbData = static_cast<DWORD>(len);
        }

        if (lpData)
        {
            memcpy(lpData, value, len);
        }

        return ERROR_SUCCESS;
    });

    EXPECT_CALL(*ieExtensionsWrapper,
                GetFileVersionInfoSizeWWrapper(::testing::_, ::testing::_))
    .WillOnce([](LPCWSTR, LPDWORD lpdwHandle) -> DWORD
    {
        if (lpdwHandle) *lpdwHandle = 0;
        return 2132;
    })
    .WillOnce([](LPCWSTR, LPDWORD lpdwHandle) -> DWORD
    {
        if (lpdwHandle) *lpdwHandle = 0;
        return 2132;
    })
    .WillOnce([](LPCWSTR, LPDWORD lpdwHandle) -> DWORD
    {
        if (lpdwHandle) *lpdwHandle = 0;
        return 1844;
    });

    EXPECT_CALL(*ieExtensionsWrapper,
                GetFileVersionInfoWWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce([](LPCWSTR, DWORD, DWORD dwLen, LPVOID lpData) -> BOOL
    {
        const char data[] =
        "☺ FileDescription     IEToEdge BHO     > ☼ ☺ FileVersion     139.0.3405.119 "
        "F‼ ☺ InternalName   ie_to_edge_bho_dll "
        "É6 ☺ LegalCopyright   Copyright Microsoft Corporation. All rights reserved. "
        "N‼ ☺ OriginalFilename   ie_to_edge_bho. "
        "☺ ProductName     IEToEdge BHO     "
        "B☼ ☺ ProductVersion   139.0.3405.119";
        memcpy(lpData, data, std::min<DWORD>(dwLen, sizeof(data)));
        return TRUE;
    })
    .WillOnce([](LPCWSTR, DWORD, DWORD dwLen, LPVOID lpData) -> BOOL
    {
        const char data[] =
        "☺ FileDescription     IEToEdge BHO     > ☼ ☺ FileVersion     139.0.3405.119 "
        "F‼ ☺ InternalName   ie_to_edge_bho_dll "
        "É6 ☺ LegalCopyright   Copyright Microsoft Corporation. All rights reserved. "
        "N‼ ☺ OriginalFilename   ie_to_edge_bho. "
        "☺ ProductName     IEToEdge BHO     "
        "B☼ ☺ ProductVersion   139.0.3405.119";
        memcpy(lpData, data, std::min<DWORD>(dwLen, sizeof(data)));
        return TRUE;
    })
    .WillOnce([](LPCWSTR, DWORD, DWORD dwLen, LPVOID lpData) -> BOOL
    {
        const char data[] =
        "ÿ♥4   VS_VERSION_INFO     "
        "☺ StringFileInfo "
        "☺ 040904B0 "
        "CompanyName     Microsoft Corporation "
        "FileDescription     Internet Browser "
        "FileVersion     11.00.26100.1742 (WinBuild.160101.0800) "
        "InternalName   IEFRAME.DLL "
        "LegalCopyright   Microsoft Corporation. All rights reserved. "
        "OriginalFilename   IEFRAME.DLL.MUI "
        "ProductName     Internet Explorer "
        "ProductVersion   11.00.26100.1742";
        memcpy(lpData, data, std::min<DWORD>(dwLen, sizeof(data)));
        return TRUE;
    });

    EXPECT_CALL(*ieExtensionsWrapper,
                VerQueryValueWWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce([](const void*, LPCWSTR, LPVOID * lplpBuffer, PUINT puLen)
    {
        VS_FIXEDFILEINFO* fixedFileInfo = reinterpret_cast<VS_FIXEDFILEINFO*>(lplpBuffer);
        fixedFileInfo->dwFileVersionMS = (139 << 16) | 0;
        fixedFileInfo->dwFileVersionLS = (3405 << 16) | 119;
        *puLen = sizeof(*fixedFileInfo);
        return TRUE;
    })
    .WillOnce([](const void*, LPCWSTR, LPVOID * lplpBuffer, PUINT puLen)
    {
        VS_FIXEDFILEINFO* fixedFileInfo = reinterpret_cast<VS_FIXEDFILEINFO*>(lplpBuffer);
        fixedFileInfo->dwFileVersionMS = (139 << 16) | 0;
        fixedFileInfo->dwFileVersionLS = (3405 << 16) | 119;
        *puLen = sizeof(*fixedFileInfo);
        return TRUE;
    })
    .WillOnce([](const void*, LPCWSTR, LPVOID * lplpBuffer, PUINT puLen)
    {
        VS_FIXEDFILEINFO* fixedFileInfo = reinterpret_cast<VS_FIXEDFILEINFO*>(lplpBuffer);
        fixedFileInfo->dwFileVersionMS = (11 << 16) | 0;
        fixedFileInfo->dwFileVersionLS = (26100 << 16) | 1742;
        *puLen = sizeof(*fixedFileInfo);
        return TRUE;
    });

    // Mock registry key closing
    EXPECT_CALL(*ieExtensionsWrapper, RegCloseKeyWrapper(::testing::_))
    .WillRepeatedly(::testing::Return(ERROR_SUCCESS));
}

TEST(IEExplorerTests, NumberOfExtensions)
{
    auto ieExtensionsWrapper = std::make_shared<MockIEExtensionsWrapper>();

    setupWrapper(ieExtensionsWrapper);

    IEExtensionsProvider ieExtensionsProvider(ieExtensionsWrapper);
    nlohmann::json extensionsJson = ieExtensionsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(3));
}
