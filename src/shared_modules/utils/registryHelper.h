/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#ifndef _REGISTRY_HELPER_H
#define _REGISTRY_HELPER_H

#include <string>
#include <windows.h>
#include <winreg.h>
#include <cstdio>
#include <memory>
#include "encodingWindowsHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    class Registry final
    {
    public:
        Registry(const HKEY key, const std::string& subKey = "", const REGSAM access = KEY_READ)
        : m_registryKey{openRegistry(key, subKey, access)}
        {}
        ~Registry()
        {
            RegCloseKey(m_registryKey);
        }

        DWORD dword(const std::string& valueName) const
        {
            DWORD ret{};
            DWORD size{sizeof(DWORD)};
            const auto result
            {
                RegQueryValueEx(m_registryKey, valueName.c_str(), nullptr, nullptr, reinterpret_cast<LPBYTE>(&ret), &size)
            };
            if (result != ERROR_SUCCESS)
            {
                throw std::system_error
                {
                    result,
                    std::system_category(),
                    "Error reading DWORD value of: " + valueName
                };
            }
            return ret;
        }

        bool dword(const std::string& valueName, DWORD& value) const
        {
            bool ret{true};
            try
            {
                value = this->dword(valueName);
            }
            catch(...)
            {
                ret = false;
            }
            return ret;
        }

        std::vector<std::string> enumerate() const
        {
            std::vector<std::string> ret;
            constexpr auto MAX_KEY_NAME_SIZE{255};//https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
            char buff[MAX_KEY_NAME_SIZE]{};
            DWORD size{MAX_KEY_NAME_SIZE};
            DWORD index{0};
            auto result{RegEnumKeyEx(m_registryKey, index, buff, &size, nullptr, nullptr, nullptr, nullptr)};
            while(result == ERROR_SUCCESS)
            {
                ret.push_back(buff);
                size = MAX_KEY_NAME_SIZE;
                ++index;
                result = RegEnumKeyEx(m_registryKey, index, buff, &size, nullptr, nullptr, nullptr, nullptr);
            }
            if (result != ERROR_NO_MORE_ITEMS)
            {
                throw std::system_error
                {
                    result,
                    std::system_category(),
                    "Error enumerating registry."
                };
            }
            return ret;
        }

        bool enumerate(std::vector<std::string>& values) const
        {
            bool ret{true};
            try
            {
                values = this->enumerate();
            }
            catch(...)
            {
                ret = false;
            }
            return ret;
        }

        std::string string(const std::string& valueName) const
        {
            DWORD size{0};
            auto result
            {
                RegQueryValueEx(m_registryKey, valueName.c_str(), nullptr, nullptr, nullptr, &size)
            };
            if (result != ERROR_SUCCESS)
            {
                throw std::system_error
                {
                    result,
                    std::system_category(),
                    "Error reading the size of: " + valueName
                };
            }
            const auto spBuff{std::make_unique<BYTE[]>(size)};
            if (!spBuff)
            {
                throw std::runtime_error
                {
                    "Error allocating memory to read String value of: " + valueName
                };
            }
            result = RegQueryValueEx(m_registryKey, valueName.c_str(), nullptr, nullptr, spBuff.get(), &size);
            if (result != ERROR_SUCCESS)
            {
                throw std::system_error
                {
                    result,
                    std::system_category(),
                    "Error reading String value of: " + valueName
                };
            }
            return std::string{reinterpret_cast<const char*>(spBuff.get())};
        }

        bool string(const std::string& valueName, std::string& value) const
        {
            bool ret{true};
            try
            {
                value = EncodingWindowsHelper::stringAnsiToStringUTF8(this->string(valueName));
            }
            catch(...)
            {
                ret = false;
            }
            return ret;
        }

        private:
        static HKEY openRegistry(const HKEY key, const std::string& subKey, const REGSAM access)
        {
            HKEY ret{nullptr};
            const auto result
            {
                RegOpenKeyEx(key, subKey.c_str(), 0, access, &ret)
            };
            if (result != ERROR_SUCCESS)
            {
                throw std::system_error
                {
                    result,
                    std::system_category(),
                    "Error opening registry: " + subKey
                };
            }
            return ret;
        }
        HKEY m_registryKey;
    };
}

#pragma GCC diagnostic pop

#endif // _REGISTRY_HELPER_H

#endif //WIN32
