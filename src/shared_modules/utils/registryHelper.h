/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
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
#include <winsock2.h>
#include <windows.h>
#include <winreg.h>
#include <cstdio>
#include <memory>
#include "encodingWindowsHelper.h"
#include "windowsHelper.h"

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
                close();
            }

            void close()
            {
                if (m_registryKey)
                {
                    RegCloseKey(m_registryKey);
                    m_registryKey = nullptr;
                }
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
                DWORD size{sizeof(DWORD)};
                const auto result
                {
                    RegQueryValueEx(m_registryKey, valueName.c_str(), nullptr, nullptr, reinterpret_cast<LPBYTE>(&value), &size)
                };
                return result == ERROR_SUCCESS;
            }

            std::vector<std::string> enumerate() const
            {
                std::vector<std::string> ret;
                constexpr auto MAX_KEY_NAME_SIZE{255};//https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
                char buff[MAX_KEY_NAME_SIZE] {};
                DWORD size{MAX_KEY_NAME_SIZE};
                DWORD index{0};
                auto result{RegEnumKeyEx(m_registryKey, index, buff, &size, nullptr, nullptr, nullptr, nullptr)};

                while (result == ERROR_SUCCESS)
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

            std::vector<std::string> enumerateValueKey() const
            {
                std::vector<std::string> ret;
                constexpr auto MAX_KEY_NAME_VALUE {32767}; // https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
                char buffer[MAX_KEY_NAME_VALUE];
                DWORD size {MAX_KEY_NAME_VALUE};
                DWORD index {0};

                auto result {RegEnumValue(m_registryKey, index, buffer, &size, nullptr,  nullptr, nullptr, nullptr)};

                while (ERROR_SUCCESS == result)
                {
                    ret.push_back(buffer);
                    size = MAX_KEY_NAME_VALUE;
                    index++;
                    result = RegEnumValue(m_registryKey, index, buffer, &size, nullptr,  nullptr, nullptr, nullptr);
                }

                if (ERROR_NO_MORE_ITEMS != result)
                {
                    throw std::system_error
                    {
                        result,
                        std::system_category(),
                        "Error enumerating Values in registry."
                    };
                }

                return ret;
            }

            void enumerate(const std::function<void(const std::string&)>& callback) const
            {
                std::vector<std::string> ret;
                constexpr auto MAX_KEY_NAME_SIZE{255};//https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
                char buff[MAX_KEY_NAME_SIZE] {};
                DWORD size{MAX_KEY_NAME_SIZE};
                DWORD index{0};
                auto result{RegEnumKeyEx(m_registryKey, index, buff, &size, nullptr, nullptr, nullptr, nullptr)};

                while (result == ERROR_SUCCESS)
                {
                    callback(buff);
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
            }

            bool enumerate(std::vector<std::string>& values) const
            {
                bool ret{true};

                try
                {
                    values = this->enumerate();
                }
                catch (...)
                {
                    ret = false;
                }

                return ret;
            }

            bool enumerateValueKey(std::vector<std::string>& values) const
            {
                auto ret{true};

                try
                {
                    values = this->enumerateValueKey();
                }
                catch (...)
                {
                    ret = false;
                }

                return ret;
            }

            std::string keyModificationDate() const
            {
                std::string ret;
                FILETIME lastModificationTime { };
                const auto result
                {
                    RegQueryInfoKey(m_registryKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &lastModificationTime)
                };

                if (ERROR_SUCCESS == result)
                {
                    ULARGE_INTEGER time { };

                    time.LowPart = lastModificationTime.dwLowDateTime;
                    time.HighPart = lastModificationTime.dwHighDateTime;

                    // Use structure values to build 18-digit LDAP/FILETIME number
                    ret = Utils::buildTimestamp(time.QuadPart);
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


            bool qword(const std::string& valueName, ULONGLONG& value) const
            {
                ULONGLONG valueRegistry;
                DWORD size {sizeof(ULONGLONG)};
                DWORD type;
                auto ret {false};

                const auto result { RegQueryValueEx(m_registryKey, valueName.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(&valueRegistry), &size) };

                if (ERROR_SUCCESS != result)
                {
                    throw std::system_error
                    {
                        result,
                        std::system_category(),
                        "Error reading the value of: " + valueName
                    };
                }

                if (REG_QWORD == type)
                {
                    value = valueRegistry;
                    ret = true;
                }

                return ret;
            }

            bool string(const std::string& valueName, std::string& value) const
            {
                bool ret{true};

                try
                {
                    value = EncodingWindowsHelper::stringAnsiToStringUTF8(this->string(valueName));
                }
                catch (...)
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
