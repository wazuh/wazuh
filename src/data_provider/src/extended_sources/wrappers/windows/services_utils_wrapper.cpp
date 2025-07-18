/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "services_utils_wrapper.hpp"
#include "windows_api_wrapper.hpp"

ServicesHelper::ServicesHelper(std::shared_ptr<IWindowsApiWrapper> winapiWrapper)
    : m_winapiWrapper(std::move(winapiWrapper))
{
}

ServicesHelper::ServicesHelper()
    : m_winapiWrapper(std::make_shared<WindowsApiWrapper>())
{
}

std::optional<std::wstring> ServicesHelper::expandEnvStringW(const std::wstring& input)
{
    DWORD size = ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);

    if (size == 0)
    {
        return std::nullopt;
    }

    std::wstring result(size, L'\0');

    if (ExpandEnvironmentStringsW(input.c_str(), &result[0], size) == 0)
    {
        return std::nullopt;
    }

    result.pop_back(); // Remove null terminator
    return result;
}

std::optional<std::wstring> ServicesHelper::readServiceDllFromParameters(const std::wstring& serviceName)
{
    const std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName + L"\\Parameters";
    HKEY hKey = nullptr;

    LSTATUS status = m_winapiWrapper->RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey);

    if (status != ERROR_SUCCESS)
    {
        return std::nullopt;
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    status = m_winapiWrapper->RegQueryValueExWWrapper(hKey, L"ServiceDll", nullptr, &type, nullptr, &dataSize);

    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        m_winapiWrapper->RegCloseKeyWrapper(hKey);
        return std::nullopt;
    }

    std::wstring buffer(dataSize / sizeof(wchar_t), L'\0');
    status = m_winapiWrapper->RegQueryValueExWWrapper(hKey, L"ServiceDll", nullptr, nullptr, reinterpret_cast<LPBYTE>(&buffer[0]), &dataSize);

    m_winapiWrapper->RegCloseKeyWrapper(hKey);

    if (status != ERROR_SUCCESS)
    {
        return std::nullopt;
    }

    if (!buffer.empty() && buffer.back() == L'\0')
    {
        buffer.pop_back();
    }

    return buffer;
}
