#include <windows.h>
#include <winsvc.h>

#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "services_windows.hpp"
#include "winsvc_wrapper.hpp"
#include "windows_api_wrapper.hpp"
#include "encodingWindowsHelper.h"

using json = nlohmann::json;

std::optional<std::wstring> expandEnvStringW(const std::wstring& input)
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

const std::string K_SERVICE_START_TYPE[] = {"BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"};

const std::string K_SERVICE_STATUS[] =
{
    "UNKNOWN", "STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED"
};

/* Possible values defined here (dwServiceType):
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw
 */
const std::map<int, std::string> K_SERVICE_TYPE = {{0x00000001, "KERNEL_DRIVER"},
    {0x00000002, "FILE_SYSTEM_DRIVER"},
    {0x00000010, "OWN_PROCESS"},
    {0x00000020, "SHARE_PROCESS"},
    {0x00000050, "USER_OWN_PROCESS"},
    {0x00000060, "USER_SHARE_PROCESS"},
    {0x000000d0, "USER_OWN_PROCESS(Instance)"},
    {0x000000e0, "USER_SHARE_PROCESS(Instance)"},
    {0x00000100, "INTERACTIVE_PROCESS"},
    {0x00000110, "OWN_PROCESS(Interactive)"},
    {0x00000120, "SHARE_PROCESS(Interactive)"}
};

std::optional<std::wstring> readServiceDllFromParameters(const std::wstring& serviceName)
{
    const std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName + L"\\Parameters";
    HKEY hKey = nullptr;

    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey);

    if (status != ERROR_SUCCESS)
    {
        return std::nullopt;
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    status = RegQueryValueExW(hKey, L"ServiceDll", nullptr, &type, nullptr, &dataSize);

    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    std::wstring buffer(dataSize / sizeof(wchar_t), L'\0');
    status = RegQueryValueExW(hKey, L"ServiceDll", nullptr, nullptr, reinterpret_cast<LPBYTE>(&buffer[0]), &dataSize);

    RegCloseKey(hKey);

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

ServicesProvider::ServicesProvider(std::shared_ptr<IWinSvcWrapper> winSvcWrapper,
                                   std::shared_ptr<IWindowsApiWrapper> winApiWrapper)
    : m_winSvcWrapper(std::move(winSvcWrapper))
    , m_winApiWrapper(std::move(winApiWrapper))
{}

ServicesProvider::ServicesProvider()
    : m_winSvcWrapper(std::make_shared<WinSvcWrapper>())
    , m_winApiWrapper(std::make_shared<WindowsApiWrapper>())
{}

bool ServicesProvider::getService(SC_HANDLE scmHandle, const ENUM_SERVICE_STATUS_PROCESSW& svc, json& results)
{

    auto svcHandle = m_winSvcWrapper->OpenServiceWWrapper(scmHandle, svc.lpServiceName, SERVICE_QUERY_CONFIG);

    if (!svcHandle)
    {
        std::cerr << "Error opening service handle: " << m_winApiWrapper->GetLastErrorWrapper() << "\n";
        return false;
    }

    DWORD cbBufSize = 0;
    m_winSvcWrapper->QueryServiceConfigWWrapper(svcHandle, nullptr, 0, &cbBufSize);

    if (m_winApiWrapper->GetLastErrorWrapper() != ERROR_INSUFFICIENT_BUFFER)
    {
        std::cerr << "Error getting config size: " << m_winApiWrapper->GetLastErrorWrapper() << "\n";
        m_winSvcWrapper->CloseServiceHandleWrapper(svcHandle);
        return false;
    }

    auto configBuf = std::make_unique<wchar_t[]>(cbBufSize);
    auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuf.get());

    if (!m_winSvcWrapper->QueryServiceConfigWWrapper(svcHandle, config, cbBufSize, &cbBufSize))
    {
        std::cerr << "Error reading service config: " << m_winApiWrapper->GetLastErrorWrapper() << "\n";
        m_winSvcWrapper->CloseServiceHandleWrapper(svcHandle);
        return false;
    }

    json item;
    item["name"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(svc.lpServiceName);
    item["display_name"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(svc.lpDisplayName);
    item["status"] = K_SERVICE_STATUS[svc.ServiceStatusProcess.dwCurrentState];
    item["pid"] = svc.ServiceStatusProcess.dwProcessId;
    item["win32_exit_code"] = svc.ServiceStatusProcess.dwWin32ExitCode;
    item["service_exit_code"] = svc.ServiceStatusProcess.dwServiceSpecificExitCode;
    item["start_type"] = K_SERVICE_START_TYPE[config->dwStartType];
    item["path"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(config->lpBinaryPathName);
    item["user_account"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(config->lpServiceStartName);

    if (K_SERVICE_TYPE.count(config->dwServiceType) > 0)
    {
        item["service_type"] = K_SERVICE_TYPE.at(config->dwServiceType);
    }
    else
    {
        item["service_type"] = "UNKNOWN";
    }

    item["description"] = "";

    DWORD descBufSize = 0;
    m_winSvcWrapper->QueryServiceConfig2WWrapper(svcHandle, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &descBufSize);

    if (m_winApiWrapper->GetLastErrorWrapper() == ERROR_INSUFFICIENT_BUFFER && descBufSize > 0)
    {
        auto descBuf = std::make_unique<BYTE[]>(descBufSize);
        auto desc = reinterpret_cast<LPSERVICE_DESCRIPTIONW>(descBuf.get());

        if (m_winSvcWrapper->QueryServiceConfig2WWrapper(svcHandle, SERVICE_CONFIG_DESCRIPTION, descBuf.get(), descBufSize, &descBufSize))
        {
            if (desc->lpDescription != nullptr)
            {
                item["description"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(desc->lpDescription);
            }
        }
        else
        {
            std::cerr << "Warning: Failed to get service description. Error: " << GetLastError() << "\n";
        }
    }

    auto serviceDll = readServiceDllFromParameters(svc.lpServiceName);

    if (serviceDll.has_value())
    {
        auto expanded = expandEnvStringW(serviceDll.value());
        std::wstring finalPath = expanded.value_or(serviceDll.value());
        item["module_path"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(finalPath);
    }
    else
    {
        item["module_path"] = "";
    }

    results.push_back(item);
    m_winSvcWrapper->CloseServiceHandleWrapper(svcHandle);
    return true;
}

nlohmann::json ServicesProvider::collect()
{
    json results = json::array();

    auto scmHandle = m_winSvcWrapper->OpenSCManagerWrapper(nullptr, nullptr, GENERIC_READ);

    if (!scmHandle)
    {
        std::cerr << "Failed to connect to Service Connection Manager: " << m_winApiWrapper->GetLastErrorWrapper() << "\n";
        return results;
    }

    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    m_winSvcWrapper->EnumServicesStatusExWWrapper(scmHandle,
                                                  SC_ENUM_PROCESS_INFO,
                                                  SERVICE_WIN32 | SERVICE_DRIVER,
                                                  SERVICE_STATE_ALL,
                                                  nullptr,
                                                  0,
                                                  &bytesNeeded,
                                                  &serviceCount,
                                                  nullptr,
                                                  nullptr);

    if (m_winApiWrapper->GetLastErrorWrapper() != ERROR_MORE_DATA)
    {
        std::cerr << "Error querying buffer size: " << m_winApiWrapper->GetLastErrorWrapper() << "\n";
        m_winSvcWrapper->CloseServiceHandleWrapper(scmHandle);
        return results;
    }

    auto buffer = std::make_unique<BYTE[]>(bytesNeeded);
    auto services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.get());

    if (!m_winSvcWrapper->EnumServicesStatusExWWrapper(scmHandle,
                                                       SC_ENUM_PROCESS_INFO,
                                                       SERVICE_WIN32 | SERVICE_DRIVER,
                                                       SERVICE_STATE_ALL,
                                                       buffer.get(),
                                                       bytesNeeded,
                                                       &bytesNeeded,
                                                       &serviceCount,
                                                       nullptr,
                                                       nullptr))
    {
        std::cerr << "Error enumerating services: " << m_winApiWrapper->GetLastErrorWrapper() << "\n";
        m_winSvcWrapper->CloseServiceHandleWrapper(scmHandle);
        return results;
    }

    for (DWORD i = 0; i < serviceCount; ++i)
    {
        if (!getService(scmHandle, services[i], results))
        {
            std::cerr << "Warning: Failed to get details for service\n";
        }
    }

    m_winSvcWrapper->CloseServiceHandleWrapper(scmHandle);
    return results;
}
