#include <windows.h>
#include <winsvc.h>

#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "services_windows.hpp"
// #include <nlohmann/json.hpp>
// #include "windows_api_wrapper.hpp"
#include "encodingWindowsHelper.h"

using json = nlohmann::json;

std::optional<std::string> expandEnvString(const std::string& str) {
    DWORD size = ExpandEnvironmentStringsA(str.c_str(), nullptr, 0);
    if (size == 0) {
        return std::nullopt;
    }
    std::string result(size, '\0');
    ExpandEnvironmentStringsA(str.c_str(), &result[0], size);
    result.pop_back(); // remove null terminator
    return result;
}

const std::string kSvcStartType[] = {"BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"};

const std::string kSvcStatus[] = {
    "UNKNOWN", "STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED"};

/* Possible values defined here (dwServiceType):
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status
 * https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw
 */
const std::map<int, std::string> kServiceType = {
    {0x00000001, "KERNEL_DRIVER"},
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

std::optional<std::string> readRegistryValue(HKEY root,
                                             const std::string& subkey,
                                             const std::string& valueName) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    if (RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, nullptr, &dataSize) != ERROR_SUCCESS ||
        type != REG_SZ) {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    std::vector<char> data(dataSize);
    if (RegQueryValueExA(hKey, valueName.c_str(), nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(data.data()), &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    RegCloseKey(hKey);
    return std::string(data.data());
}

bool ServicesProvider::getService(SC_HANDLE scmHandle, const ENUM_SERVICE_STATUS_PROCESS& svc, json& results) {

    auto svcHandle = OpenServiceW(scmHandle, svc.lpServiceName, SERVICE_QUERY_CONFIG);

    if (!svcHandle) {
        std::cerr << "Error opening service handle: " << GetLastError() << "\n";
        return false;
    }

    DWORD cbBufSize = 0;
    QueryServiceConfigW(svcHandle, nullptr, 0, &cbBufSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Error getting config size: " << GetLastError() << "\n";
        CloseServiceHandle(svcHandle);
        return false;
    }

    auto configBuf = std::make_unique<wchar_t[]>(cbBufSize);
    auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuf.get());

    if (!QueryServiceConfigW(svcHandle, config, cbBufSize, &cbBufSize)) {
        std::cerr << "Error reading service config: " << GetLastError() << "\n";
        CloseServiceHandle(svcHandle);
        return false;
    }

    json item;
    item["name"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(svc.lpServiceName);
    item["display_name"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(svc.lpDisplayName);
    item["status"] = kSvcStatus[svc.ServiceStatusProcess.dwCurrentState];
    item["pid"] = svc.ServiceStatusProcess.dwProcessId;
    item["win32_exit_code"] = svc.ServiceStatusProcess.dwWin32ExitCode;
    item["service_exit_code"] = svc.ServiceStatusProcess.dwServiceSpecificExitCode;
    item["start_type"] = kSvcStartType[config->dwStartType];
    item["path"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(config->lpBinaryPathName);
    item["user_account"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(config->lpServiceStartName);

    if (kServiceType.count(config->dwServiceType) > 0) {
        item["service_type"] = kServiceType.at(config->dwServiceType);
    } else {
        item["service_type"] = "UNKNOWN";
    }

    DWORD descBufSize = 0;
    QueryServiceConfig2W(svcHandle, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &descBufSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && descBufSize > 0) {
        auto descBuf = std::make_unique<BYTE[]>(descBufSize);
        auto desc = reinterpret_cast<LPSERVICE_DESCRIPTION>(descBuf.get());

        if (QueryServiceConfig2W(svcHandle, SERVICE_CONFIG_DESCRIPTION,
                                descBuf.get(), descBufSize, &descBufSize)) {
            if (desc->lpDescription != nullptr) {
                item["description"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(desc->lpDescription);
            }
        } else {
            std::cerr << "Warning: Failed to get service description. Error: " << GetLastError() << "\n";
        }
    }

    std::string regPath = "SYSTEM\\CurrentControlSet\\Services\\" + item["name"].get<std::string>() + "\\Parameters";
    auto serviceDll = readRegistryValue(HKEY_LOCAL_MACHINE, regPath, "ServiceDll");
    if (serviceDll.has_value()) {
        auto expanded = expandEnvString(serviceDll.value());
        item["module_path"] = expanded.value_or(serviceDll.value());
    }

    results.push_back(item);
    CloseServiceHandle(svcHandle);
    return true;
}

nlohmann::json ServicesProvider::collect() {

    json results = json::array();

    auto scmHandle = OpenSCManager(nullptr, nullptr, GENERIC_READ);

    if (!scmHandle) {
        std::cerr << "Failed to connect to Service Connection Manager: " << GetLastError() << "\n";
        return results;
    }

    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    EnumServicesStatusEx(scmHandle, SC_ENUM_PROCESS_INFO,
                         SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                         nullptr, 0, &bytesNeeded, &serviceCount,
                         nullptr, nullptr);

    if (GetLastError() != ERROR_MORE_DATA) {
        std::cerr << "Error querying buffer size: " << GetLastError() << "\n";
        CloseServiceHandle(scmHandle);
        return results;
    }

    auto buffer = std::make_unique<BYTE[]>(bytesNeeded);
    auto services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buffer.get());

    if (!EnumServicesStatusEx(scmHandle, SC_ENUM_PROCESS_INFO,
                              SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                              buffer.get(), bytesNeeded, &bytesNeeded,
                              &serviceCount, nullptr, nullptr)) {
        std::cerr << "Error enumerating services: " << GetLastError() << "\n";
        CloseServiceHandle(scmHandle);
        return results;
    }

    for (DWORD i = 0; i < serviceCount; ++i) {
        if (!getService(scmHandle, services[i], results)) {
            std::cerr << "Warning: Failed to get details for service\n";
        }
    }

    CloseServiceHandle(scmHandle);
    return results;
}
