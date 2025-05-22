#pragma once

#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <aclapi.h>

#include <locale>
#include <codecvt>

#include <map>
#include <string>
#include <vector>
#include <memory>
#include <set>
#include <optional>

#include "json.hpp"
#include "iusers_windows_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"

template <typename T>
class NetApiObjectPtr final
{
    public:
        NetApiObjectPtr() noexcept = default;
        NetApiObjectPtr(NetApiObjectPtr<T>&& other) noexcept
            : pointer(std::exchange(other.pointer, nullptr)) {}

        ~NetApiObjectPtr()
        {
            if (pointer != nullptr)
            {
                NetApiBufferFree(pointer);
            }
        }

        NetApiObjectPtr& operator=(NetApiObjectPtr<T>&& other) noexcept
        {
            if (this != &other)
            {
                pointer = std::exchange(other.pointer, nullptr);
            }

            return *this;
        }

        NetApiObjectPtr(const NetApiObjectPtr<T>&) = delete;
        NetApiObjectPtr& operator=(const NetApiObjectPtr<T>&) = delete;

        T* operator->()
        {
            return pointer;
        }

        bool operator==(const T* other) const
        {
            return pointer == other;
        }

        bool operator!=(const T* other) const
        {
            return pointer != other;
        }

        T** get_new_ptr()
        {
            // We ensure that the pointer cannot be leaked
            if (pointer != nullptr)
            {
                NetApiBufferFree(pointer);
                pointer = nullptr;
            }

            return &pointer;
        }

        const T* get() const
        {
            return pointer;
        }

    private:
        T* pointer{nullptr};
};

using user_info_0_ptr = NetApiObjectPtr<USER_INFO_0>;
using user_info_2_ptr = NetApiObjectPtr<USER_INFO_2>;
using user_info_3_ptr = NetApiObjectPtr<USER_INFO_3>;
using user_info_4_ptr = NetApiObjectPtr<USER_INFO_4>;
using localgroup_users_info_0_ptr = NetApiObjectPtr<LOCALGROUP_USERS_INFO_0>;

const std::wstring kRegProfileKey =
    L"SOFTWARE\\Microsoft\\Windows "
    "NT\\CurrentVersion\\ProfileList";
const std::set<std::string> kWellKnownSids =
{
    "S-1-5-1",
    "S-1-5-2",
    "S-1-5-3",
    "S-1-5-4",
    "S-1-5-6",
    "S-1-5-7",
    "S-1-5-8",
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-12",
    "S-1-5-13",
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-21",
    "S-1-5-32",
};
const std::wstring kProfileValueName = L"ProfileImagePath";
const wchar_t kRegSep = '\\';

const std::set<int> kRegistryStringTypes =
{
    REG_SZ, REG_MULTI_SZ, REG_EXPAND_SZ
};

class UsersHelper : public IUsersHelper
{
    private:
        std::string psidToString(PSID sid);
        std::string wstringToString(const wchar_t* src);
        std::wstring stringToWstring(const std::string& src);
        std::string getUserHomeDir(const std::string& sid);
        std::optional<std::uint32_t> getGidFromUsername(LPCWSTR username);
        std::unique_ptr<BYTE[]> getSidFromAccountName(LPCWSTR account_name);
        std::optional<std::vector<std::string>> getRoamingProfileSids();
        DWORD getRidFromSid(PSID sid);

        std::shared_ptr<IWindowsApiWrapper> m_winapiWrapper;

        auto makeRegHandleDeleter()
        {
            return [this](HKEY handle)
            {
                m_winapiWrapper->RegCloseKeyWrapper(handle);
            };
        }
        using reg_handle_t = std::unique_ptr<HKEY__, std::function<void(HKEY)>>;

    public:
        explicit UsersHelper(
            std::shared_ptr<IWindowsApiWrapper> winapiWrapper);

        UsersHelper();

        std::string getUserShell(const std::string& sid) override;
        std::vector<User> processLocalAccounts(std::set<std::string>& processed_sids) override;
        std::vector<User> processRoamingProfiles(std::set<std::string>& processed_sids) override;
};
