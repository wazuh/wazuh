#pragma once

#include <map>
#include <memory>
#include <string>

#include "json.hpp"

#include "itwsapi_wrapper.hpp"

class LoggedInUsersProvider
{
    public:
        explicit LoggedInUsersProvider(std::shared_ptr<ITWSapiWrapper> twsApiWrapper);

        LoggedInUsersProvider();

        nlohmann::json collect();

    private:
        std::shared_ptr<ITWSapiWrapper> m_twsApiWrapper;

        static const std::map<int, std::string> m_kSessionStates;

        unsigned long long filetimeToUnixtime(const FILETIME& fileTime);

        std::unique_ptr<BYTE[]> getSidFromAccountName(const std::wstring& account_name_input);

        std::string psidToString(PSID sid);
};
