#pragma once

#include <map>
#include <memory>
#include <string>

#include "json.hpp"

#include "iwinapi_wrappers.hpp"

class LoggedInUsersProvider
{
    public:
        explicit LoggedInUsersProvider(std::shared_ptr<ITWSapiWrapper> twsWrapper,
            std::shared_ptr<IWinBaseApiWrapper> winBaseWrapper, std::shared_ptr<IWinSDDLWrapper> winSddlWrapper,
            std::shared_ptr<IWinSecurityBaseApiWrapper> winSecurityWrapper);

        LoggedInUsersProvider();

        nlohmann::json collect();

    private:
        std::shared_ptr<ITWSapiWrapper> m_twsApiWrapper;
        std::shared_ptr<IWinBaseApiWrapper> m_winBaseWrapper;
        std::shared_ptr<IWinSDDLWrapper> m_winSddlWrapper;
        std::shared_ptr<IWinSecurityBaseApiWrapper> m_winSecurityWrapper;

        static const std::map<int, std::string> m_kSessionStates;

        unsigned long long filetimeToUnixtime(const FILETIME& fileTime);

        std::unique_ptr<BYTE[]> getSidFromAccountName(const std::wstring& account_name_input);

        std::string psidToString(PSID sid);
};
