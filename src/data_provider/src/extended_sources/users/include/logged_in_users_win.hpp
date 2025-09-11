/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <map>
#include <memory>
#include <string>

#include "json.hpp"

#include "iusers_utils_wrapper.hpp"
#include "iwinapi_wrappers.hpp"

/// LoggedInUsersProvider class
/// This class is responsible for collecting information about logged-in users on a Windows system.
class LoggedInUsersProvider
{
    public:
        /// @brief Constructor
        /// @param twsWrapper A shared pointer to an ITWSapiWrapper object.
        /// @param winBaseWrapper A shared pointer to an IWinBaseApiWrapper object.
        /// @param winSddlWrapper A shared pointer to an IWinSDDLWrapper object.
        /// @param winSecurityWrapper A shared pointer to an IWinSecurityBaseApiWrapper object.
        explicit LoggedInUsersProvider(std::shared_ptr<ITWSapiWrapper> twsWrapper,
                                       std::shared_ptr<IWinBaseApiWrapper> winBaseWrapper, std::shared_ptr<IWinSDDLWrapper> winSddlWrapper,
                                       std::shared_ptr<IWinSecurityBaseApiWrapper> winSecurityWrapper,
                                       std::shared_ptr<IUsersHelper> usersHelperWrapper);

        /// @brief Default constructor
        LoggedInUsersProvider();

        /// @brief collect
        /// @return A JSON object containing the information about logged-in users.
        nlohmann::json collect();

    private:
        /// twsWrapper A shared pointer to an ITWSapiWrapper object.
        std::shared_ptr<ITWSapiWrapper> m_twsApiWrapper;

        /// winBaseWrapper A shared pointer to an IWinBaseApiWrapper object.
        std::shared_ptr<IWinBaseApiWrapper> m_winBaseWrapper;

        /// winSddlWrapper A shared pointer to an IWinSDDLWrapper object.
        std::shared_ptr<IWinSDDLWrapper> m_winSddlWrapper;

        /// winSecurityWrapper A shared pointer to an IWinSecurityBaseApiWrapper object.
        std::shared_ptr<IWinSecurityBaseApiWrapper> m_winSecurityWrapper;

        /// usersHelperWrapper A shared pointer to an IUsersHelper object.
        std::shared_ptr<IUsersHelper> m_usersHelpersWrapper;

        /// @brief Get the session state as a string.
        static const std::map<int, std::string> m_kSessionStates;

        /// @brief Convert FILETIME to Unix time.
        /// @param fileTime The FILETIME to convert.
        /// @return The Unix time as an unsigned long long.
        unsigned long long filetimeToUnixtime(const FILETIME& fileTime);
};
