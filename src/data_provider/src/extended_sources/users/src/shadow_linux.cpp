/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include <regex>

#include "shadow_wrapper.hpp"
#include <shadow_linux.hpp>

ShadowProvider::ShadowProvider(std::shared_ptr<IShadowWrapper> shadowWrapper)
    : m_shadowWrapper(std::move(shadowWrapper))
{
}

ShadowProvider::ShadowProvider()
    : m_shadowWrapper(std::make_shared<ShadowWrapper>())
{
}

nlohmann::json ShadowProvider::collect()
{
    nlohmann::json results = nlohmann::json::array();
    struct spwd* shadow_entry;
    const auto kPasswordHashAlgRegex = std::regex("^\\$(\\w+)\\$");

    // Acquire exclusive access to the shadow file
    if (m_shadowWrapper->lckpwdf() == -1)
    {
        //TODO: Logs and Error with "lckpwdf"
        return results;
    }

    // Rewind the shadow file to the beginning
    m_shadowWrapper->setspent();

    // Read the first shadow password entry
    while ((shadow_entry = m_shadowWrapper->getspent()) != NULL)
    {
        nlohmann::json entry;
        entry["last_change"] = shadow_entry->sp_lstchg;
        entry["min"] = shadow_entry->sp_min;
        entry["max"] = shadow_entry->sp_max;
        entry["warning"] = shadow_entry->sp_warn;
        entry["inactive"] = shadow_entry->sp_inact;
        entry["expire"] = shadow_entry->sp_expire;
        entry["username"] = shadow_entry->sp_namp != nullptr ? shadow_entry->sp_namp : "";
        // sp_flag - reserved for future use, won't be added.
        // entry["flag"] = shadow_entry->sp_flag;

        if (shadow_entry->sp_pwdp != nullptr)
        {
            std::string password = std::string(shadow_entry->sp_pwdp);
            std::smatch matches;

            if (password == "!!")
            {
                entry["password_status"] = "not_set";
            }
            else if (password[0] == '!' || password[0] == '*' || password[0] == 'x')
            {
                entry["password_status"] = "locked";
            }
            else if (password.empty())
            {
                entry["password_status"] = "empty";
            }
            else
            {
                entry["password_status"] = "active";
            }

            if (std::regex_search(password, matches, kPasswordHashAlgRegex))
            {
                entry["hash_alg"] = std::string(matches[1]);
            }
        }
        else
        {
            entry["password_status"] = "empty";
        }

        results.push_back(std::move(entry));
    }

    m_shadowWrapper->endspent();

    if (m_shadowWrapper->ulckpwdf() == -1)
    {
        //TODO: Logs and Error with "ulckpwdf"
        return results;
    }

    return results;
}
