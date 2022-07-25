/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 4, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/


#ifndef _REGISTRATIONCONTROLLER_HPP
#define _REGISTRATIONCONTROLLER_HPP


#include "commonDefs.h"
#include <map>
#include <shared_mutex>
#include <string>


class RegistrationController final
{
    private:
        std::map<std::string, RSYNC_HANDLE> m_componentStatus;
        std::shared_timed_mutex m_mutex;

    public:
        RegistrationController() = default;
        // LCOV_EXCL_START
        virtual ~RegistrationController() = default;
        // LCOV_EXCL_STOP

        void initComponentByHandle(const RSYNC_HANDLE handle,
                                   const std::string& component)
        {
            std::lock_guard<std::shared_timed_mutex> lock(m_mutex);
            m_componentStatus[component] = handle;
        }

        void removeComponentByHandle(const RSYNC_HANDLE handle)
        {
            std::lock_guard<std::shared_timed_mutex> lock(m_mutex);
            auto it { m_componentStatus.begin() };

            while (it != m_componentStatus.end())
            {
                if (it->second == handle)
                {
                    it = m_componentStatus.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        bool isComponentRegistered(const std::string& component)
        {
            std::shared_lock<std::shared_timed_mutex> lock(m_mutex);
            return m_componentStatus.find(component) != m_componentStatus.end();
        }
};


#endif //_REGISTRATIONCONTROLLER_HPP
