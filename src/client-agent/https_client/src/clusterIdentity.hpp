/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CLUSTER_IDENTITY_HPP
#define _HC_CLUSTER_IDENTITY_HPP

#include <mutex>
#include <string>
#include <utility>

/**
 * @brief The manager-authoritative cluster name (#37733, 2026-07-21).
 *
 * Overwritten from every /control startup response (including with an
 * empty/unknown value, so a stale local value never lingers). Read by the
 * periodic /stats and /config reporter, which stamps it into the documents
 * the manager indexes. Written by the control thread, read by the reporter
 * thread — hence guarded.
 */
class ClusterIdentity final
{
    public:
        struct Snapshot
        {
            std::string name;
        };

        void set(std::string name)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_value.name = std::move(name);
        }

        Snapshot get() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_value;
        }

    private:
        mutable std::mutex m_mutex;
        Snapshot m_value;
};

#endif // _HC_CLUSTER_IDENTITY_HPP
