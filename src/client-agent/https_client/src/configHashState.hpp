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

#ifndef _HC_CONFIG_HASH_STATE_HPP
#define _HC_CONFIG_HASH_STATE_HPP

#include <mutex>
#include <string>

/**
 * @brief The module's view of the local merged-config hash.
 *
 * Compared against the manager-reported agent.config_hash on every Notify.
 * Updated optimistically after a verified download is delivered; corrected by
 * the consumer through hc_set_config_hash() when applying fails or lands on a
 * different result. Guarded: written from the control thread and from the C
 * ABI (any thread, including inside callbacks).
 */
class ConfigHashState final
{
    public:
        explicit ConfigHashState(std::string initial)
            : m_hash(std::move(initial))
        {
        }

        std::string get() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_hash;
        }

        void set(const std::string& hash)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_hash = hash;
        }

    private:
        mutable std::mutex m_mutex;
        std::string m_hash;
};

#endif // _HC_CONFIG_HASH_STATE_HPP
