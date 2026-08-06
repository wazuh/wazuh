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

#ifndef _HC_COLLECTOR_SOURCE_HPP
#define _HC_COLLECTOR_SOURCE_HPP

#include "https_client.h"

#include <cstdlib>
#include <optional>
#include <string>

/**
 * @brief Where the reporter pulls the /stats and /config snapshots. Injected
 *        so the reporter can be unit-tested without C callbacks.
 */
class ICollectorSource
{
    public:
        virtual ~ICollectorSource() = default;
        virtual std::optional<std::string> collectStats() = 0;
        virtual std::optional<std::string> collectConfig() = 0;
};

/**
 * @brief Production source: calls the C collect_* callbacks directly (NOT via
 *        the dispatcher — they return a value synchronously) and adopts the
 *        malloc'd string they return, freeing it after copying.
 */
class CallbackCollectorSource final : public ICollectorSource
{
    public:
        explicit CallbackCollectorSource(const hc_callbacks_t& callbacks)
            : m_callbacks(callbacks)
        {
        }

        std::optional<std::string> collectStats() override
        {
            return invoke(m_callbacks.collect_stats);
        }

        std::optional<std::string> collectConfig() override
        {
            return invoke(m_callbacks.collect_config);
        }

    private:
        std::optional<std::string> invoke(char* (*collector)(void*)) const
        {
            if (collector == nullptr)
            {
                return std::nullopt;
            }

            char* raw = collector(m_callbacks.user_data);

            if (raw == nullptr)
            {
                return std::nullopt; // The collector chose to skip this cycle.
            }

            std::string document {raw};
            std::free(raw); // Module owns the buffer; free after copying.
            return document;
        }

        hc_callbacks_t m_callbacks;
};

#endif // _HC_COLLECTOR_SOURCE_HPP
