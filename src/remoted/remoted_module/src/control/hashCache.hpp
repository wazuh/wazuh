/*
 * Wazuh remoted module - Hash cache
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_HASH_CACHE_HPP
#define _REMOTED_CONTROL_HASH_CACHE_HPP

#include "controlConfig.hpp"
#include <memory>
#include <string>

namespace remoted::control
{
    class HashCache
    {
    public:
        explicit HashCache(const Config& config);
        ~HashCache();

        /**
         * Resolve the absolute path of the merged.mg file for a group set.
         * @param groupsCsv Raw comma-separated group list, in the order returned
         *                  by wdb's `select-agent-group`. No URL-encoding.
         * @return The resolved merged.mg path, or an empty string on invalid input.
         */
        std::string getMergedMgPath(const std::string& groupsCsv) const;

        /**
         * Cached SHA-256 of the manager's static settings (limits + cluster).
         * Computed once per process, cached forever — does not depend on any
         * per-agent state (in particular, not on the agent's group set).
         */
        std::string getSettingsHash();

        /**
         * Cached SHA-256 of the merged.mg at @p mergedMgPath.
         * Returns an empty string on error or when @p mergedMgPath is empty.
         */
        std::string getConfigHash(const std::string& mergedMgPath);

        void invalidateConfigHash(const std::string& mergedMgPath);

        void stop();

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_HASH_CACHE_HPP
