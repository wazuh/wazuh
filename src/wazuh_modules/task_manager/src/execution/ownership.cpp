/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ownership.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace
{
    /// @brief Field number of `starttime` in /proc/<pid>/stat, counting from one.
    constexpr int STARTTIME_FIELD {22};

    /// @brief `state` is the first field after comm, so it is field 3.
    constexpr int STATE_FIELD {3};
} // namespace

namespace task_manager::execution
{
    std::string OwnerIdentity::toString() const
    {
        return std::to_string(pid) + ':' + std::to_string(startTime) + ":w" + std::to_string(workerIndex);
    }

    std::uint64_t processStartTime(const std::int32_t pid)
    {
        std::ifstream stat {"/proc/" + std::to_string(pid) + "/stat"};
        if (!stat.is_open())
        {
            return 0;
        }

        std::string line;
        if (!std::getline(stat, line))
        {
            return 0;
        }

        // The comm field is parenthesised and may itself contain spaces AND parentheses, so
        // splitting the whole line on whitespace is wrong. Scan to the LAST ')' and start counting
        // fields after it -- the next token is `state`, field 3.
        const auto commEnd {line.rfind(')')};
        if (commEnd == std::string::npos)
        {
            return 0;
        }

        std::istringstream fields {line.substr(commEnd + 1)};
        std::string token;
        for (int field = STATE_FIELD; field <= STARTTIME_FIELD; ++field)
        {
            if (!(fields >> token))
            {
                return 0;
            }

            if (field == STARTTIME_FIELD)
            {
                try
                {
                    return std::stoull(token);
                }
                catch (const std::exception&)
                {
                    return 0;
                }
            }
        }

        return 0;
    }

    OwnerIdentity selfIdentity(const int workerIndex)
    {
        OwnerIdentity identity;
        identity.pid = static_cast<std::int32_t>(::getpid());
        identity.startTime = processStartTime(identity.pid);
        identity.workerIndex = workerIndex;
        return identity;
    }

    std::optional<OwnerIdentity> parseOwner(const std::string_view owner)
    {
        // "<pid>:<starttime>:w<index>"
        const auto firstColon {owner.find(':')};
        if (firstColon == std::string_view::npos)
        {
            return std::nullopt;
        }

        const auto secondColon {owner.find(':', firstColon + 1)};
        if (secondColon == std::string_view::npos)
        {
            return std::nullopt;
        }

        const auto workerPart {owner.substr(secondColon + 1)};
        if (workerPart.size() < 2 || workerPart.front() != 'w')
        {
            return std::nullopt;
        }

        try
        {
            OwnerIdentity identity;
            identity.pid = static_cast<std::int32_t>(std::stol(std::string {owner.substr(0, firstColon)}));
            identity.startTime =
                std::stoull(std::string {owner.substr(firstColon + 1, secondColon - firstColon - 1)});
            identity.workerIndex = std::stoi(std::string {workerPart.substr(1)});
            return identity;
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
    }

    OwnerKind classifyOwner(const std::string_view owner, const OwnerIdentity& self)
    {
        const auto parsed {parseOwner(owner)};
        if (!parsed.has_value())
        {
            return OwnerKind::Unparseable;
        }

        if (parsed->sameProcess(self))
        {
            return OwnerKind::Mine;
        }

        // Reading the start time answers both questions at once: zero means the process is gone,
        // and a different value means the pid has been reused by something else entirely.
        if (processStartTime(parsed->pid) != parsed->startTime)
        {
            return OwnerKind::Dead;
        }

        return OwnerKind::Foreign;
    }

    bool isReclaimable(const ReclaimQuery& query, const OwnerIdentity& self)
    {
        switch (classifyOwner(query.owner, self))
        {
            case OwnerKind::Dead:
                return true;

            case OwnerKind::Unparseable:
                return true;

            case OwnerKind::Foreign:
                return false;

            case OwnerKind::Mine:
                // Both terms, in this order. A worker that says it is running this row IS running
                // it, however long it has been; what bounds that is the per-call deadline, not the
                // sweep. Reclaiming it would flip the row to pending while the handler still runs.
                if (!query.workerInflightTaskId.empty() && query.workerInflightTaskId == query.rowTaskId)
                {
                    return false;
                }

                return (query.now - query.claimTime) > query.claimGrace.count();
        }

        return false;
    }
} // namespace task_manager::execution
