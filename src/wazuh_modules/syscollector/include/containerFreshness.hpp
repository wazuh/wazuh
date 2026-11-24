/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_FRESHNESS_HPP
#define _CONTAINER_FRESHNESS_HPP

#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

/// The locks a package manager holds while it writes its database. Readers do
/// not take them, so opening one marks the start of a write by that process.
inline const std::vector<std::string>& packageLockPaths()
{
    static const std::vector<std::string> paths
    {
        // Held for a whole apt or `dpkg -i` transaction. Not `lock`: apt's
        // dpkg runs take only that one, and a walk after each run would read
        // the transaction half done.
        "/var/lib/dpkg/lock-frontend",
        "/lib/apk/db/lock",
        "/var/lib/rpm/.rpm.lock",
        "/usr/lib/sysimage/rpm/.rpm.lock",
    };
    return paths;
}

/// Their file names, for the kernel's name filter.
inline const std::vector<std::string>& packageLockNames()
{
    static const std::vector<std::string> names {"lock", "lock-frontend", ".rpm.lock"};
    return names;
}

/// Whether an event at `path`, inside a container, is on a package lock.
/// Exact: the kernel filters on the bare name, which other files share.
[[nodiscard]] inline bool isPackageLockPath(const std::string& path)
{
    // An image where /lib links to usr/lib reports the resolved path.
    if (path == "/usr/lib/apk/db/lock")
    {
        return true;
    }

    for (const auto& lock : packageLockPaths())
    {
        if (path == lock)
        {
            return true;
        }
    }

    return false;
}

/// The start time, in clock ticks since boot, from a /proc/<pid>/stat line;
/// nothing when the process has exited (zombie or dead) or the line does not
/// parse.
[[nodiscard]] inline std::optional<std::uint64_t> parseProcStartTime(const std::string& line)
{
    // comm is parenthesised and may hold spaces and parentheses itself.
    const auto commEnd = line.rfind(')');

    if (commEnd == std::string::npos)
    {
        return std::nullopt;
    }

    std::istringstream fields {line.substr(commEnd + 1)};
    std::string token;

    // Field 3 is the state, field 22 the start time.
    for (int field = 3; field <= 22; ++field)
    {
        if (!(fields >> token))
        {
            return std::nullopt;
        }

        if (field == 3 && (token == "Z" || token == "X"))
        {
            return std::nullopt;
        }
    }

    try
    {
        return std::stoull(token);
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
}

/// A running process's start time; nothing when it is gone.
[[nodiscard]] inline std::optional<std::uint64_t> processStartTime(int pid)
{
    std::ifstream stat {"/proc/" + std::to_string(pid) + "/stat"};
    std::string line;

    if (!std::getline(stat, line))
    {
        return std::nullopt;
    }

    return parseProcStartTime(line);
}

/// Whether a process that started at `startTicks` is younger than an event at
/// `eventNs` (both since boot): its pid was reused after the event's process
/// exited. One tick of slack covers the start time's resolution.
[[nodiscard]] inline bool startedAfter(std::uint64_t startTicks, std::uint64_t ticksPerSecond, std::uint64_t eventNs)
{
    if (ticksPerSecond == 0)
    {
        return false;
    }

    const std::uint64_t tickNs = 1000000000ULL / ticksPerSecond;
    return startTicks * tickNs > eventNs + tickNs;
}

/// Which processes hold each container's package lock, and when the container
/// is due a refresh: when one of them exits, its transaction complete. A holder
/// that never exits holds back no other transaction. A container reported
/// changed without a lock event (events lost, or a container seen only after
/// it started writing) is due at once. Liveness is passed in.
class LockHolders
{
    public:
        using Clock = std::chrono::steady_clock;
        using IsAlive = std::function<bool(int pid, std::uint64_t startTime)>;
        using IsAdmitted = std::function<bool(const std::string& containerId)>;

        /// A process opened one of the container's package locks. No start
        /// time means it has already exited, its transaction complete.
        void note(const std::string& containerId, int pid, std::optional<std::uint64_t> startTime)
        {
            auto& entry = m_entries[containerId];

            if (!startTime)
            {
                entry.due = true;
                return;
            }

            entry.holders.insert({pid, *startTime});
        }

        void markChanged(const std::string& containerId)
        {
            m_entries[containerId].now = true;
        }

        /// The containers to refresh now. One `isAdmitted` refuses is dropped:
        /// its refresh would report nothing.
        std::vector<std::string> takeDue(const IsAlive& isAlive, const IsAdmitted& isAdmitted)
        {
            std::vector<std::string> due;

            for (auto it = m_entries.begin(); it != m_entries.end();)
            {
                auto& entry = it->second;

                for (auto holder = entry.holders.begin(); holder != entry.holders.end();)
                {
                    if (isAlive(holder->first, holder->second))
                    {
                        ++holder;
                    }
                    else
                    {
                        entry.due = true;
                        holder = entry.holders.erase(holder);
                    }
                }

                if (entry.now || entry.due)
                {
                    entry.now = false;
                    entry.due = false;

                    if (isAdmitted(it->first))
                    {
                        due.push_back(it->first);
                    }
                }

                if (entry.holders.empty())
                {
                    it = m_entries.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            return due;
        }

        [[nodiscard]] bool hasHolders() const
        {
            for (const auto& entry : m_entries)
            {
                if (!entry.second.holders.empty())
                {
                    return true;
                }
            }

            return false;
        }

        void clear()
        {
            m_entries.clear();
        }

    private:
        struct Entry
        {
            /// Every process holding the lock, by (pid, start time).
            std::set<std::pair<int, std::uint64_t>> holders;
            /// A transaction ended; due on the next take.
            bool                                    due {false};
            /// Due on the next take, whoever holds the lock.
            bool                                    now {false};
        };

        std::map<std::string, Entry> m_entries;
};

#endif // _CONTAINER_FRESHNESS_HPP
