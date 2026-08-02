/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_SOCKET_PATH_CHECK_HPP
#define _INVSYNC_COMMON_SOCKET_PATH_CHECK_HPP

#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

namespace invsync::common
{
    /**
     * @brief Checks the things that would make binding a UDS impossible, WITHOUT binding it.
     *
     * Used by the facade's start() so an unusable socket path is fatal at daemon startup instead of an
     * ERROR repeated every 60 s forever while modulesd runs on looking healthy with no inventory
     * ingress. The actual bind stays where it is -- after the indexer startup gate -- because opening
     * the socket before the indexer objects are built is precisely what that gate exists to prevent,
     * and moving it earlier would break that ordering.
     *
     * Only conditions nothing can fix at runtime are checked, which is what makes failing them fatal
     * rather than retryable: the `sun_path` length cap, a non-socket file already sitting at the path,
     * and a missing or unwritable parent directory. A stale SOCKET at the path is fine -- bindAcceptor()
     * unlinks that. A bind that still fails afterwards for some other reason keeps the retry loop.
     *
     * A free function in its own header rather than a facade method deliberately: it has no state, and
     * the facade's header pulls in loggerHelper.h, whose log sink has hidden ELF visibility and so
     * cannot be linked from the test binary.
     *
     * @param socketPath The resolved path.
     * @param reason     Set to an operator-readable explanation when the result is false.
     * @return true when a bind could plausibly succeed.
     */
    inline bool socketPathIsUsable(const std::string& socketPath, std::string& reason)
    {
        constexpr std::size_t SUN_PATH_MAX {sizeof(::sockaddr_un::sun_path)};

        if (socketPath.empty())
        {
            reason = "the resolved socket path is empty";
            return false;
        }

        if (socketPath.size() >= SUN_PATH_MAX)
        {
            reason = "it is " + std::to_string(socketPath.size()) + " characters, over the " +
                     std::to_string(SUN_PATH_MAX - 1) + "-character limit for Unix domain sockets";
            return false;
        }

        struct stat existing {};
        if (::stat(socketPath.c_str(), &existing) == 0 && !S_ISSOCK(existing.st_mode))
        {
            reason = "a file that is not a socket already exists there, and it will not be removed";
            return false;
        }

        const auto slash = socketPath.find_last_of('/');
        const std::string parent = (slash == std::string::npos) ? std::string {"."} : socketPath.substr(0, slash);

        struct stat parentStat {};
        if (::stat(parent.c_str(), &parentStat) != 0 || !S_ISDIR(parentStat.st_mode))
        {
            reason = "its parent directory '" + parent + "' does not exist";
            return false;
        }

        if (::access(parent.c_str(), W_OK) != 0)
        {
            reason = "its parent directory '" + parent + "' is not writable";
            return false;
        }

        return true;
    }
} // namespace invsync::common

#endif // _INVSYNC_COMMON_SOCKET_PATH_CHECK_HPP
