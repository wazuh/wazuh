/*
 * Wazuh container_instances — consumer side of the lifecycle notification
 * channel (#37532 / #37203).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * A consumer binds one of these and adds its fd to whatever it already waits
 * on, so a container appearing or leaving wakes it immediately instead of at
 * its next scheduled poll.
 *
 * The datagram is a HINT AND NOTHING MORE. It is not read for content, not
 * acknowledged, and not required to arrive: everything the consumer acts on is
 * read afterwards from the query socket. That is what makes an unreliable
 * transport the right one here — a lost datagram costs latency until the next
 * periodic read, which every consumer keeps regardless.
 *
 * So the correct shape of a consumer loop is:
 *
 *     poll({notify.fd(), stopFd}, timeoutUntilNextPeriodicRead)
 *     notify.drain();     // discard; the payload is not authority
 *     refreshFromTheQuerySocket();
 *
 * drain() exists because a burst of changes produces a burst of datagrams and
 * they should collapse into one read, not one read each.
 */

#ifndef _CONTAINER_INSTANCES_NOTIFY_SOCKET_HPP
#define _CONTAINER_INSTANCES_NOTIFY_SOCKET_HPP

#include <cerrno>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace wazuh::container_instances_client
{

    class NotifySocket final
    {
        public:
            NotifySocket() = default;

            ~NotifySocket()
            {
                close();
            }

            NotifySocket(const NotifySocket&) = delete;
            NotifySocket& operator=(const NotifySocket&) = delete;
            NotifySocket(NotifySocket&&) = delete;
            NotifySocket& operator=(NotifySocket&&) = delete;

            /// Binds `path`, replacing a stale socket file left by a previous
            /// run. Returns false on any failure, which callers treat as "no
            /// notifications" rather than an error: the periodic read still
            /// covers everything, so refusing to start over this would turn a
            /// latency optimisation into an outage.
            [[nodiscard]] bool bind(const std::string& path)
            {
                close();

                if (path.empty())
                {
                    return false;
                }

                sockaddr_un address {};
                address.sun_family = AF_UNIX;

                if (path.size() >= sizeof(address.sun_path))
                {
                    return false;
                }
                std::memcpy(address.sun_path, path.c_str(), path.size());

                m_fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                if (m_fd < 0)
                {
                    return false;
                }

                // A socket file outlives the process that bound it, so a crash
                // or a kill -9 leaves one behind and bind() would fail with
                // EADDRINUSE forever after. Nothing else may be listening on it:
                // this path belongs to this daemon alone.
                ::unlink(path.c_str());

                if (::bind(m_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
                {
                    close();
                    return false;
                }

                // The sender runs as the same user; keep it off-limits to others
                // rather than inheriting whatever umask happened to be set.
                ::chmod(path.c_str(), 0660);

                m_path = path;
                return true;
            }

            /// -1 when not bound, which poll() treats as "ignore this entry" —
            /// so a consumer needs no branch for the unbound case.
            [[nodiscard]] int fd() const
            {
                return m_fd;
            }

            /// Discards every queued datagram. Returns how many were waiting,
            /// which is useful for diagnostics and for nothing else — the
            /// contents are deliberately not parsed, because acting on them
            /// would make a hint into authority.
            int drain()
            {
                if (m_fd < 0)
                {
                    return 0;
                }

                int drained = 0;
                char scratch[256];

                while (::recv(m_fd, scratch, sizeof(scratch), MSG_DONTWAIT) >= 0)
                {
                    ++drained;
                }

                return drained;
            }

            void close()
            {
                if (m_fd >= 0)
                {
                    ::close(m_fd);
                    m_fd = -1;
                }
                if (!m_path.empty())
                {
                    ::unlink(m_path.c_str());
                    m_path.clear();
                }
            }

        private:
            int m_fd {-1};
            std::string m_path;
    };

} // namespace wazuh::container_instances_client

#endif // _CONTAINER_INSTANCES_NOTIFY_SOCKET_HPP
