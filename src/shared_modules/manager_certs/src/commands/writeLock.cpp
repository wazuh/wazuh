/*
 * Wazuh manager certs tool - the CA bundle write lock
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "writeLock.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>
#include <utility>

namespace manager_certs
{
    namespace
    {
        /// The lock file is opened exactly the same way twice (once to lock it, once to prove it is
        /// still the same file), so the flags live in one place.
        constexpr int kLockFlags = O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC;
        constexpr mode_t kLockMode = 0600;

        std::string errnoText(int error)
        {
            return std::generic_category().message(error);
        }
    } // namespace

    BundleWriteLock::BundleWriteLock(int fd, LockIo io)
        : m_fd {fd}
        , m_io {std::move(io)}
    {
    }

    BundleWriteLock::BundleWriteLock(BundleWriteLock&& other)
        : m_fd {other.m_fd}
        , m_io {std::move(other.m_io)}
    {
        other.m_fd = -1;
    }

    BundleWriteLock& BundleWriteLock::operator=(BundleWriteLock&& other)
    {
        if (this != &other)
        {
            std::swap(m_fd, other.m_fd);
            std::swap(m_io, other.m_io);
        }
        return *this;
    }

    BundleWriteLock::~BundleWriteLock()
    {
        if (m_fd >= 0)
        {
            // Unlocking explicitly rather than relying on close(2) alone: the descriptor is the only
            // one this process holds on that inode, so both do the same thing, but a future caller
            // that duplicates it would find the intent written down.
            if (m_io.flock)
            {
                m_io.flock(m_fd, LOCK_UN);
            }
            else
            {
                ::flock(m_fd, LOCK_UN);
            }
            ::close(m_fd);
            m_fd = -1;
        }
    }

    int BundleWriteLock::fd() const noexcept
    {
        return m_fd;
    }

    LockAcquisition
    BundleWriteLock::acquire(int directoryFd, const std::string& name, const std::string& displayPath, LockIo io)
    {
        LockAcquisition outcome;

        const int fd = ::openat(directoryFd, name.c_str(), kLockFlags, kLockMode);
        if (fd < 0)
        {
            outcome.error = errno;
            outcome.message = outcome.error == ELOOP ? "lock path is a symlink: " + displayPath
                                                     : "cannot open the lock file at " + displayPath + " (" +
                                                           errnoText(outcome.error) + ")";
            return outcome;
        }

        struct stat attributes {};
        if (::fstat(fd, &attributes) != 0)
        {
            outcome.error = errno;
            outcome.message = "cannot stat the lock file at " + displayPath + " (" + errnoText(outcome.error) + ")";
            ::close(fd);
            return outcome;
        }

        // A regular file owned by root, on the descriptor -- not a stat(2) of the path, which
        // another process could swap under us between the two calls. The directory being
        // root-owned is not enough: mode 1770 lets the manager's group create files in it.
        if (!S_ISREG(attributes.st_mode) || attributes.st_uid != 0)
        {
            outcome.message = "lock file at " + displayPath + " is not a root-owned regular file";
            ::close(fd);
            return outcome;
        }

        const auto lockCall = [&io](int descriptor, int operation)
        {
            return io.flock ? io.flock(descriptor, operation) : ::flock(descriptor, operation);
        };

        // Blocking on purpose: a second writer waits its turn instead of failing, which is what an
        // operator running two commands back to back expects. EINTR is not a refusal.
        while (lockCall(fd, LOCK_EX) != 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            outcome.error = errno;
            outcome.message = "cannot lock " + displayPath + " (" + errnoText(outcome.error) + ")";
            ::close(fd);
            return outcome;
        }

        // We may have waited a long time for that lock. If the file at the path is no longer the
        // inode we locked, whoever replaced it is being excluded by nothing at all, and the next
        // process to arrive would lock the NEW inode and write beside us.
        const int check = ::openat(directoryFd, name.c_str(), kLockFlags, kLockMode);
        struct stat current {};
        const bool sameFile = check >= 0 && ::fstat(check, &current) == 0 && current.st_dev == attributes.st_dev &&
                              current.st_ino == attributes.st_ino;
        const int checkError = check < 0 ? errno : 0;
        if (check >= 0)
        {
            ::close(check);
        }

        if (!sameFile)
        {
            outcome.error = checkError;
            outcome.message = "lock file identity changed while waiting: " + displayPath;
            lockCall(fd, LOCK_UN);
            ::close(fd);
            return outcome;
        }

        outcome.lock = BundleWriteLock {fd, std::move(io)};
        return outcome;
    }

} // namespace manager_certs
