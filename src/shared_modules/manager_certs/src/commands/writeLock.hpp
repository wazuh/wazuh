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

#ifndef _MANAGER_CERTS_WRITE_LOCK_HPP
#define _MANAGER_CERTS_WRITE_LOCK_HPP

/**
 * @file writeLock.hpp
 * @brief The exclusive lock every writing command of `wazuh-manager-certs` holds over the whole
 *        read -> validate -> write transaction (C34f).
 *
 * Two root processes publishing at the same time is not a theoretical race: both read the same
 * bundle, both build a candidate from it, and the second `rename` wins -- so one operator's CA
 * silently disappears from a file the whole fleet trusts. `flock(LOCK_EX)` over a lock file beside
 * the bundle serialises them, and the kernel drops the lock if a writer dies, so a crash cannot
 * leave the next run locked out.
 *
 * The lock file's path is DERIVED from the configured bundle path (`<bundle>.lock`), never from a
 * literal `etc/certs/root-ca.pem` (C36a): the bundle is an operator-configurable path and the lock
 * has to sit beside whatever that turns out to be. Everything here is done through the directory
 * descriptor the caller already holds, so nothing re-resolves the path by name halfway through.
 *
 * Two properties beyond "take a lock" (C36f), both of them attacks the certs directory makes
 * possible -- it is `1770 root:<group>` (src/init/inst-functions.sh:228-240), so a member of the
 * manager's group can create files in it, and the sticky bit only stops them removing OURS:
 *   - the lock file is opened `O_NOFOLLOW` and has to be a root-owned regular file, so a symlink or
 *     a file planted by another user is refused instead of becoming the thing we synchronise on;
 *   - after `flock()` returns, the path is opened again and its `(st_dev, st_ino)` compared with the
 *     descriptor we locked: if somebody replaced the lock file while we were blocked, two writers
 *     would be holding locks on DIFFERENT inodes and neither would exclude the other.
 */

#include "manager_certs/commands.hpp" // LockIo

#include <optional>
#include <string>

namespace manager_certs
{
    /// What BundleWriteLock::acquire() produced: the held lock, or why there is none. Outside the
    /// class because it holds one by value, and a class is not complete inside its own definition.
    struct LockAcquisition;

    /**
     * @brief An acquired `flock(LOCK_EX)` on the bundle's lock file, released on destruction.
     *
     * Move-only, and only ever produced by acquire(): an object of this type existing IS the
     * guarantee that this process holds the lock on the inode it validated.
     */
    class BundleWriteLock final
    {
    public:
        /**
         * @brief Opens @p name inside @p directoryFd, validates it and blocks until it is locked.
         *
         * @param directoryFd Descriptor of the bundle's own directory (the caller keeps owning it).
         * @param name        Lock file name inside that directory (`<bundle basename>.lock`).
         * @param displayPath The same file's full path, for the diagnostics an operator reads.
         * @param io          Test seam for `flock(2)`; empty means the real call.
         */
        static LockAcquisition
        acquire(int directoryFd, const std::string& name, const std::string& displayPath, LockIo io = {});

        BundleWriteLock(BundleWriteLock&& other);
        BundleWriteLock& operator=(BundleWriteLock&& other);
        BundleWriteLock(const BundleWriteLock&) = delete;
        BundleWriteLock& operator=(const BundleWriteLock&) = delete;

        /// `flock(LOCK_UN)` + `close()`. The kernel would do both anyway if the process died here.
        ~BundleWriteLock();

        /// The locked descriptor, or -1 in a moved-from object. Nothing outside the tests needs it.
        int fd() const noexcept;

    private:
        BundleWriteLock(int fd, LockIo io);

        int m_fd {-1};
        LockIo m_io {};
    };

    struct LockAcquisition
    {
        std::optional<BundleWriteLock> lock; ///< Engaged only on success.
        std::string message;                 ///< Operator-facing cause; empty on success.
        int error {0};                       ///< errno of the refusing call, 0 when there was none.
    };

} // namespace manager_certs

#endif // _MANAGER_CERTS_WRITE_LOCK_HPP
