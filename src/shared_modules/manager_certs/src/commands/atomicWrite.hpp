/*
 * Wazuh manager certs tool - atomic bundle replacement
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MANAGER_CERTS_ATOMIC_WRITE_HPP
#define _MANAGER_CERTS_ATOMIC_WRITE_HPP

/**
 * @file atomicWrite.hpp
 * @brief Replacing the CA bundle without any reader ever seeing a half-written file, and without
 *        overwriting a change somebody else made while we were deciding (C31, C36b/c/f).
 *
 * The file this replaces is the trust anchor every agent in the fleet holds. A reader
 * (`GET /cacerts`, `openssl verify`, an agent's own OpenSSL) must see either the old document or
 * the new one, never a prefix of either -- so the new one is written beside it and `renameat(2)`
 * publishes it in one step -- and a failure anywhere before that rename must leave the destination
 * byte for byte as it was.
 *
 * The twelve steps, their exact flags and the failure matrix each one has to satisfy are written
 * down in `ca_rotation/anexos/e7/escritura-atomica.md`. The three that are easy to get wrong:
 *   - the temporary is opened `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`. Without `O_WRONLY`
 *     the first `write()` returns EBADF and nothing is ever published (the same open remoted's
 *     caPublicationRecord.cpp:226 gets right);
 *   - its name carries a 16-hex random nonce, not PID + counter: a counter that another crashed run
 *     already exhausted would make `O_EXCL` refuse every attempt;
 *   - `contents` is written verbatim. It was serialised and hashed ONCE by the caller, and
 *     re-serialising here could publish a block that describes certificates the file does not hold.
 */

#include "manager_certs/commands.hpp" // DestinationImage, IoPort

#include <string>
#include <string_view>

namespace manager_certs
{
    /// What atomicWrite() did. `written == false` means the destination was not touched at all.
    struct AtomicWriteOutcome
    {
        bool written {false};
        std::string message;            ///< Operator-facing cause; empty when written and durable.
        int error {0};                  ///< errno of the refusing call, 0 when there was none.
        bool durabilityUnknown {false}; ///< Published, but the directory's fsync failed (C31).
    };

    /**
     * @brief Publishes @p contents as @p name inside @p directoryFd, atomically.
     *
     * @param directoryFd Descriptor of the destination's directory; stays open and owned by the caller.
     * @param name        The destination's basename -- never a literal "root-ca.pem" (C36a).
     * @param contents    The exact bytes to publish (block + certificates), already serialised once.
     * @param image       The destination as it was read under the lock: its owner, group and mode
     *                    are carried over to the new file, and its identity and content hash are
     *                    re-checked just before the rename. A destination that changed since then
     *                    was written without the lock, and is never overwritten (C36f).
     * @param io          Syscall seams; every empty field means the real call.
     */
    AtomicWriteOutcome atomicWrite(int directoryFd,
                                   const std::string& name,
                                   const std::string& contents,
                                   const DestinationImage& image,
                                   const IoPort& io);

    /// Hex SHA-256 of raw @p bytes -- the file's content identity. Deliberately NOT
    /// ca_bundle::contentSha256(), which hashes the certificates' DER and would read two different
    /// spellings of the same certificates as unchanged. Empty if the digest itself fails.
    std::string bytesSha256(std::string_view bytes);

} // namespace manager_certs

#endif // _MANAGER_CERTS_ATOMIC_WRITE_HPP
