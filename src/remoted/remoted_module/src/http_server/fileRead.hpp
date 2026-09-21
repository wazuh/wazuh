/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_FILE_READ_HPP
#define _REMOTED_HTTP_SERVER_FILE_READ_HPP

/**
 * @file fileRead.hpp
 * @brief Bounded, injectable file reading with an exact failure cause: the seam CaCertificateSource
 *        reads the CA bundle through.
 *
 * Three things a plain std::ifstream did not give that reader (issue #39318): a bound that holds
 * BEFORE the bytes are in memory (never more than maxBytes + 1 are requested, whatever the file's
 * size), the errno of the failed call (a directory at the path, a permission change and a missing
 * file lead the operator to different fixes), and a seam a test can replace -- root ignores file
 * permissions, so "make it unreadable" is not something a test can do to a real file.
 *
 * Kept apart from caCertificateSource.hpp because the TLS status (tlsCertificateStatus.hpp) carries
 * the last read failure too, and it cannot include the source's header, which includes it.
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace remoted::http
{
    /// Outcome of one bounded read.
    enum class ReadStatus
    {
        Ok,         ///< `contents` holds the whole file, at most `maxBytes` long.
        CannotOpen, ///< open(2) failed: the file is missing, or not ours to read (ENOENT, EACCES, ...).
        ReadError,  ///< read(2) failed after the open succeeded (EISDIR for a directory, EIO, ...).
        TooLarge    ///< More than `maxBytes` bytes were available; nothing past the cap was requested.
    };

    /// What a FileReader hands back.
    struct ReadResult
    {
        ReadStatus status {ReadStatus::Ok};
        int error {0}; ///< errno of the failed call for CannotOpen and ReadError; 0 otherwise.
    };

    /**
     * @brief Reads @p path into @p contents, requesting at most @p maxBytes + 1 bytes from it.
     *
     * Production uses readFileBounded(); a test passes a reader that fails on demand, or one that
     * records what was asked of it. Must not throw; on anything but Ok, @p contents is left empty.
     */
    using FileReader = std::function<ReadResult(const std::string& path, std::size_t maxBytes, std::string& contents)>;

    /// The default FileReader: POSIX open/read, so the cause of a failure is the exact errno.
    ReadResult readFileBounded(const std::string& path, std::size_t maxBytes, std::string& contents);

    /// The latest read that failed, remembered for as long as the failure lasts.
    struct ReadFailure
    {
        ReadStatus status {ReadStatus::CannotOpen};
        int error {0};                 ///< errno of that read; 0 for TooLarge.
        std::uint64_t consecutive {0}; ///< Failed reads in a row since the last good one: 1 on the first.
    };

    /**
     * @brief The failure as a log line fragment that completes "the file ...": "cannot be opened
     *        (No such file or directory)", "cannot be read (Is a directory)", "is larger than the
     *        1 MiB cap". @p maxBytes is the cap the reader was given, for the last of those.
     */
    std::string describeReadFailure(const ReadFailure& failure, std::size_t maxBytes);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_FILE_READ_HPP
