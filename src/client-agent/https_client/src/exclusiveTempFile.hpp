/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_EXCLUSIVE_TEMP_FILE_HPP
#define _HC_EXCLUSIVE_TEMP_FILE_HPP

#include <string>

/// Creates a new, uniquely-named file under `dir` atomically and exclusively
/// (O_EXCL) with owner-only permissions, so a shared dir (e.g. /tmp) cannot be
/// used to hijack or read back the file's contents via a pre-planted symlink
/// -- the create simply fails on an existing path rather than following it.
/// An empty `dir` falls back to TMPDIR/TEMP/TMP or "/tmp" (never silently
/// resolves to the process's cwd via a bare relative path) -- callers whose
/// own configured spool directory can be unset (e.g. ModuleConfig::spoolDir,
/// which nothing populates today) don't each need their own fallback.
/// `prefix` names the caller (e.g. "hc_sync_", "hc_zstd_") for easier
/// spool-dir triage; the rest of the name is unpredictable (pid + thread id +
/// a monotonic counter + a random token), so it cannot be pre-planted to force
/// a collision. Retries on the (essentially impossible) random-name collision;
/// any other error means the directory is unusable. On success, returns an
/// open, writable fd and sets `outPath` to the created path. On failure,
/// returns -1 (errno set, except after exhausting collision retries).
int createExclusiveTempFile(const std::string& dir, const std::string& prefix, std::string& outPath);

/// Portable close() wrapper, paired with the fd createExclusiveTempFile() returns.
void closeExclusiveTempFile(int fd);

#endif // _HC_EXCLUSIVE_TEMP_FILE_HPP
