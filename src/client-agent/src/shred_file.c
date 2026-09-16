/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Overwriting a credential file before unlinking it, and --shred-enrollment-password, the
 * subcommand the MSI uses to reach it.
 *
 * The 5.0 upgrade removes the fleet-wide enrollment password from the endpoint, overwriting it
 * before unlinking. The DEB postinst, the RPM %post and the macOS postinstall do that with
 * `dd conv=notrunc`, which writes over the file's existing allocation. The MSI's VBScript custom
 * action could not: no write mode reachable from a script host opens a file without truncating it
 * first -- FileSystemObject's ForWriting truncates on open, and ADODB.Stream's
 * SaveToFile(adSaveCreateOverWrite) truncates too (measured on Windows, not inferred from the
 * documentation: saving 5 bytes over a 10-byte file leaves a 5-byte file). So the installer
 * released the secret's bytes and wrote its zeros into a fresh allocation, and the four packages
 * did not agree on what "overwriting it before unlinking" meant.
 *
 * The agent already had the primitive the script lacked -- w_reenroll_secret_clear() has opened
 * "r+" to overwrite the re-enrollment secret since #39064 -- so the fix is to let the installer
 * call it rather than to reimplement it a third time. It is reached through a binary
 * InstallerScripts.vbs is already running for --show-token, and one that ships signed, which for a
 * security product's installer is the real argument against the other route to OPEN_EXISTING from
 * VBScript: `powershell.exe -ExecutionPolicy Bypass`.
 *
 * --shred-enrollment-password takes no path argument on purpose. What the packages remove is the
 * compiled default and only the compiled default -- a password an operator put somewhere else is
 * theirs to keep (see the #39064 CHANGELOG entry) -- and a subcommand that zeroes and unlinks
 * whatever path it is handed is a primitive worth not shipping at all.
 */

#include "shared.h"
#include "agentd.h"
#include "shred_file.h"

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

/* Written in one pass for the credential files this serves, which hold a single line. Sized as a
 * fixed buffer rather than from the file's own length so an unexpectedly large file cannot turn
 * into an unbounded stack allocation. */
#define W_SHRED_CHUNK 4096

int w_shred_file_in_place(const char *path)
{
    char zeros[W_SHRED_CHUNK] = {0};
    FILE *fp;
    long size;
    long written;

    /* "r+b", and the order matters: wfopen() walks the mode string, so 'r' sets OPEN_EXISTING and
     * '+' then adds GENERIC_WRITE. A mode that put '+' first, or a "w", would still open the file
     * and would silently stop overwriting the original allocation -- the one failure this whole
     * function exists to prevent, and one no return value reports. */
    if (fp = wfopen(path, "r+b"), fp == NULL) {
        merror(FOPEN_ERROR, path, errno, strerror(errno));
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0) {
        merror(FSEEK_ERROR, path, errno, strerror(errno));
        fclose(fp);
        return 1;
    }

    if (size == 0) {
        fclose(fp);
        return 0;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        merror(FSEEK_ERROR, path, errno, strerror(errno));
        fclose(fp);
        return 1;
    }

    for (written = 0; written < size; ) {
        const size_t chunk = (size - written) < W_SHRED_CHUNK ? (size_t) (size - written) : W_SHRED_CHUNK;

        if (fwrite(zeros, 1, chunk, fp) != chunk) {
            merror("Could not overwrite '%s': %s (%d).", path, strerror(errno), errno);
            fclose(fp);
            return 1;
        }

        written += (long) chunk;
    }

    /* The zeros have to reach the disk before the caller's unlink does. Left in the page cache, a
     * machine that loses power here comes back with the secret still in its own blocks and nothing
     * referencing them -- which is worse than not having tried, because the file is gone and
     * nobody can tell that it did not work. */
    if (fflush(fp) != 0
#ifdef WIN32
            || _commit(_fileno(fp)) != 0
#else
            || fsync(fileno(fp)) != 0
#endif
       ) {
        merror("Could not flush the overwrite of '%s' to disk: %s (%d).", path, strerror(errno), errno);
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return 0;
}

int w_agent_shred_enrollment_password(void)
{
    int failed = 0;

    /* Existence is tested here rather than read out of a failed open: on Windows wfopen() reports
     * failure by assigning GetLastError() straight into errno, so a missing file arrives as
     * ERROR_FILE_NOT_FOUND rather than as ENOENT. Both are 2, which is a coincidence and not a
     * contract -- every other Win32 code on that path means something else entirely. */
    if (!w_is_file(AUTHD_PASS)) {
        return 0;
    }

    if (w_shred_file_in_place(AUTHD_PASS) != 0) {
        /* Deliberately not an early return. Overwriting is defence in depth; unlinking is what
         * actually takes the fleet-wide credential off the endpoint, and a file that could not be
         * opened for writing can still be removable. */
        failed = 1;
    }

    if (unlink(AUTHD_PASS) != 0) {
        merror(UNLINK_ERROR, AUTHD_PASS, errno, strerror(errno));
        failed = 1;
    }

    return failed;
}
