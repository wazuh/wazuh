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
 * call it rather than to reimplement it a third time. Both callers now go through
 * w_fopen_nofollow_update(), which opens for update without truncating on either platform and
 * refuses a symlink at the target -- something `dd conv=notrunc` in the POSIX scripts does not do,
 * and which matters here because the MSI custom action runs as SYSTEM. It is reached through a binary
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

#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC
#else
    #define STATIC static
#endif

/* Written in one pass for the credential files this serves, which hold a single line. Sized as a
 * fixed buffer rather than from the file's own length so an unexpectedly large file cannot turn
 * into an unbounded stack allocation. */
#define W_SHRED_CHUNK 4096

/* Split @p path into the directory and bare filename w_fopen_nofollow_update() needs.
 *
 * AUTHD_PASS and AGENT_REENROLL_SECRET are "etc/<name>" on POSIX but a bare "<name>" on Windows
 * (defs.h), and both platforms chdir() into the installation directory before anything here runs,
 * so a path with no separator at all is the normal Windows case rather than an error -- it means
 * the working directory.
 *
 * @param buf Backing storage for the directory; @p filename points into it, so it must outlive it.
 * @return 0 on success, -1 when @p path does not fit in @p buf (errno set to ENAMETOOLONG).
 */
STATIC int w_shred_split_dir_filename(const char *path, char *buf, size_t buf_size, const char **filename)
{
    const char *separator = strrchr(path, '/');

#ifdef WIN32
    const char *backslash = strrchr(path, '\\');

    if (backslash != NULL && (separator == NULL || backslash > separator)) {
        separator = backslash;
    }
#endif

    if (separator == NULL) {
        if (strlen(path) == 0) {
            errno = EINVAL;
            return -1;
        }

        if ((size_t) snprintf(buf, buf_size, ".") >= buf_size) {
            errno = ENAMETOOLONG;
            return -1;
        }

        *filename = path;
        return 0;
    }

    if ((size_t) (separator - path) >= buf_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(buf, path, (size_t) (separator - path));
    buf[separator - path] = '\0';

    /* An absolute path whose only separator is the leading one: the directory is the root itself,
     * not the empty string, which openat() would reject. */
    if (buf[0] == '\0') {
        buf[0] = '/';
        buf[1] = '\0';
    }

    *filename = separator + 1;
    return 0;
}

int w_shred_file_in_place(const char *path)
{
    char zeros[W_SHRED_CHUNK] = {0};
    char dir[PATH_MAX];
    const char *filename;
    FILE *fp;
    long size;
    long written;

    if (w_shred_split_dir_filename(path, dir, sizeof(dir), &filename) != 0) {
        merror(FOPEN_ERROR, path, errno, strerror(errno));
        return 1;
    }

    /* Opened through the vetted no-follow helper rather than wfopen(): this runs over a credential
     * path, and one caller (the MSI's --shred-enrollment-password) runs privileged, so a symlink or
     * hard link swapped in at the target would otherwise be written through -- zeroing whatever it
     * points at. The helper opens for update WITHOUT truncating, which is the whole point here: a
     * truncating open would release the secret's bytes and write the zeros into a fresh allocation,
     * silently, with nothing in the return value to say so. */
    if (fp = w_fopen_nofollow_update(dir, filename), fp == NULL) {
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
