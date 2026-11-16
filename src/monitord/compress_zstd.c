/* Copyright (C) 2015, Wazuh Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "shared.h"
#include "monitord.h"
#include "../external/zstd/lib/zstd.h"

/* Publish a complete stream before removing the original log. */
int OS_CompressLogZstd(const char *logfile)
{
    char destination[OS_FLSIZE + 1];
    char temporary[OS_FLSIZE + 1];
    char input[OS_MAXSTR];
    char output[OS_MAXSTR];
    FILE *source = NULL;
    FILE *target = NULL;
    ZSTD_CCtx *context = NULL;
    int result = -1;
    int fd = -1;

    if (snprintf(destination, sizeof(destination), "%s.zst", logfile) >= (int)sizeof(destination) ||
        snprintf(temporary, sizeof(temporary), "%s.zst.XXXXXX", logfile) >= (int)sizeof(temporary)) {
        merror("Log compression path too long: '%s'", logfile);
        return -1;
    }
    if (!(source = wfopen(logfile, "rb"))) {
        return -1; /* Optional log may not exist. */
    }
    umask(0027);
    if ((fd = mkstemp(temporary)) < 0) {
        goto cleanup;
    }
    if (fchmod(fd, 0640) < 0 || !(target = fdopen(fd, "wb"))) {
        close(fd);
        goto cleanup;
    }
    if (!(context = ZSTD_createCCtx())) {
        goto cleanup;
    }
    for (;;) {
        size_t count = fread(input, 1, sizeof(input), source);
        if (ferror(source)) {
            goto cleanup;
        }
        ZSTD_inBuffer in = { input, count, 0 };
        ZSTD_EndDirective mode = feof(source) ? ZSTD_e_end : ZSTD_e_continue;
        size_t remaining;
        do {
            ZSTD_outBuffer out = { output, sizeof(output), 0 };
            remaining = ZSTD_compressStream2(context, &out, &in, mode);
            if (ZSTD_isError(remaining) || fwrite(output, 1, out.pos, target) != out.pos) {
                goto cleanup;
            }
        } while (in.pos < in.size || (mode == ZSTD_e_end && remaining != 0));
        if (mode == ZSTD_e_end) {
            break;
        }
    }
    if (fclose(target) != 0) {
        target = NULL;
        goto cleanup;
    }
    target = NULL;
    /* Do not overwrite an existing compressed archive. */
    if (link(temporary, destination) < 0) {
        goto cleanup;
    }
    if (unlink(logfile) < 0) {
        merror("Unable to delete '%s' due to '%s'", logfile, strerror(errno));
        goto cleanup;
    }
    result = 0;
cleanup:
    if (result != 0) {
        merror("Unable to compress log '%s' with zstd", logfile);
    }
    ZSTD_freeCCtx(context);
    if (target) {
        fclose(target);
    }
    fclose(source);
    if (fd >= 0) {
        unlink(temporary);
    }
    return result;
}
