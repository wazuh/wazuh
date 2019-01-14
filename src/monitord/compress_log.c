/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"
#include "../external/zlib/zlib.h"


/* gzip a log file */
void OS_CompressLog(const char *logfile)
{
    FILE *log;
    gzFile zlog;

    char logfileGZ[OS_FLSIZE + 1];
    int len, err;

    char buf[OS_MAXSTR + 1];

    /* Clear memory */
    memset(logfileGZ, '\0', OS_FLSIZE + 1);
    memset(buf, '\0', OS_MAXSTR + 1);

    /* Set umask */
    umask(0027);

    /* Create the gzip file name */
    snprintf(logfileGZ, OS_FLSIZE, "%s.gz", logfile);

    /* Read log file */
    log = fopen(logfile, "r");
    if (!log) {
        /* Do not warn in here, since the alert file may not exist */
        return;
    }

    /* Open compressed file */
    zlog = gzopen(logfileGZ, "w");
    if (!zlog) {
        fclose(log);
        merror(FOPEN_ERROR, logfileGZ, errno, strerror(errno));
        return;
    }

    for (;;) {
        len = (int) fread(buf, 1, OS_MAXSTR, log);
        if (len <= 0) {
            break;
        }
        if (gzwrite(zlog, buf, (unsigned)len) != len) {
            merror("Compression error: %s", gzerror(zlog, &err));
        }
    }

    fclose(log);
    gzclose(zlog);

    /* Remove uncompressed file */
    if ( unlink(logfile) == -1)
        merror("Unable to delete '%s' due to '%s'", logfile, strerror(errno));

    return;
}
