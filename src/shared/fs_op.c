/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to retrieve information about the filesystem
 */


#include "shared.h"

short IsNFS(const char *dir_name)
{
#if defined(__linux__) || defined(__FreeBSD__)
    struct statfs stfs;

    /* ignore NFS (0x6969) or CIFS (0xFF534D42) mounts */
    if ( ! statfs(dir_name, &stfs) )
    {
        if ( (stfs.f_type == 0x6969) || (stfs.f_type == 0xFF534D42) )
        {
            return(1); /* NFS/CIFS path */
        }
    }
    else
    {
        /* Throw an error and retreat! */
        merror("ERROR: statfs('%s') produced error: %s", dir_name, strerror(errno));
        return(-1);
    }
#else
    verbose(
        "INFO: Attempted to check NFS status for '%s', but we don't know how on this OS.",
        dir_name
    );
#endif
    return(0);
}

/* EOF */
