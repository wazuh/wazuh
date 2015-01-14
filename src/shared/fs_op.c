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

const struct file_system_type network_file_systems[] = {
    {.name="NFS",  .f_type=0x6969,     .flag=1},
    {.name="CIFS", .f_type=0xFF534D42, .flag=1},

    /*  The last entry must be name=NULL */
    {.name=NULL, .f_type=0, .flag=0}
};

short IsNFS(const char *dir_name)
{
#if defined(Linux) || defined(FreeBSD)
    struct statfs stfs;

    /* ignore NFS (0x6969) or CIFS (0xFF534D42) mounts */
    if ( ! statfs(dir_name, &stfs) )
    {
        int i;
        for ( i=0; network_file_systems[i].name != NULL; i++ ) {
            if(network_file_systems[i].f_type == stfs.f_type ) {
                return network_file_systems[i].flag;
            }
        }
        return(0);
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
