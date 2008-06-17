/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WIN32
#include "shared.h"
#include <pthread.h>



/* CreateThread(void v0.1
 * Creates a new thread and gives the argument passed to the function
 * Return 0 on success or -1 on error
 */
int CreateThread(void *function_pointer(void *data), void *data)
{
    pthread_t lthread;
    int ret = 0;

    ret = pthread_create(&lthread, NULL, function_pointer, (void*)data);
    if(ret != 0)
    {
        merror(THREAD_ERROR, __local_name);
        return (-1);
    }

    if(pthread_detach(lthread) != 0)
    {
        merror(THREAD_ERROR, __local_name);
        return(-1);
    }

    return(0);
}

#endif
/* EOF */
