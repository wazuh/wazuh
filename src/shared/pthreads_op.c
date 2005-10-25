/*      $OSSEC, pthreads_op.c, v0.1, 2005/09/23, Daniel B. Cid$      */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <pthread.h>

#include "headers/debug_op.h"
#include "error_messages/error_messages.h"


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
        merror(THREAD_ERROR,ARGV0);
        return (-1);
    }

    if(pthread_detach(lthread) != 0)
    {
        merror(THREAD_ERROR,ARGV0);
        return(-1);
    }

    return(0);
}


/* EOF */
