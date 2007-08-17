/* @(#) $Id$ */

/* Copyright (C) 2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "shared.h"


/** int os_getprime
 * Get the first available prime after the provided value.
 * Returns 0 on error.
 */
int os_getprime(int val)
{
    int i;
    int max_i;
    
    /* Value can't be even */
    if((val % 2) == 0)
    {
        val++;
    }
   
   
    do
    {
        /* We just need to check odd numbers up until half
         * the size of the provided value.
         */
        i = 3;
        max_i = val/2;
        while(i <= max_i)
        {
            /* Not prime */
            if((val % i) == 0)
            {
                break;
            }
            i += 2;
        }

        /* Prime */
        if(i >= max_i)
        {
            return(val);
        }
    }while(val += 2);

    return(0);
}


/* EOF */
