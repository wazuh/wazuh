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


#ifndef H_MATHOP_OS
#define H_MATHOP_OS


/** int os_getprime
 * Get the first available prime after the provided value.
 * Returns 0 on error.
 */
int os_getprime(int val); 


#endif

/* EOF */
