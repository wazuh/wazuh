/* @(#) $Id: ./src/headers/math_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
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
unsigned int os_getprime(unsigned int val);


#endif

/* EOF */
