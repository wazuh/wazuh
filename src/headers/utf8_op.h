/* Copyright (C) 2015-2019, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * June 19, 2019
 */

/* Return whether a string is UTF-8 */
bool w_utf8_valid(const char * string);

/* Return pointer to the first character that does not match UTF-8, or the last byte (0) */
const char * w_utf8_drop(const char * string);

/* Return a new string with valid UTF-8 characters only */
char * w_utf8_filter(const char * string, bool replacement);
