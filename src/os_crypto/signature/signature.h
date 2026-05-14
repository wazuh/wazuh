/* RSA-PKCS1-SHA256 signature
 * Copyright (C) 2015, Wazuh Inc.
 * July 3, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unsign a WPK256 file, using a key path array. Returns 0 on success or -1 on error.
int w_wpk_unsign(const char * source, const char * target, const char ** ca_store);
