/*   $OSSEC, validate_op.h, v0.1, 2006/01/24, Daniel B. Cid$    */

/* Copyright (C) 2004,2005,2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


#ifndef __VALIDATE_H

#define __VALIDATE_H



/** int OS_IPFoundList(char *ip_address, char **list_of_ips)
 * Checks if ip_address is present on the "list_of_ips".
 * Returns 1 on success or 0 on failure.
 * The list MUST be NULL terminated
 */
int OS_IPFoundList(char *ip_address, char **list_of_ips);



/** int OS_HasNetmask(char *ip)
 * Checks if an IP Address has a netmask or not.
 * This function must ONLY be called after "OS_IsValidIP"
 */
int OS_HasNetmask(char *ip_address);



/** int OS_IsValidIP(char *ip)
 * Validates if an ip address is in the right
 * format.
 * Returns 0 if doesn't match or 1 if it does.
 * ** On success this function may modify the value of ip_address
 */
int OS_IsValidIP(char *ip_address);
    
    
#endif

/* EOF */
