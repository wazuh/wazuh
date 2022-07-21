/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"


/* Read the file pointer specified
 * and check if the configured file is there
 */
void check_rc_unixaudit(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_unixaudit");
    rkcl_get_entry(fp, "System Audit:", p_list);
}

/* Read the file pointer specified
 * and check if the configured file is there
 */
void check_rc_winaudit(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_winaudit");
    rkcl_get_entry(fp, "Windows Audit:", p_list);
}

/* Read the file pointer specified
 * and check if the configured file is there
 */
void check_rc_winmalware(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_winmalware");
    rkcl_get_entry(fp, "Windows Malware:", p_list);
}

/* Read the file pointer specified
 * and check if the configured file is there
 */
void check_rc_winapps(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_winapps");
    rkcl_get_entry(fp, "Application Found:", p_list);
}
