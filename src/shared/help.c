/* @(#) $Id: ./src/shared/help.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

/* Help Function
 */


#include "shared.h"

void help(const char *prog)
{
    print_out(" ");
    print_out("%s %s - %s (%s)", __ossec_name, __version, __author, __contact);
    print_out("%s", __site);
    print_out(" ");
    print_out("  %s: -[Vhdt] [-u user] [-g group] [-c config] [-D dir]", prog);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   Run as 'user'");
    print_out("    -g <group>  Run as 'group'");
    print_out("    -c <config> Read the 'config' file");
    print_out("    -D <dir>    Chroot to 'dir'");
    print_out(" ");
    exit(1);
}

void print_version()
{
    print_out(" ");
    print_out("%s %s - %s", __ossec_name, __version, __author);
    print_out(" ");
    print_out("%s",__license);
    exit(1);
}

/* EOF */
