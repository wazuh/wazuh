/* @(#) $Id$ */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
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

void help()
{
    int i = 0;
    char *daemons[] = {"ossec-maild", "ossec-execd", 
                      "ossec-analysisd", "ossec-logcollector",
                      "ossec-remoted", "ossec-syscheckd", NULL};
    
    print_out("");
    print_out("%s %s - %s (%s)", __name, __version, __author, __contact);
    print_out("%s", __site);
    while(daemons[i])
    {
        print_out("");
        print_out("  %s: -[thd] [-u user] [-g group] [-c config]",daemons[i]);
        print_out("    -V          Version and license message");
        print_out("    -h          This help message");
        print_out("    -d          Execute in debug mode");
        print_out("    -t          Test configuration");
        print_out("    -u <user>   Run as 'user'");
        print_out("    -g <group>  Run as 'group'");
        print_out("    -c <config> Read the 'config' file");
        i++;
    }
    print_out("");
    exit(1);
}

void print_version()
{
    print_out("");
    print_out("%s %s - %s", __name, __version, __author);
    print_out("");
    print_out("%s",__license);
    exit(1);
}

/* EOF */
