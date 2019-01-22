/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Help Function */

#include "shared.h"


void print_header()
{
    print_out(" ");
    print_out("%s %s - %s (%s)", __ossec_name, __ossec_version, __author, __contact);
    print_out("%s", __site);
}

void print_version()
{
    print_out(" ");
    print_out("%s %s - %s", __ossec_name, __ossec_version, __author);
    print_out(" ");
    print_out("%s", __license);
    exit(0);
}
