/* Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "jsonout.h"
#include "alerts/getloglocation.h"
#include "format/to_json.h"

void jsonout_output_event(const Eventinfo *lf)
{
    char *json_alert = Eventinfo_to_jsonstr(lf);

    fprintf(_jflog,
            "%s\n",
            json_alert);

    fflush(_jflog);
    free(json_alert);
    return;
}
