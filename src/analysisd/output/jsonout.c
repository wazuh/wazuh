/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
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

    free(json_alert);
    return;
}
void jsonout_output_archive(const Eventinfo *lf)
{
    char *json_alert;

    if (strcmp(lf->location, "ossec-keepalive") && !strstr(lf->location, "->ossec-keepalive")) {
        json_alert = Eventinfo_to_jsonstr(lf);
        fprintf(_ejflog, "%s\n", json_alert);
        free(json_alert);
    }
}

void jsonout_output_archive_flush(){
    fflush(_ejflog);
}

void jsonout_output_event_flush(){
    fflush(_jflog);
}

