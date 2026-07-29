/*
 * Module-tagged config and stats reports
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MODULE_REPORT_H
#define MODULE_REPORT_H

#include <stddef.h>
#include "cJSON.h"

/* A report is a JSON array where each entry names one module and carries its
 * body:
 *
 *   [{"module": "fim", "config": {...}}, {"module": "logcollector", ...}]
 *
 * Every agent daemon answers "getallconfig" / "getallstats" with the report for
 * the modules it hosts, so the HTTPS client needs one query per daemon instead
 * of one per configuration section. The client concatenates the arrays into the
 * document it pushes to /config and /stats. */

/**
 * @brief Move every member of a section into a module body.
 *
 * The per-section getters return a one-key wrapper such as {"syscheck": {...}}.
 * A module that spans several sections merges them into a single body. Does
 * nothing when section is NULL, so a getter result can be passed straight in.
 *
 * @param body Destination object.
 * @param section Source object. Consumed by this call.
 */
void module_report_merge(cJSON *body, cJSON *section);

/**
 * @brief Append a {"module": name, "config": body} entry to a report.
 *
 * A module that produced nothing is left out rather than reported empty, so the
 * manager can tell "not configured" from "configured with no options".
 *
 * @param report Destination array.
 * @param module Module name as the manager knows it, e.g. "fim".
 * @param body Module body. Consumed by this call.
 */
void module_report_add_config(cJSON *report, const char *module, cJSON *body);

/**
 * @brief Append a {"module": name, "stats": body} entry to a report.
 *
 * @param report Destination array.
 * @param module Module name as the manager knows it, e.g. "logcollector".
 * @param body Module body. Consumed by this call.
 */
void module_report_add_stats(cJSON *report, const char *module, cJSON *body);

/**
 * @brief Serialize a report into the "ok <json>" reply a dispatcher returns.
 *
 * @param report Report array. Consumed by this call.
 * @param output Receives the allocated reply.
 * @return Length of *output.
 */
size_t module_report_reply(cJSON *report, char **output);

#endif /* MODULE_REPORT_H */
