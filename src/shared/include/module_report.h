/*
 * Module-tagged config and stats reports
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MODULE_REPORT_H
#define MODULE_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include "cJSON.h"

/* A report is a JSON object keyed by module name:
 *
 *   {"fim": {...}, "logcollector": {...}}
 *
 * Every agent daemon answers "getallconfig" / "getallstats" with the report for
 * the modules it hosts, so the HTTPS client needs one query per daemon instead
 * of one per configuration section. The client merges the objects into the
 * document it pushes to /config and /stats.
 *
 * Keyed rather than an array of {"module": name, ...} entries so the manager
 * only has to validate the object and move it under wazuh.agent.statistics:
 * one entry per module is already the invariant, and a stored array cannot be
 * read back by key without a `nested` mapping. */

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
 * @brief Store a module's body in a report under its own name.
 *
 * A module that produced nothing is left out rather than reported empty, so the
 * manager can tell "not configured" from "configured with no options".
 *
 * @param report Destination object.
 * @param module Module name as the manager knows it, e.g. "fim".
 * @param body Module body. Consumed by this call.
 */
void module_report_add(cJSON *report, const char *module, cJSON *body);

/* What a report shows instead of a credential's value. The same text the
 * server API masks configuration secrets with, so a masked value reads the
 * same wherever the configuration is shown. */
#define MODULE_REPORT_SECRET_MASK "*****"

/**
 * @brief Store a credential in a module body, masked unless asked otherwise.
 *
 * Module bodies leave the agent: the manager indexes the /config report as it
 * arrives. Masked, the key is kept with MODULE_REPORT_SECRET_MASK as its value,
 * so the report still tells that the credential is set, and the field stays a
 * string, the type the index maps it with. A path to a file holding a
 * credential is not a credential and is reported as is.
 *
 * Adds nothing when the secret is NULL or empty: no credential is set, and a
 * mask would claim one is. Call sites can pass the field straight in.
 *
 * @param object Destination object, e.g. one entry of a module's api_auth.
 * @param key Field name, e.g. "secret_key".
 * @param secret Credential value. Copied only when unmasked.
 * @param unmasked true reports the value itself instead of the mask.
 */
void module_report_add_secret(cJSON *object, const char *key,
                              const char *secret, bool unmasked);

/**
 * @brief Serialize a report into the "ok <json>" reply a dispatcher returns.
 *
 * @param report Report array. Consumed by this call.
 * @param output Receives the allocated reply.
 * @return Length of *output.
 */
size_t module_report_reply(cJSON *report, char **output);

#endif /* MODULE_REPORT_H */
