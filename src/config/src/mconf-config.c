/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLIENT

#include "shared.h"
#include "string_op.h"
#include "mconf-config.h"
#include "manager_config/manager_config_c.h"

/* One document per process (RF-7): loaded by the daemon's *Config() entry point, read by every
 * section reader and by the getconfig handlers. */
static mconf_t *g_mconf = NULL;
static char g_mconf_file[PATH_MAX + 1];

int w_mconf_load(const char *cfgfile) {
    char err[OS_SIZE_2048] = {0};

    if (g_mconf != NULL) {
        return 0;
    }

    if (cfgfile == NULL || *cfgfile == '\0') {
        cfgfile = WAZUHCONF_YML;
    }

    /* home = NULL: relative paths resolve against the current working directory, which the daemons
     * have already changed to the manager home. check_files = 0: start-up does not require the
     * certificate files to exist (the installer generates them after writing the configuration, and the
     * XML readers never checked them either); `-t` does, through w_mconf_validate() (P44). */
    if (mconf_load_ex(cfgfile, NULL, 0, &g_mconf, err, sizeof(err)) != 0) {
        merror(CONFIG_YAML_INVALID, cfgfile, err);
        g_mconf = NULL;
        return -1;
    }

    snprintf(g_mconf_file, sizeof(g_mconf_file), "%s", cfgfile);
    return 0;
}

int w_mconf_validate(const char *cfgfile) {
    char err[OS_SIZE_2048] = {0};

    if (cfgfile == NULL || *cfgfile == '\0') {
        cfgfile = WAZUHCONF_YML;
    }

    if (mconf_validate(cfgfile, NULL, err, sizeof(err)) != 0) {
        merror(CONFIG_YAML_INVALID, cfgfile, err);
        return -1;
    }

    return 0;
}

struct cJSON *w_mconf_section(const char *section) {
    char *json = NULL;
    cJSON *object = NULL;

    if (g_mconf == NULL || section == NULL) {
        return NULL;
    }

    json = mconf_section_json(g_mconf, section);
    if (json == NULL) {
        return NULL;
    }

    object = cJSON_Parse(json);
    free(json);
    return object;
}

const char *w_mconf_file(void) {
    return g_mconf != NULL ? g_mconf_file : NULL;
}

void w_mconf_free(void) {
    mconf_free(g_mconf);
    g_mconf = NULL;
    g_mconf_file[0] = '\0';
}

int w_mconf_json_bool(const struct cJSON *item, int def) {
    if (!cJSON_IsBool(item)) {
        return def;
    }
    return cJSON_IsTrue(item) ? 1 : 0;
}

long w_mconf_json_time(const struct cJSON *item) {
    if (cJSON_IsNumber(item)) {
        return item->valuedouble < 0 || item->valuedouble > (double) LONG_MAX ? -1 : (long) item->valuedouble;
    }
    if (cJSON_IsString(item) && item->valuestring != NULL) {
        return w_parse_time(item->valuestring);
    }
    return -1;
}

long w_mconf_json_size(const struct cJSON *item) {
    if (cJSON_IsNumber(item)) {
        return item->valuedouble < 0 || item->valuedouble > (double) LONG_MAX ? -1 : (long) item->valuedouble;
    }
    if (cJSON_IsString(item) && item->valuestring != NULL) {
        ssize_t size = w_parse_size(item->valuestring);
        return size < 0 ? -1 : (long) size;
    }
    return -1;
}

void w_mconf_json_invalid(const char *element, const struct cJSON *item) {
    char *text = item != NULL ? cJSON_PrintUnformatted(item) : NULL;
    merror(XML_VALUEERR, element, text != NULL ? text : "(null)");
    free(text);
}

#endif /* CLIENT */
