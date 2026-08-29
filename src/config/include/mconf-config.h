/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Manager configuration (etc/wazuh-manager.yml) for the C daemons.
 *
 * Thin C layer over the manager_config library (src/shared_modules/manager_config): the YAML file is
 * loaded, validated against the embedded schema and completed with its defaults once per process; the
 * daemons then read their sections as cJSON through w_mconf_section() and fill their structs with the
 * Read_*_JSON() readers of this library. Manager only: never compiled for the agent.
 */

#ifndef MCONF_CONFIG_H
#define MCONF_CONFIG_H

#ifndef CLIENT

struct cJSON;

/**
 * @brief Load, validate (schema + cross-field rules) and complete the manager configuration.
 *
 * The existence of the certificate/key files named in the document is NOT checked here (the daemons
 * start exactly as they do today; `-t` and `wazuh-manager-conf validate` check them, see
 * w_mconf_validate()). One document at a time: a second call with the same path is a no-op, a call
 * with a different path (`-c`) replaces the document -- libwazuh's readers (cluster_utils.c,
 * debug_op.c, see mconf_hook.h) may have made libconfig load the default file before main() got here.
 *
 * @param cfgfile Path of the YAML file (WAZUHCONF_YML or the `-c` argument).
 * @return 0 on success, -1 otherwise (the reason is logged with CONFIG_YAML_INVALID).
 */
int w_mconf_load(const char *cfgfile);

/**
 * @brief Full validation for `-t`: schema, cross-field rules and existence of the certificate/key
 *        files, relative paths resolved against the current working directory (the manager home).
 *
 * @return 0 when valid, -1 otherwise (the reason is logged with CONFIG_YAML_INVALID).
 */
int w_mconf_validate(const char *cfgfile);

/**
 * @brief One top-level section of the effective document (defaults applied).
 *
 * @param section Section name ("remote", "global", "auth", "wdb"...).
 * @return A cJSON object the caller frees with cJSON_Delete(), or NULL when nothing is loaded or the
 *         section is not defined by the schema.
 */
struct cJSON *w_mconf_section(const char *section);

/** @brief Path of the loaded file, or NULL when nothing is loaded. */
const char *w_mconf_file(void);

/** @brief Release the loaded document (tests and shutdown paths). */
void w_mconf_free(void);

/* Helpers shared by the Read_*_JSON() readers. */

/** @brief Boolean item; `def` when the item is absent or not a boolean. */
int w_mconf_json_bool(const struct cJSON *item, int def);

/**
 * @brief Duration item: an integer number of seconds or a string with a unit (w_parse_time: s, m, h, d, w).
 * @return Seconds, or -1 when the item is absent, of another type or malformed.
 */
long w_mconf_json_time(const struct cJSON *item);

/**
 * @brief Size item: an integer number of bytes or a string with a unit (w_parse_size: b, k, m, g).
 * @return Bytes, or -1 when the item is absent, of another type or malformed.
 */
long w_mconf_json_size(const struct cJSON *item);

/** @brief Log XML_VALUEERR for `element` with the item printed as text. */
void w_mconf_json_invalid(const char *element, const struct cJSON *item);

#endif /* CLIENT */

#endif /* MCONF_CONFIG_H */
