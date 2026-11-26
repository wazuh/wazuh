/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef INSTALLER_CONF_H
#define INSTALLER_CONF_H

#include <stddef.h>
#include <wchar.h>

/* Fields of the CustomActionData set by SetCustomActionDataValue in wazuh-installer.wxs, in order. */
enum {
    CAD_HOME_DIR,
    CAD_OS_VERSION,
    CAD_MANAGER,
    CAD_MANAGER_PORT,
    CAD_PROTOCOL,
    CAD_NOTIFY_TIME,
    CAD_REG_SERVER,
    CAD_REG_PORT,
    CAD_REG_PASSWORD,
    CAD_KEEP_ALIVE,
    CAD_TIME_RECONNECT,
    CAD_REG_CA,
    CAD_REG_CERT,
    CAD_REG_KEY,
    CAD_AGENT_NAME,
    CAD_AGENT_GROUP,
    CAD_ENROLLMENT_DELAY,
    CAD_FIELDS
};

/**
 * @brief Concatenate a NULL-terminated list of wide strings.
 * @return Newly allocated string, or NULL on allocation failure.
 */
wchar_t *installer_wconcat(const wchar_t *first, ...);

/**
 * @brief Get one field of a CustomActionData string, with every double quote removed.
 * @param cad CustomActionData.
 * @param sep Field separator, or NULL to take the whole string as field 0.
 * @param index Field index.
 * @return Newly allocated field, or NULL if it does not exist or on allocation failure.
 */
wchar_t *installer_cad_field(const wchar_t *cad, const wchar_t *sep, int index);

/**
 * @brief Apply the deployment variables (manager, protocol, enrollment...) to an ossec.conf text.
 * @param conf ossec.conf contents.
 * @param value CustomActionData fields, indexed by the CAD_* enum. None of them may be NULL.
 * @return Newly allocated ossec.conf contents, or NULL on failure.
 */
char *installer_apply_deployment(const char *conf, char *const value[CAD_FIELDS]);

/**
 * @brief Apply the per-OS templates to an ossec.conf text.
 * @param conf ossec.conf contents.
 * @param profile profile-<OS>.template contents, or NULL.
 * @param syscheck syscheck-<OS>.template contents, or NULL.
 * @param events localfile-events-<OS>.template contents, or NULL.
 * @return Newly allocated ossec.conf contents, or NULL on failure.
 */
char *installer_apply_templates(const char *conf, const char *profile, const char *syscheck, const char *events);

/**
 * @brief Write the first-install configuration files in the install folder.
 * @param cad CustomActionData of the CustomAction_InstallerScripts action.
 * @return 0 on success, -1 on failure.
 */
int installer_config(const wchar_t *cad);

/**
 * @brief Find the first REG_MULTI_SZ entry that contains a folder, ignoring case.
 * @param entries REG_MULTI_SZ data, followed by a terminating null character.
 * @param len Length of entries in characters, without that terminator.
 * @param dir Folder to look for.
 * @return Pointer to the matching entry inside entries, or NULL.
 */
const wchar_t *installer_pending_conflict(const wchar_t *entries, size_t len, const wchar_t *dir);

/**
 * @brief Tell whether a folder is the root of a drive, such as "C:\" or "C:".
 * @param dir Folder, with or without a trailing backslash.
 * @return 1 if it is a drive root, 0 otherwise.
 */
int installer_is_drive_root(const wchar_t *dir);

/**
 * @brief Keep the configuration and keys as .save copies and delete everything else in the install folder.
 *
 * The backup and upgrade folders are kept. Links found while deleting are removed, never followed.
 * Nothing is deleted if home is a drive root.
 *
 * @param home Install folder.
 * @return 0 on success, -1 if a configuration file could not be renamed.
 */
int installer_remove_all(const wchar_t *home);

#endif
