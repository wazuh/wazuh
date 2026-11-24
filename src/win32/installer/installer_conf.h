/*
 * Copyright (C) Wazuh Inc.
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
    CAD_ENROLLMENT_TOKEN,
    CAD_AGENT_NAME,
    CAD_AGENT_GROUP,
    CAD_KEEP_ALIVE,
    CAD_TIME_RECONNECT,
    CAD_ENROLLMENT_DELAY,
    CAD_SSL_VERIFICATION,
    /* Removed in 5.0: only reported when set. */
    CAD_MANAGER,
    CAD_MANAGER_PORT,
    CAD_MANAGER_ENDPOINT,
    CAD_REG_SERVER,
    CAD_REG_PORT,
    CAD_REG_PASSWORD,
    CAD_REG_CA,
    CAD_REG_CERT,
    CAD_REG_KEY,
    CAD_SSL_VERIFICATION_OLD,
    CAD_ADDRESS,
    CAD_SERVER_PORT,
    CAD_AUTHD_SERVER,
    CAD_AUTHD_PORT,
    CAD_PASSWORD,
    CAD_CERTIFICATE,
    CAD_PEM,
    CAD_KEY,
    CAD_FIELDS
};

/* Receives each message the installer writes to ossec.log. */
typedef void (*installer_log_fn)(void *ctx, const char *message);

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
 * @brief Run a program without a window and wait for it.
 * @param app Full path of the program.
 * @param args Command line arguments, without the program name.
 * @return Exit code of the program, or -1 if it could not be run.
 */
long installer_run(const wchar_t *app, const wchar_t *args);

/**
 * @brief Run a System32 tool without a window and wait for it.
 * @return Exit code of the tool, or -1 if it could not be run.
 */
long installer_run_system(const wchar_t *exe, const wchar_t *args);

/**
 * @brief Decode an enrollment token with "wazuh-agent.exe --show-token", passing it on stdin.
 * @param home Install folder, with a trailing backslash.
 * @param token Enrollment token.
 * @param adr Receives the token's address, newly allocated, or NULL if the decoder printed none.
 * @return Exit code of the decoder (0 accepted, 2 refused), or 127 if it could not be run.
 */
int installer_decode_token(const wchar_t *home, const char *token, char **adr);

/**
 * @brief Apply the deployment variables (token address, intervals, enrollment, TLS mode) to an ossec.conf text.
 * @param conf ossec.conf contents.
 * @param value CustomActionData fields, indexed by the CAD_* enum. None of them may be NULL.
 * @param adr Address decoded from the enrollment token, or NULL to keep the configured one.
 * @param log Receives the messages for ossec.log.
 * @param ctx Passed to log.
 * @return Newly allocated ossec.conf contents, or NULL on failure.
 */
char *installer_apply_deployment(const char *conf, char *const value[CAD_FIELDS], const char *adr, installer_log_fn log,
                                 void *ctx);

/**
 * @brief Insert the profile template after the manager block of an ossec.conf text.
 * @param conf ossec.conf contents.
 * @param profile profile-<OS>.template contents, or NULL.
 * @return Newly allocated ossec.conf contents, or NULL on failure.
 */
char *installer_apply_templates(const char *conf, const char *profile);

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
 * @brief Keep the configuration and keys as .save copies and delete everything else in the install folder.
 *
 * The backup and upgrade folders are kept. Links found while deleting are removed, never followed.
 * Nothing is deleted if home is a drive root.
 *
 * @param home Install folder.
 * @return 0 on success, -1 if a configuration file could not be renamed.
 */
int installer_remove_all(const wchar_t *home);

/**
 * @brief Remove authd.pass: shredded by "wazuh-agent.exe --shred-enrollment-password", else overwritten and deleted.
 * @param home Install folder, with a trailing backslash.
 */
void installer_remove_fleet_password(const wchar_t *home);

/**
 * @brief Delete the databases of the agent versions prior to 5.0.
 * @param home Install folder, with a trailing backslash.
 */
void installer_cleanup_legacy_databases(const wchar_t *home);

#endif
