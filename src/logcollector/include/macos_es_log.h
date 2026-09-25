/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MACOS_ES_LOG_H
#define MACOS_ES_LOG_H

/* ******************  INCLUDES  ****************** */

#include "shared.h"
#include "localfile-config.h"

/* ******************  DEFINES  ****************** */

#define ESLOGGER_CMD_STR "/usr/bin/eslogger" ///< Path to Apple's Endpoint Security `eslogger` CLI
#define ESLOGGER_NOT_PERMITTED_STR "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED" ///< `eslogger` stderr marker of a missing Full Disk Access grant

/* Backoff policy: the collector is never disabled permanently once started, so a later spawn attempt
 * (e.g. after Full Disk Access is granted again) always retries. `failures` resets only after a healthy
 * run; otherwise a process that dies right away would reset the backoff every cycle and loop. */
#define MACOS_ES_BACKOFF_BASE_SEC    5   ///< Initial retry delay
#define MACOS_ES_BACKOFF_MULTIPLIER  2   ///< Delay growth factor per consecutive failure
#define MACOS_ES_BACKOFF_CAP_SEC     300 ///< Maximum retry delay
#define MACOS_ES_HEALTHY_UPTIME_SEC  60  ///< Minimum uptime for an exit to reset the failure count
#define MACOS_ES_WARN_THROTTLE_AFTER 3   ///< Log every failure up to this count, then throttle
#define MACOS_ES_WARN_THROTTLE_SEC   300 ///< Minimum gap between repeated failure log lines

/* ******************  PROTOTYPES  ****************** */

/**
 * @brief Creates the environment for collecting Endpoint Security events on macOS systems (macos-es log format)
 *
 * Allocates the runtime config and performs the first spawn attempt via `w_macos_es_ensure_running()`.
 * Unlike `w_macos_create_log_env()`, there is no vault/replay logic to set up: `eslogger` is live-only.
 * When `eslogger` does not exist it warns once and leaves `lf->macos_es` NULL,
 * so the collector is never polled.
 *
 * @param lf localfile's logreader structure with the `<events>` list and its runtime configuration to be set
 */
void w_macos_es_create_env(logreader * lf);

/**
 * @brief Ensures the `eslogger` process is running, honoring the backoff delay after a failure
 *
 * A no-op when a process is already running or the backoff delay has not elapsed yet. Otherwise
 * checks that `eslogger` is executable, builds its argv from `lf->events` and spawns it.
 *
 * @param lf localfile's logreader structure
 */
void w_macos_es_ensure_running(logreader * lf);

/**
 * @brief Records a spawn/run failure: advances the exponential backoff and decides whether to log it
 *
 * @param config macos-es runtime config
 * @return true if this failure should be logged (every failure up to `MACOS_ES_WARN_THROTTLE_AFTER`,
 *         then at most once every `MACOS_ES_WARN_THROTTLE_SEC`)
 */
bool w_macos_es_note_failure(w_macos_es_config_t * config);

/**
 * @brief Stops a live `eslogger` process and releases its resources
 *
 * Sends `SIGTERM` before `wpclose()`: `eslogger` never exits on its own, so the blocking `waitpid()`
 * inside `wpclose()` would otherwise hang. Also drops any partial record kept from that process.
 * @param lf localfile's logreader structure
 */
void w_macos_es_release(logreader * lf);

/**
 * @brief Releases the resources of an `eslogger` process that was already reaped with `waitpid()`
 *
 * Closes the pipe and frees the connector without signaling or waiting on the pid again: once reaped,
 * the pid may already belong to an unrelated process. Also drops any partial record kept from it.
 * @param lf localfile's logreader structure
 */
void w_macos_es_release_reaped(logreader * lf);

#endif /* MACOS_ES_LOG_H */
