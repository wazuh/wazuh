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

/* Backoff policy (R7/R14): never permanently disables the collector — a later spawn attempt
 * (e.g. after FDA is re-granted) always retries. failures resets only after a healthy run,
 * otherwise a fast-dying process would reset backoff every cycle and produce a crash loop. */
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
 * Unlike `w_macos_create_log_env()`, there is no vault/replay logic to set up (R8): `eslogger` is live-only.
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
 * @brief Releases the `eslogger` process resources
 *
 * Sends `SIGTERM` before `wpclose()` on every call — including when the child is already dead —
 * matching the fix for R1/I7 (a blocking `waitpid()` inside `wpclose()` on a live child is a hang risk).
 * @param lf localfile's logreader structure
 */
void w_macos_es_release(logreader * lf);

#endif /* MACOS_ES_LOG_H */
