/*
 * Wazuh Module Manager - exec module header
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_EXEC_H
#define WM_EXEC_H

/**
 * @brief Execute command with timeout
 * @param command Command to execute
 * @param output Command output (dynamically allocated, must be freed by caller)
 * @param exitcode Exit code of the command
 * @param secs Timeout in seconds (0 for no timeout)
 * @param add_path Additional path to prepend to PATH environment variable
 * @return 0 on success, WM_ERROR_TIMEOUT on timeout, -1 on error
 *
 * If the called program timed-out, returns WM_ERROR_TIMEOUT and output may
 * be NULL. If the called program finished correctly, returns 0 and output
 * contains the stdout of the process.
 */
int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);

#endif /* WM_EXEC_H */
