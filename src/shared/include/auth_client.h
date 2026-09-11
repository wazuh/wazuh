/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

// Remove agent. Returns 0 on success or -1 on error.
int auth_remove_agent(int sock, const char *id, int json_format);

/**
 * @brief Remove an agent, reporting authd's own error code instead of collapsing it to -1.
 *
 * WHY THIS EXISTS BESIDE auth_remove_agent(), which does the same request. That one is written for
 * the command-line tools: it calls merror_exit() on every transport and protocol failure, and
 * prints the raw response to stdout when asked for JSON. Both are right for a short-lived process
 * whose only job is the removal, and both are fatal inside a long-lived daemon -- a wedged authd
 * would take modulesd down with it, and a stray write to stdout would go to the daemon's console.
 *
 * It also collapses every failure to -1, which loses the one distinction a retention sweep needs:
 * a deletion refused because authd's backlog is full is worth retrying, and an agent that is
 * already gone is not a failure at all.
 *
 * The caller supplies the socket, so the deadline is the caller's to set -- see
 * auth_connect_timeout().
 *
 * @param[in] sock Connected authd local socket.
 * @param[in] id Agent id to remove.
 * @param[out] error_code authd's error field: 0 on success, one of the 90xx codes otherwise.
 *             Written only when authd answered. May be NULL.
 * @return 0 when authd answered, whatever it answered; -1 when it did not.
 */
int auth_remove_agent_code(int sock, const char *id, int *error_code);

#endif /* AUTH_CLIENT_H */
