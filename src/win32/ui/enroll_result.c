/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <ctype.h>
#include <string.h>
#include "os_win32ui.h"
#include "agent_auth_cli.h"

/* Kept apart from agent_enroll.c, which drives dialogs and the service, so the text the
 * message box ends up showing can be unit tested on its own. */

/* Matches the size of the report field wazuh-agent-auth prints the manager's message from;
 * anything longer did not come from the manager. */
#define MANAGER_REASON_MAX 256

void agent_auth_append_manager_reason(const char *base, const char *cli_stderr,
                                      char *out, size_t size)
{
    char reason[MANAGER_REASON_MAX];
    const char *reason_start;
    const char *start = cli_stderr != NULL ? strstr(cli_stderr, AGENT_AUTH_MANAGER_SAID) : NULL;
    size_t base_len = strlen(base);
    size_t len = 0;
    size_t i;

    if (size == 0) {
        return;
    }

    if (start != NULL) {
        start += strlen(AGENT_AUTH_MANAGER_SAID);

        /* One line only: whatever wazuh-agent-auth printed after it is its own commentary. */
        len = strcspn(start, "\r\n");

        if (len >= sizeof(reason)) {
            len = sizeof(reason) - 1;
        }

        /* The text comes from the manager; nothing in it may lay out the message box. */
        for (i = 0; i < len; i++) {
            reason[i] = iscntrl((unsigned char)start[i]) ? ' ' : start[i];
        }

        reason[len] = '\0';

        /* The trailing period is dropped because the sentence below supplies its own. */
        while (len > 0 && (reason[len - 1] == ' ' || reason[len - 1] == '.')) {
            reason[--len] = '\0';
        }
    }

    if (len == 0) {
        snprintf(out, size, "%s", base);
        return;
    }

    reason_start = reason + strspn(reason, " ");

    while (base_len > 0 && base[base_len - 1] == '.') {
        base_len--;
    }

    snprintf(out, size, "%.*s: %s.", (int)base_len, base, reason_start);
}
