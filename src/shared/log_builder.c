/**
 * @file log_builder.c
 * @brief Definition of the shared log builder library
 * @date 2019-12-06
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "client-agent/agentd.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#ifdef WIN32
#define get_agent_ip_legacy_win32 wrap_get_agent_ip_legacy_win32
#define getDefine_Int __wrap_getDefine_Int
#endif
#else
#define STATIC static
#endif

/**
 * @brief Update the hostname value
 *
 * @param builder Pointer to a log builder structure.
 * @post If the hostname cannot be updated, it's replaced by "localhost".
 * @retval 0 If the hostname was updated successfully.
 * @retval 1 If the hostname failed to be updated.
 */
static int log_builder_update_hostname(log_builder_t * builder);

/**
 * @brief Update the host's IP value
 *
 * @param builder Pointer to a log builder structure.
 * @post If the host IP cannot be updated, it's replaced by "0.0.0.0".
 * @retval 0 If the host IP was updated successfully.
 * @retval 1 If the host IP failed to be updated.
 */
STATIC int log_builder_update_host_ip(log_builder_t * builder);

/* Number of seconds of how often the IP must be updated. */
STATIC int g_ip_update_interval = 0;

// Initialize a log builder structure
log_builder_t * log_builder_init(bool update) {
    log_builder_t * builder;
    os_calloc(1, sizeof(log_builder_t), builder);

    {
        g_ip_update_interval = getDefine_Int("logcollector","ip_update_interval", 0, 3600);
        rwlock_init(&builder->rwlock);
    }

    if (update) {
        log_builder_update(builder);
    } else {
        strncpy(builder->host_name, "localhost", LOG_BUILDER_HOSTNAME_LEN - 1);
        strncpy(builder->host_ip, "0.0.0.0", IPSIZE - 1);
    }

    return builder;
}

// Free a log builder structure.
void log_builder_destroy(log_builder_t * builder) {
    rwlock_destroy(&builder->rwlock);
    free(builder);
}

// Update the pattern values
int log_builder_update(log_builder_t * builder) {
    int result = 0;

    result = log_builder_update_hostname(builder) == 0 ? result : -1;
    result = log_builder_update_host_ip(builder) == 0 ? result : -1;

    return result;
}

// Build a log string
char * log_builder_build(log_builder_t * builder, const char * pattern, const char * logmsg, const char * location) {
    char * final;
    char * _pattern;
    char * cur;
    char * tok;
    char * end;
    char * param;
    const char * field;
    char _timestamp[64];
    char * escaped_log = NULL;
    size_t n = 0;
    size_t z;
    time_t timestamp = time(NULL);

    assert(logmsg != NULL);

    if (!pattern) {
        return strdup(logmsg);
    }

    assert(&builder->rwlock != NULL);

    os_malloc(OS_MAXSTR, final);
    os_strdup(pattern, _pattern);

    rwlock_lock_read(&builder->rwlock);

    for (cur = _pattern; tok = strstr(cur, "$("), tok; cur = end) {
        field = NULL;
        *tok = '\0';

        // Skip $(
        param = tok + 2;

        // Copy anything before the token
        z = strlen(cur);

        if (n + z >= OS_MAXSTR) {
            goto fail;
        }

        strncpy(final + n, cur, OS_MAXSTR - n);
        n += z;

        if (end = strchr(param, ')'), !end) {
            // Token not closed: break
            *tok = '$';
            cur = tok;
            break;
        }

        *end++ = '\0';

        // Find parameter

        if (strcmp(param, "log") == 0 || strcmp(param, "output") == 0) {
            field = logmsg;
        } else if (strcmp(param, "location") == 0 || strcmp(param, "command") == 0) {
            field = location;
        } else if (strncmp(param, "timestamp", 9) == 0) {
            struct tm tm;
            char * format;

            localtime_r(&timestamp, &tm);

            if (format = strchr(param, ' '), format) {
                if (strftime(_timestamp, sizeof(_timestamp), format + 1, &tm)) {
                    field = _timestamp;
                } else {
                    mdebug1("Cannot format time '%s': %s (%d)", format, strerror(errno), errno);
                }
            } else {
                // If format is not speficied, use RFC3164
#ifdef WIN32
                // strfrime() does not allow %e in Windows
                const char * MONTHS[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

                if (snprintf(_timestamp, sizeof(_timestamp), "%s %s%d %02d:%02d:%02d", MONTHS[tm.tm_mon], tm.tm_mday < 10 ? " " : "", tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec) < (int)sizeof(_timestamp)) {
                    field = _timestamp;
                }
#else
                if (strftime(_timestamp, sizeof(_timestamp), "%b %e %T", &tm)) {
                    field = _timestamp;
                }
#endif // WIN32
            }
        } else if (strcmp(param, "hostname") == 0) {
            field = builder->host_name;
        } else if (strcmp(param, "host_ip") == 0) {
            field = builder->host_ip;
        } else if (strcmp(param, "json_escaped_log") == 0) {
            field = escaped_log = wstr_escape_json(logmsg);
        } else if (strcmp(param, "base64_log") == 0) {
            field = escaped_log = encode_base64(strlen(logmsg), logmsg);
        } else {
            mdebug1("Invalid parameter '%s' for log format.", param);
            continue;
        }

        if (field) {
            z = strlen(field);

            if (n + z >= OS_MAXSTR) {
                goto fail;
            }

            strncpy(final + n, field, OS_MAXSTR - n);
            n += z;
        }

        os_free(escaped_log);
    }

    // Copy rest of the pattern

    z = strlen(cur);

    if (n + z >= OS_MAXSTR) {
        goto fail;
    }

    rwlock_unlock(&builder->rwlock);

    strncpy(final + n, cur, OS_MAXSTR - n);
    final[n + z] = '\0';

    free(_pattern);
    return final;

fail:
    rwlock_unlock(&builder->rwlock);

    mdebug1("Too long message format");
    strncpy(final, logmsg ? logmsg : "Too long message format", OS_MAXSTR - 1);
    final[OS_MAXSTR - 1] = '\0';
    free(_pattern);
    free(escaped_log);
    return final;
}

// Update the hostname value
int log_builder_update_hostname(log_builder_t * builder) {
    int retval = 0;

    rwlock_lock_write(&builder->rwlock);

    if (gethostname(builder->host_name, LOG_BUILDER_HOSTNAME_LEN) != 0) {
        strncpy(builder->host_name, "localhost", LOG_BUILDER_HOSTNAME_LEN - 1);
        builder->host_name[LOG_BUILDER_HOSTNAME_LEN - 1] = '\0';
        retval = -1;
    }

    rwlock_unlock(&builder->rwlock);
    return retval;
}

// Update the host's IP value
int log_builder_update_host_ip(log_builder_t * builder) {
    static char host_ip[IPSIZE] = { '\0' };
    static time_t last_update = 0;
    time_t now = time(NULL);

    if (g_ip_update_interval > 0 && (now - last_update) >= g_ip_update_interval) {
        last_update = now;
#ifdef WIN32
        char * tmp_host_ip = get_agent_ip_legacy_win32();

        if (tmp_host_ip) {
            strncpy(host_ip, tmp_host_ip, IPSIZE - 1);
            os_free(tmp_host_ip);
        } else {
            mdebug1("Cannot update host IP.");
            *host_ip = '\0';
        }

#elif defined __linux__ || defined __MACH__ || defined sun || defined FreeBSD || defined OpenBSD
        const char * REQUEST = "host_ip";
        int sock = control_check_connection();

        if (sock == -1) {
            mdebug1("Cannot update host IP: The control module is not available: %s (%d)", strerror(errno), errno);
            last_update = 0;
        } else {
            if (send(sock, REQUEST, strlen(REQUEST), 0) > 0) {
                if (recv(sock, host_ip, IPSIZE - 1, 0) < 0) {
                    mdebug1("The control module did not respond: %s (%d).", strerror(errno), errno);
                    *host_ip = '\0';
                }
            }

            close(sock);
        }
#endif
    }
    rwlock_lock_write(&builder->rwlock);
    if (*host_ip != '\0' && strcmp(host_ip, "Err")) {
        strcpy(builder->host_ip, host_ip);
    } else {
        strncpy(builder->host_ip, "0.0.0.0", IPSIZE - 1);
    }

    builder->host_ip[IPSIZE - 1] = '\0';
    rwlock_unlock(&builder->rwlock);

    return 0;
}
