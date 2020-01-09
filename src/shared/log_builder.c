/**
 * @file log_builder.c
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief Definition of the shared log builder library
 * @version 0.1
 * @date 2019-12-06
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

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
static int log_builder_update_host_ip(log_builder_t * builder);

// Initialize a log builder structure
log_builder_t * log_builder_init(bool update) {
    log_builder_t * builder;
    os_calloc(1, sizeof(log_builder_t), builder);

    {
        pthread_rwlockattr_t attr;
        pthread_rwlockattr_init(&attr);

#ifdef __linux__
        /* PTHREAD_RWLOCK_PREFER_WRITER_NP is ignored.
        * Do not use recursive locking.
        */
        pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

        w_rwlock_init(&builder->rwlock, &attr);
        pthread_rwlockattr_destroy(&attr);
    }

    if (update) {
        log_builder_update(builder);
    } else {
        strncpy(builder->host_name, "localhost", LOG_BUILDER_HOSTNAME_LEN - 1);
        strncpy(builder->host_ip, "0.0.0.0", INET6_ADDRSTRLEN - 1);
    }

    return builder;
}

// Free a log builder structure.
void log_builder_destroy(log_builder_t * builder) {
    pthread_rwlock_destroy(&builder->rwlock);
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

    if (!pattern) {
        return strdup(logmsg);
    }

    os_malloc(OS_MAXSTR, final);
    os_strdup(pattern, _pattern);

    w_rwlock_rdlock(&builder->rwlock);

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

    w_rwlock_unlock(&builder->rwlock);

    strncpy(final + n, cur, OS_MAXSTR - n);
    final[n + z] = '\0';

    free(_pattern);
    return final;

fail:
    w_rwlock_unlock(&builder->rwlock);

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

    w_rwlock_wrlock(&builder->rwlock);

    if (gethostname(builder->host_name, LOG_BUILDER_HOSTNAME_LEN) != 0) {
        strncpy(builder->host_name, "localhost", LOG_BUILDER_HOSTNAME_LEN - 1);
        builder->host_name[LOG_BUILDER_HOSTNAME_LEN - 1] = '\0';
        retval = -1;
    }

    w_rwlock_unlock(&builder->rwlock);
    return retval;
}

// Update the host's IP value
int log_builder_update_host_ip(log_builder_t * builder) {
    char * host_ip = NULL;

#ifdef WIN32
    host_ip = get_agent_ip();

    if (host_ip == NULL) {
        mdebug1("Cannot update host IP.");
    }

#elif defined __linux__ || defined __MACH__ || defined sun
    const char * REQUEST = "host_ip";
    int sock = control_check_connection();

    if (sock == -1) {
        mdebug1("Cannot update host IP: The control module is not available: %s (%d)", strerror(errno), errno);
    } else {
        os_calloc(INET6_ADDRSTRLEN, sizeof(char), host_ip);

        if (send(sock, REQUEST, strlen(REQUEST), 0) > 0) {
            if (recv(sock, host_ip, INET6_ADDRSTRLEN - 1, 0) < 0) {
                mdebug1("The control module did not respond: %s (%d).", strerror(errno), errno);
                *host_ip = '\0';
            }
        }

        close(sock);

        if (*host_ip == '\0') {
            os_free(host_ip);
        }
    }

#endif
    w_rwlock_wrlock(&builder->rwlock);

    if (host_ip != NULL) {
        strncpy(builder->host_ip, host_ip, INET6_ADDRSTRLEN - 1);
        free(host_ip);
    } else {
        strncpy(builder->host_ip, "0.0.0.0", INET6_ADDRSTRLEN - 1);
    }

    builder->host_ip[INET6_ADDRSTRLEN - 1] = '\0';
    w_rwlock_unlock(&builder->rwlock);

    return 0;
}
