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

/**
 * @brief Fill a log format, using only the start of the log
 *
 * The fields that come from the log ($(log), $(output), $(json_escaped_log) and $(base64_log)) take its
 * first log_len bytes, so a shorter log is escaped or encoded whole instead of being cut afterwards.
 *
 * @param builder Pointer to a log builder structure. The caller holds its read lock.
 * @param pattern Log format.
 * @param logmsg Log message.
 * @param log_len Number of bytes of logmsg to use. It is not greater than strlen(logmsg).
 * @param location Log location.
 * @param timestamp Time for the timestamp fields.
 * @param output Buffer to fill. It gets as much of the result as fits, null-terminated.
 * @param size Size of output.
 * @param report Whether to log the fields that cannot be filled. They are the same in every render of a log, so
 *               only one render reports them.
 * @return Length of the whole result. It did not fit in output if it is size or greater.
 */
STATIC size_t log_builder_render(log_builder_t * builder, const char * pattern, const char * logmsg, size_t log_len, const char * location, time_t timestamp, char * output, size_t size, bool report);

/* Number of seconds of how often the IP must be updated. */
STATIC int g_ip_update_interval = 0;

/* Host IP cache shared by every builder of the process, and the time of its last request. */
STATIC char g_host_ip[IPSIZE] = { '\0' };
STATIC time_t g_host_ip_last_update = 0;

// Initialize a log builder structure
log_builder_t * log_builder_init(bool update, bool host_ip_used) {
    log_builder_t * builder;
    os_calloc(1, sizeof(log_builder_t), builder);
    builder->host_ip_used = host_ip_used;

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
char * log_builder_build(log_builder_t * builder, const char * pattern, const char * logmsg, const char * location, size_t size) {
    char * final;
    size_t log_len;
    size_t fits;
    size_t overflows;
    size_t mid;
    size_t lead;
    time_t timestamp = time(NULL);

    assert(logmsg != NULL);

    if (!pattern) {
        return strdup(logmsg);
    }

    assert(&builder->rwlock != NULL);
    assert(size > 0);

    os_malloc(size, final);
    log_len = strlen(logmsg);

    rwlock_lock_read(&builder->rwlock);

    if (log_builder_render(builder, pattern, logmsg, log_len, location, timestamp, final, size, true) >= size) {
        // Cut the log, never the format: the format holds fields the log must not replace.
        if (log_builder_render(builder, pattern, logmsg, 0, location, timestamp, final, size, false) >= size) {
            mdebug1("Too long message format");
        } else {
            // The length grows with the part of the log used, so find the longest part that fits.
            fits = 0;
            overflows = log_len;

            while (overflows - fits > 1) {
                mid = fits + (overflows - fits) / 2;

                if (log_builder_render(builder, pattern, logmsg, mid, location, timestamp, final, size, false) < size) {
                    fits = mid;
                } else {
                    overflows = mid;
                }
            }

            // Do not split a UTF-8 character: if the cut falls inside one, cut before its first byte.
            lead = fits;

            while (lead > 0 && fits - lead < 3 && ((unsigned char)logmsg[lead] & 0xC0) == 0x80) {
                lead--;
            }

            if (((unsigned char)logmsg[lead] & 0xC0) == 0xC0) {
                fits = lead;
            }

            log_builder_render(builder, pattern, logmsg, fits, location, timestamp, final, size, false);
            mdebug1("Log cut from %lu to %lu bytes to fit in its output format.", (unsigned long)log_len, (unsigned long)fits);
        }
    }

    rwlock_unlock(&builder->rwlock);

    return final;
}

/**
 * @brief Append a string to a buffer, as far as it fits
 *
 * @param output Buffer to append to.
 * @param size Size of output.
 * @param n Length of the result so far, which may already exceed the buffer. The length of src is added to it.
 * @param src String to append.
 */
static void log_builder_append(char * output, size_t size, size_t * n, const char * src) {
    size_t z = strlen(src);

    if (*n < size - 1) {
        memcpy(output + *n, src, z < size - 1 - *n ? z : size - 1 - *n);
    }

    *n += z;
}

// Fill a log format, using only the start of the log
size_t log_builder_render(log_builder_t * builder, const char * pattern, const char * logmsg, size_t log_len, const char * location, time_t timestamp, char * output, size_t size, bool report) {
    char * _pattern;
    char * cur;
    char * tok;
    char * end;
    char * param;
    const char * field;
    char _timestamp[64];
    char * escaped_log = NULL;
    char * cut_log = NULL;
    const char * log_part = logmsg;
    size_t n = 0;

    os_strdup(pattern, _pattern);

    // log_len is not greater than strlen(logmsg), so the log is whole only if it ends at log_len.
    if (logmsg[log_len] != '\0') {
        log_part = cut_log = w_strndup(logmsg, log_len);
    }

    for (cur = _pattern; tok = strstr(cur, "$("), tok; cur = end) {
        field = NULL;
        *tok = '\0';

        // Skip $(
        param = tok + 2;

        // Copy anything before the token
        log_builder_append(output, size, &n, cur);

        if (end = strchr(param, ')'), !end) {
            // Token not closed: break
            *tok = '$';
            cur = tok;
            break;
        }

        *end++ = '\0';

        // Find parameter

        if (strcmp(param, "log") == 0 || strcmp(param, "output") == 0) {
            field = log_part;
        } else if (strcmp(param, "location") == 0 || strcmp(param, "command") == 0) {
            field = location;
        } else if (strncmp(param, "timestamp", 9) == 0) {
            struct tm tm;
            char * format;

            localtime_r(&timestamp, &tm);

            if (format = strchr(param, ' '), format) {
                if (strftime(_timestamp, sizeof(_timestamp), format + 1, &tm)) {
                    field = _timestamp;
                } else if (report) {
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
            field = escaped_log = wstr_escape_json(log_part);
        } else if (strcmp(param, "base64_log") == 0) {
            field = escaped_log = encode_base64(strlen(log_part), log_part);
        } else {
            if (report) {
                mdebug1("Invalid parameter '%s' for log format.", param);
            }

            continue;
        }

        if (field) {
            log_builder_append(output, size, &n, field);
        }

        os_free(escaped_log);
    }

    // Copy rest of the pattern
    log_builder_append(output, size, &n, cur);
    output[n < size ? n : size - 1] = '\0';

    free(_pattern);
    free(cut_log);
    return n;
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

// Check whether a log format uses the host IP
bool log_builder_uses_host_ip(const char * pattern) {
    return pattern != NULL && strstr(pattern, "$(host_ip)") != NULL;
}

// Update the host's IP value
int log_builder_update_host_ip(log_builder_t * builder) {
    time_t now = time(NULL);

    // Resolving the host IP lists every network interface, so it is skipped when no log format uses it.
    if (builder->host_ip_used && g_ip_update_interval > 0 && (now - g_host_ip_last_update) >= g_ip_update_interval) {
        g_host_ip_last_update = now;
#ifdef WIN32
        char * tmp_host_ip = get_agent_ip_legacy_win32();

        if (tmp_host_ip) {
            strncpy(g_host_ip, tmp_host_ip, IPSIZE - 1);
            os_free(tmp_host_ip);
        } else {
            mdebug1("Cannot update host IP.");
            *g_host_ip = '\0';
        }

#elif defined __linux__ || defined __MACH__ || defined sun || defined FreeBSD || defined OpenBSD
        const char * REQUEST = "host_ip";
        int sock = control_check_connection();

        if (sock == -1) {
            mdebug1("Cannot update host IP: The control module is not available: %s (%d)", strerror(errno), errno);
            g_host_ip_last_update = 0;
        } else {
            if (send(sock, REQUEST, strlen(REQUEST), 0) > 0) {
                if (recv(sock, g_host_ip, IPSIZE - 1, 0) < 0) {
                    mdebug1("The control module did not respond: %s (%d).", strerror(errno), errno);
                    *g_host_ip = '\0';
                }
            }

            close(sock);
        }
#endif
    }
    rwlock_lock_write(&builder->rwlock);
    if (*g_host_ip != '\0' && strcmp(g_host_ip, "Err")) {
        strcpy(builder->host_ip, g_host_ip);
    } else {
        strncpy(builder->host_ip, "0.0.0.0", IPSIZE - 1);
    }

    builder->host_ip[IPSIZE - 1] = '\0';
    rwlock_unlock(&builder->rwlock);

    return 0;
}
