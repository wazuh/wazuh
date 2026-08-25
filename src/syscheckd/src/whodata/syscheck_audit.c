/*
 * Copyright (C) 2015, Wazuh Inc.
 * June 13, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef __linux__
#include "syscheck_audit.h"
#include "readproc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include "os_net.h"
#include "syscheck_op.h"
#include "audit_op.h"
#include "string_op.h"

#define AUDIT_RULES_FILE            "etc/audit_rules_wazuh.rules"
#define AUDIT_RULES_LINK            "/etc/audit/rules.d/audit_rules_wazuh.rules"
#define PLUGINS_OLD_DIR_AUDISP      "/etc/audisp/plugins.d"
#define PLUGINS_DIR_AUDIT           "/etc/audit/plugins.d"
#define AUDIT_CONF_LINK             "af_wazuh.conf"
#define BUF_SIZE OS_MAXSTR
#define MAX_CONN_RETRIES 5          // Max retries to reconnect to Audit socket

// Global variables
pthread_mutex_t audit_mutex;
pthread_mutex_t audit_rules_mutex;
pthread_cond_t audit_db_consistency;
pthread_cond_t audit_thread_started;

unsigned int count_reload_retries;

static const char *const AUDISP_CONFIGURATION_0 = "active = yes\ndirection = out\npath = builtin_af_unix\n"
                                                  "type = builtin\nargs = 0640 %s\nformat = string\n";
static const char *const AUDISP_CONFIGURATION_1 = "active = yes\ndirection = out\npath = /sbin/audisp-af_unix\n"
                                                  "type = always\nargs = 0640 %s\nformat = string\n";
static const char *const AUDISP_CONFIGURATION_2 = "active = yes\ndirection = out\npath = /sbin/audisp-af_unix\n"
                                                  "type = always\nargs = 0640 %s string\nformat = binary\n";

w_queue_t * audit_queue;

//This variable controls if the the modification of the rule is made by syscheck.

volatile int audit_db_consistency_flag = 0;
atomic_int_t audit_parse_thread_active = ATOMIC_INT_INITIALIZER(0);
atomic_int_t audit_thread_active = ATOMIC_INT_INITIALIZER(0);

#ifdef ENABLE_AUDIT
typedef struct _audit_data_s {
    int socket;
    audit_mode mode;
} audit_data_t;

/**
 * @brief Creates the necessary threads to process audit events
 *
 * @param [out] audit_data Struct that saves the audit socket to read the events from and the audit mode.
 */
static void *audit_main(audit_data_t *audit_data);

int get_audit_version_code(unsigned *out_code) {
    if (!out_code) return -1;

    FILE *p = popen("auditctl -v 2>/dev/null", "r");
    if (!p) return -1;

    int M = 0, m = 0, pch = 0;
    int n = fscanf(p, "auditctl version %d.%d.%d", &M, &m, &pch);
    pclose(p);

    if (n < 1) return -1;
    if ((unsigned)M > 255 || (unsigned)m > 255 || (unsigned)pch > 255) return -1;

    *out_code = VERCODE(M, m, pch);
    return 0;
}

int check_auditd_enabled(void) {
    PROCTAB *proc = openproc(PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLCOM );
    proc_t *proc_info;
    int auditd_pid = -1;

    if (!proc) {
        return -1;
    }

    while (proc_info = readproc(proc, NULL), proc_info != NULL) {
        if(strcmp(proc_info->cmd,"auditd") == 0) {
            auditd_pid = proc_info->tid;
            freeproc(proc_info);
            break;
        }

        freeproc(proc_info);
    }

    closeproc(proc);
    return auditd_pid;
}

int configure_audisp(const char *audisp_path, const char *abs_path_socket, const char *audisp_config) {
    FILE *fp;
    char tmp_file_path[PATH_MAX] = {'\0'};
    struct stat st;

    minfo(FIM_AUDIT_SOCKET, AUDIT_CONF_FILE);

    if (unlink(audisp_path) < 0) {
        if (errno != ENOENT) {
            merror(UNLINK_ERROR, audisp_path, errno, strerror(errno));
            return -1;
        }
    }

    if (unlink(abs_path_socket) < 0) {
        if (errno != ENOENT) {
            merror(UNLINK_ERROR, abs_path_socket, errno, strerror(errno));
            return -1;
        }
    }

    abspath(AUDIT_CONF_FILE, tmp_file_path, PATH_MAX);

    fp = wfopen(AUDIT_CONF_FILE, "w");
    if (!fp) {
        merror(FOPEN_ERROR, AUDIT_CONF_FILE, errno, strerror(errno));
        return -1;
    }

    if (fwrite(audisp_config, sizeof(char), strlen(audisp_config), fp) < strlen(audisp_config)) {
        merror(FWRITE_ERROR, AUDIT_CONF_FILE, errno, strerror(errno));
        fclose(fp);
        return -1;
    }

    if (fclose(fp)) {
        merror(FCLOSE_ERROR, AUDIT_CONF_FILE, errno, strerror(errno));
        return -1;
    }

    if (OS_MoveFile(tmp_file_path, audisp_path) < 0) {
        merror("Failed to move '%s' to '%s'", tmp_file_path, audisp_path);
        return -1;
    }

    if (syscheck.restart_audit) {
        minfo(FIM_AUDIT_RESTARTING, audisp_path);
        return audit_restart();
    } else {
        mwarn(FIM_WARN_AUDIT_CONFIGURATION_MODIFIED);
        return 1;
    }
}

/**
 * @brief Build the list of audisp plugin configurations to try, ordered by preference.
 *
 * The installed audit version tells which configuration is the most likely to work, but it cannot
 * tell a vendor rebuild that lacks the event format propagation apart from the upstream release it
 * is based on: Amazon Linux 2023 ships an audit 3.1.5 whose audisp-af_unix still takes two
 * arguments, so the three argument form rendered for that version makes the plugin fall back to
 * its own default socket. The configurations that were not selected are appended as fallbacks so
 * the caller can probe them when the preferred one does not yield a working socket.
 *
 * @param plugin_dir [out] Directory holding the audisp plugin configuration files.
 * @param templates [out] Array to fill with the configuration templates, most preferred first.
 * @param max Size of the templates array.
 * @return Number of candidates written to templates, 0 if no known plugins directory was found.
 */
int audisp_get_candidates(const char **plugin_dir, const char **templates, int max) {
    int count = 0;

#define ADD_CANDIDATE(template) do { if (count < max) { templates[count++] = (template); } } while (0)

    if (IsDir(PLUGINS_DIR_AUDIT) == 0) {
        unsigned vcode;
        *plugin_dir = PLUGINS_DIR_AUDIT;

        if (get_audit_version_code(&vcode) != 0) {
            mdebug2("Could not get audit version code. Using default configuration.");
            ADD_CANDIDATE(AUDISP_CONFIGURATION_2);
            ADD_CANDIDATE(AUDISP_CONFIGURATION_1);
        } else {
            mdebug2("Audit version detected: %u.%u.%u", (vcode >> 16) & 0xFF, (vcode >> 8) & 0xFF, vcode & 0xFF);

            if (vcode < VERCODE(3, 1, 1)) {
                // Before audit version 3.1.1 af_unix is builtin into Auditd and /sbin/audisp-af_unix
                // does not exist, so the standalone configurations are not offered as fallbacks:
                // probing them would only cost a useless Auditd restart.
                ADD_CANDIDATE(AUDISP_CONFIGURATION_0);
            } else if (vcode < VERCODE(3, 1, 5)) {
                // Audit version 3.1.1 includes changes for audispd af_unix plugin to a standalone program
                ADD_CANDIDATE(AUDISP_CONFIGURATION_1);
                ADD_CANDIDATE(AUDISP_CONFIGURATION_2);
            } else if (vcode < VERCODE(4, 0, 0)) {
                // Audit version 3.1.5 includes changes to propagate event format to the audisp-af_unix plugin
                ADD_CANDIDATE(AUDISP_CONFIGURATION_2);
                ADD_CANDIDATE(AUDISP_CONFIGURATION_1);
            } else if (vcode < VERCODE(4, 0, 3)) {
                // From audit version 4.0.0 to 4.0.2 format changes are not included
                ADD_CANDIDATE(AUDISP_CONFIGURATION_1);
                ADD_CANDIDATE(AUDISP_CONFIGURATION_2);
            } else {
                // From audit version 4.0.3 format changes are included
                ADD_CANDIDATE(AUDISP_CONFIGURATION_2);
                ADD_CANDIDATE(AUDISP_CONFIGURATION_1);
            }
        }
    } else if (IsDir(PLUGINS_OLD_DIR_AUDISP) == 0) {
        *plugin_dir = PLUGINS_OLD_DIR_AUDISP;
        ADD_CANDIDATE(AUDISP_CONFIGURATION_0);
    }

#undef ADD_CANDIDATE

    return count;
}

/**
 * @brief Render an audisp plugin configuration and report whether it matches a given SHA1.
 *
 * @param audisp_config Configuration template to render.
 * @param abs_path_socket Absolute path of the who-data socket, rendered into the template.
 * @param sha1 Digest to compare the rendered configuration against.
 * @return 1 when the rendered configuration matches, 0 otherwise.
 */
static int audisp_configuration_matches(const char *audisp_config, const char *abs_path_socket, const char *sha1) {
    char *configuration = NULL;
    os_sha1 configuration_sha1;
    int configuration_length;
    int matches;

    configuration_length = snprintf(NULL, 0, audisp_config, abs_path_socket);
    if (configuration_length <= 0) {
        return 0; // LCOV_EXCL_LINE
    }

    os_calloc((size_t)configuration_length + 1, sizeof(char), configuration);
    snprintf(configuration, (size_t)configuration_length + 1, audisp_config, abs_path_socket);
    OS_SHA1_Str(configuration, configuration_length, configuration_sha1);
    os_free(configuration);

    matches = strcmp(sha1, configuration_sha1) == 0;

    return matches;
}

/**
 * @brief Whether the audisp plugin configuration on disk is one of the known templates.
 *
 * Used to decide if a socket that is already up can be trusted: Auditd serving a socket with a
 * configuration this agent could have written is a working setup and must not be disturbed, while
 * a file that matches nothing -- tampered with, or written by an older agent -- has to be rewritten.
 *
 * @param plugin_dir Directory holding the audisp plugin configuration files.
 * @param templates Known configuration templates.
 * @param count Number of templates.
 * @return 1 when the file on disk matches one of them, 0 otherwise.
 */
int audisp_configuration_is_known(const char *plugin_dir, const char **templates, int count) {
    char audisp_path[PATH_MAX] = {'\0'};
    char abs_path_socket[PATH_MAX] = {'\0'};
    os_sha1 file_sha1;
    int i;

    if (snprintf(audisp_path, sizeof(audisp_path), "%s/%s", plugin_dir, AUDIT_CONF_LINK) >= (int)sizeof(audisp_path)) {
        return 0; // LCOV_EXCL_LINE
    }

    if (OS_SHA1_File(audisp_path, file_sha1, OS_TEXT) != 0) {
        return 0;
    }

    abspath(AUDIT_SOCKET, abs_path_socket, PATH_MAX);

    for (i = 0; i < count; i++) {
        if (audisp_configuration_matches(templates[i], abs_path_socket, file_sha1)) {
            return 1;
        }
    }

    return 0;
}

// Write the given audisp plugin configuration and restart Auditd if it changed
int set_auditd_config_template(const char *plugin_dir, const char *audisp_config) {
    char audisp_path[PATH_MAX] = {'\0'};
    char abs_path_socket[PATH_MAX] = {'\0'};
    char *configuration = NULL;
    int configuration_length;
    int retval = 1;
    os_sha1 file_sha1, configuration_sha1;

    // Build the config file path safely
    if (snprintf(audisp_path, sizeof(audisp_path), "%s/%s", plugin_dir, AUDIT_CONF_LINK) >= (int)sizeof(audisp_path)) {
        merror("audisp_path too long: base '%s', file '%s'", plugin_dir, AUDIT_CONF_LINK);
        return -1;
    }

    // Resolve absolute socket path
    abspath(AUDIT_SOCKET, abs_path_socket, PATH_MAX);

    // Compute required size for the final configuration content (template expects the socket path)
    configuration_length = snprintf(NULL, 0, audisp_config, abs_path_socket);
    if (configuration_length <= 0) {
        return -1; // LCOV_EXCL_LINE
    }

    // Allocate and render the final configuration file content
    os_calloc((size_t)configuration_length + 1, sizeof(char), configuration);
    snprintf(configuration, (size_t)configuration_length + 1, audisp_config, abs_path_socket);

    // Sanity check the configuration file
    OS_SHA1_Str(configuration, configuration_length, configuration_sha1);

    if (OS_SHA1_File(audisp_path, file_sha1, OS_TEXT) != 0) {
        // File does not exist or cannot be read; write it
        retval = configure_audisp(audisp_path, abs_path_socket, configuration);
        goto end;
    }

    if (strcmp(file_sha1, configuration_sha1) != 0) {
        // Contents differ; update file
        retval = configure_audisp(audisp_path, abs_path_socket, configuration);
        goto end;
    }

    // Check that the socket exists
    if (IsSocket(AUDIT_SOCKET) == 0) {
        retval = 0;
        goto end;
    }

    if (syscheck.restart_audit) {
        minfo(FIM_AUDIT_NOSOCKET, AUDIT_SOCKET);
        retval = audit_restart();
        goto end;
    }

    mwarn(FIM_WARN_AUDIT_SOCKET_NOEXIST, AUDIT_SOCKET);
end:
    os_free(configuration);
    return retval;
}

// Connect to the Audit events socket
static int audit_socket_connect(int quiet) {
    int sfd;

    if (sfd = OS_ConnectUnixDomain(AUDIT_SOCKET, SOCK_STREAM, OS_MAXSTR), sfd < 0) {
        if (!quiet) {
            merror(FIM_ERROR_WHODATA_SOCKET_CONNECT, AUDIT_SOCKET);
        }
        return (-1);
    }

    return sfd;
}

// Init Audit events socket
int init_auditd_socket(void) {
    return audit_socket_connect(0);
}

void audit_create_rules_file() {
    char *real_path = NULL;
    directory_t *dir_it = NULL;
    OSListNode *node_it;
    FILE *fp;

    fp = wfopen(AUDIT_RULES_FILE, "w");
    if (!fp) {
        merror(FOPEN_ERROR, AUDIT_RULES_FILE, errno, strerror(errno));
        return;
    }

    w_rwlock_rdlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if ((dir_it->options & WHODATA_ACTIVE)) {
            real_path = fim_get_real_path(dir_it);

            mdebug2(FIM_ADDED_RULE_TO_FILE, real_path);
            fprintf(fp, "-w %s -p wa -k %s\n", real_path, AUDIT_KEY);

            free(real_path);
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);

    if (fclose(fp)) {
        merror(FCLOSE_ERROR, AUDIT_RULES_FILE, errno, strerror(errno));
        return;
    }

    char abs_rules_file_path[PATH_MAX] = {'\0'};
    abspath(AUDIT_RULES_FILE, abs_rules_file_path, PATH_MAX);

    // Create symlink to audit rules file
    if (symlink(abs_rules_file_path, AUDIT_RULES_LINK) < 0) {
        if (errno != EEXIST) {
            merror(LINK_ERROR, AUDIT_RULES_LINK, abs_rules_file_path, errno, strerror(errno));
            return;
        }
        if (unlink(AUDIT_RULES_LINK) < 0) {
            merror(UNLINK_ERROR, AUDIT_RULES_LINK, errno, strerror(errno));
            return;
        }
        if (symlink(abs_rules_file_path, AUDIT_RULES_LINK) < 0) {
            merror(LINK_ERROR, AUDIT_RULES_LINK, abs_rules_file_path, errno, strerror(errno));
            return;
        }
    }

    minfo(FIM_AUDIT_CREATED_RULE_FILE);
}

void audit_rules_to_realtime() {
    char *real_path = NULL;
    directory_t *dir_it = NULL;
    OSListNode *node_it;
    int found;
    int realtime_check = 0;

    // Initialize audit_rule_list
    int auditd_fd = audit_open();
    int res = audit_get_rule_list(auditd_fd);
    audit_close(auditd_fd);

    if (!res) {
        merror(FIM_ERROR_WHODATA_READ_RULE); // LCOV_EXCL_LINE
    }

    w_rwlock_wrlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;

        if ((dir_it->options & WHODATA_ACTIVE)) {
            found = 0;
            real_path = fim_get_real_path(dir_it);

            if (search_audit_rule(real_path, WHODATA_PERMS, AUDIT_KEY) == 1) {
                free(real_path);
                continue;
            }

            for (int j = 0; syscheck.audit_key[j]; j++) {
                if (search_audit_rule(real_path, WHODATA_PERMS, syscheck.audit_key[j]) == 1) {
                    found = 1;
                    break;
                }
            }

            if (!found){
                realtime_check = 1;
                mwarn(FIM_ERROR_WHODATA_ADD_DIRECTORY, real_path);
                dir_it->options &= ~WHODATA_ACTIVE;
                dir_it->options |= REALTIME_ACTIVE;
            }

            free(real_path);
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);

    if (realtime_check) {
        w_mutex_lock(&syscheck.fim_realtime_mutex);
        if (syscheck.realtime == NULL) {
            if (realtime_start() < 0) {
                w_mutex_unlock(&syscheck.fim_realtime_mutex);
                w_rwlock_wrlock(&syscheck.directories_lock);
                OSList_foreach(node_it, syscheck.directories) {
                    dir_it = node_it->data;
                    if (dir_it->options & REALTIME_ACTIVE) {
                        dir_it->options &= ~REALTIME_ACTIVE;
                        dir_it->options |= SCHEDULED_ACTIVE;
                    }
                }
                w_rwlock_unlock(&syscheck.directories_lock);
                return;
            }
        }
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
    }
}

/**
 * @brief Connect to the who-data socket, retrying a few times before giving up.
 *
 * A socket that refuses connections is usually one left behind by a plugin that is no longer
 * running, but a transient failure -- no file descriptors left, a saturated backlog -- looks the
 * same from here, and the caller unlinks the socket on failure. A single refusal is not enough.
 *
 * @return The connected socket descriptor, or -1 if every attempt failed.
 */
static int audit_socket_connect_retry(void) {
    int attempt;
    int sfd;

    for (attempt = 0; attempt < AUDIT_SOCKET_CONNECT_RETRIES; attempt++) {
        if (sfd = audit_socket_connect(1), sfd >= 0) {
            return sfd;
        }

        if (attempt + 1 < AUDIT_SOCKET_CONNECT_RETRIES) {
            usleep(AUDIT_SOCKET_POLL_MS * 1000);
        }
    }

    return -1;
}

/**
 * @brief Wait for the audisp plugin to create the who-data socket.
 *
 * configure_audisp() removes the socket before rewriting the plugin configuration, so its
 * reappearance is what tells that Auditd came back with a plugin that honoured the configured
 * path. A misconfigured plugin binds its own default path instead and the socket never shows up.
 *
 * @return 0 if the socket is present, -1 if it did not appear before the timeout.
 */
static int wait_for_audit_socket(void) {
    int waited_ms;

    for (waited_ms = 0; waited_ms < AUDIT_SOCKET_WAIT_MS; waited_ms += AUDIT_SOCKET_POLL_MS) {
        if (IsSocket(AUDIT_SOCKET) == 0) {
            return 0;
        }

        usleep(AUDIT_SOCKET_POLL_MS * 1000);
    }

    return -1;
}

/**
 * @brief Configure the audisp plugin and connect to the who-data socket.
 *
 * The configuration expected for the installed audit version is applied first. If it does not
 * yield a socket that can be connected to, the remaining known configurations are probed, since
 * the audit version alone cannot tell whether the installed audisp-af_unix understands the event
 * format argument.
 *
 * @return The connected socket descriptor, or -1 if no configuration worked.
 */
int configure_and_connect_audit_socket(void) {
    const char *templates[MAX_AUDISP_CANDIDATES] = {NULL};
    const char *plugin_dir = NULL;
    int count;
    int sfd;
    int i;
    int previous_applied = 0;

    count = audisp_get_candidates(&plugin_dir, templates, MAX_AUDISP_CANDIDATES);

    if (count == 0) {
        // No known plugins directory found, so there is nothing to configure
        return init_auditd_socket();
    }

    if (IsSocket(AUDIT_SOCKET) == 0) {
        if (sfd = audit_socket_connect_retry(), sfd >= 0) {
            // Auditd is already serving the socket. A configuration this agent could have written
            // is a working setup, and restarting Auditd to rewrite it would be gratuitous.
            if (audisp_configuration_is_known(plugin_dir, templates, count)) {
                return sfd;
            }

            close(sfd);
            mdebug1("The audisp plugin configuration in place is not one of the known ones. Rewriting it.");
        } else if (syscheck.restart_audit) {
            // Nothing is listening: the socket was left behind by a plugin that is gone, and it
            // would otherwise make a candidate look like it took effect. It is only removed when
            // Auditd can be restarted to recreate it, so that a connection failure this agent
            // cannot recover from does not leave who-data permanently without a socket.
            if (unlink(AUDIT_SOCKET) < 0 && errno != ENOENT) {
                merror(UNLINK_ERROR, AUDIT_SOCKET, errno, strerror(errno)); // LCOV_EXCL_LINE
            }
        }
    }

    for (i = 0; i < count; i++) {
        if (i > 0) {
            if (previous_applied) {
                mdebug1("Could not establish the who-data socket '%s' with the current audisp plugin "
                        "configuration. Trying an alternative one.", AUDIT_SOCKET);
            } else {
                mdebug1("The current audisp plugin configuration could not be applied. Trying an "
                        "alternative one.");
            }
        }

        previous_applied = 0;

        switch (set_auditd_config_template(plugin_dir, templates[i])) {
        case -1:
            // This candidate could not be written or Auditd failed to restart with it. The next
            // one may still work, which is the whole point of probing.
            mdebug1(FIM_AUDIT_NOCONF);
            continue;
        case 0:
            previous_applied = 1;
            break;
        case 1:
        default:
            // The configuration was written but Auditd was not restarted, because restart_audit is
            // disabled, so no candidate can be probed.
            return -1;
        }

        if (wait_for_audit_socket() != 0) {
            continue;
        }

        // Retried for the same reason the stale socket check is: one refusal may be transient,
        // and discarding a working candidate here would settle on the wrong configuration.
        if (sfd = audit_socket_connect_retry(), sfd >= 0) {
            if (i > 0) {
                minfo(FIM_AUDIT_FALLBACK_CONFIGURATION, AUDIT_SOCKET);
            }
            return sfd;
        }
    }

    merror(FIM_ERROR_WHODATA_SOCKET_CONNECT, AUDIT_SOCKET);
    return -1;
}

// LCOV_EXCL_START
int audit_init(void) {
    static audit_data_t audit_data = { .socket = -1, .mode = AUDIT_DISABLED };

    w_mutex_init(&audit_mutex, NULL);

    // Check if auditd is installed and running.
    int aupid = check_auditd_enabled();

    if (aupid <= 0) {
        mwarn(FIM_AUDIT_NORUNNING);
        return (-1);
    }

    // Check audit socket configuration and initialize the Audit socket
    audit_data.socket = configure_and_connect_audit_socket();
    if (audit_data.socket < 0) {
        merror("Can't init auditd socket in 'init_auditd_socket()'");
        return -1;
    }

    int regex_comp = init_regex();
    if (regex_comp < 0) {
        merror("Can't init regex in 'init_regex()'");
        return -1;
    }

    if (fim_audit_rules_init() != 0) {
        return -1;
    }

    // Initialize audit queue
    audit_queue = queue_init(syscheck.queue_size);
    atomic_int_set(&audit_parse_thread_active, 1);
    w_create_thread(audit_parse_thread, NULL);

    // Print audit queue size
    minfo(FIM_AUDIT_QUEUE_SIZE, syscheck.queue_size);

    // Check for conflicting audit rules
    int auditd_check_fd = audit_open();
    if (auditd_check_fd >= 0) {
        audit_get_rule_list(auditd_check_fd);
        audit_close(auditd_check_fd);
    } else {
        mdebug1("Unable to open audit socket for conflicting rule check. Continuing without validation.");
    }

    // Perform Audit healthcheck
    if (syscheck.audit_healthcheck) {
        if(audit_health_check(audit_data.socket)) {
            merror(FIM_ERROR_WHODATA_HEALTHCHECK_START);
            return -1;
        }
    } else {
        minfo(FIM_AUDIT_HEALTHCHECK_DISABLE);
    }

    // Change to realtime directories that don't have any rules when Auditd is in immutable mode
    int auditd_fd = audit_open();
    audit_data.mode = audit_is_enabled(auditd_fd);
    audit_close(auditd_fd);

    switch (audit_data.mode) {
    case AUDIT_IMMUTABLE:
        audit_create_rules_file();
        audit_rules_to_realtime();
        break;
    case AUDIT_ENABLED:
        fim_rules_initial_load();
        atexit(clean_rules);
        break;
    case AUDIT_DISABLED:
        mwarn(FIM_AUDIT_DISABLED);
        return -1;
    default:
        merror(FIM_ERROR_AUDIT_MODE, strerror(errno), errno);
        return -1;
    }

    // Start audit thread
    w_cond_init(&audit_thread_started, NULL);
    w_cond_init(&audit_db_consistency, NULL);
    w_create_thread(audit_main, &audit_data);
    w_mutex_lock(&audit_mutex);
    while (atomic_int_get(&audit_thread_active) == 0) {
        w_cond_wait(&audit_thread_started, &audit_mutex);
    }
    w_mutex_unlock(&audit_mutex);
    return 1;

}
// LCOV_EXCL_STOP


// LCOV_EXCL_START
void audit_set_db_consistency(void) {
    w_mutex_lock(&audit_mutex);
    audit_db_consistency_flag = 1;
    w_cond_signal(&audit_db_consistency);
    w_mutex_unlock(&audit_mutex);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void *audit_main(audit_data_t *audit_data) {
    char *path = NULL;
    directory_t *dir_it = NULL;
    OSListNode *node_it;
    count_reload_retries = 0;
    atomic_int_set(&audit_thread_active,0);

    w_mutex_lock(&audit_mutex);
    atomic_int_set(&audit_thread_active, 1);
    w_cond_signal(&audit_thread_started);

    while (!audit_db_consistency_flag) {
        w_cond_wait(&audit_db_consistency, &audit_mutex);
    }

    w_mutex_unlock(&audit_mutex);

    if (audit_data->mode == AUDIT_ENABLED) {
        // Start rules reloading thread
        w_create_thread(audit_reload_thread, NULL);
    }

    minfo(FIM_WHODATA_STARTED);

    // Read events
    audit_read_events(&audit_data->socket, &audit_thread_active);

    // Auditd is not runnig or socket closed.
    mdebug1(FIM_AUDIT_THREAD_STOPED);
    close(audit_data->socket);

    // Clean regexes used for parsing events
    clean_regex();

    int realtime_started = 0;
    w_mutex_lock(&syscheck.fim_realtime_mutex);
    if (syscheck.realtime == NULL) {
        if (realtime_start() < 0) {
            realtime_started = -1;
        }
    }
    w_mutex_unlock(&syscheck.fim_realtime_mutex);

    // Change Audit monitored folders to Inotify.
    w_rwlock_wrlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if ((dir_it->options & WHODATA_ACTIVE)) {
            path = fim_get_real_path(dir_it);
            // Check if it's a broken link.
            if (*path == '\0') {
                free(path);
                continue;
            }
            dir_it->options &= ~ WHODATA_ACTIVE;

            if (realtime_started < 0) {
                dir_it->options |= SCHEDULED_ACTIVE;
            } else {
                dir_it->options |= REALTIME_ACTIVE;
                realtime_adddir(path, dir_it);
            }
            free(path);
        }
    }

    OSList_foreach(node_it, syscheck.wildcards) {
        dir_it = node_it->data;
        if ((dir_it->options & WHODATA_ACTIVE)) {
            dir_it->options &= ~ WHODATA_ACTIVE;

            if (realtime_started < 0) {
                dir_it->options |= SCHEDULED_ACTIVE;
            } else {
                dir_it->options |= REALTIME_ACTIVE;
            }
        }
    }

    w_rwlock_unlock(&syscheck.directories_lock);

    atomic_int_set(&audit_parse_thread_active, 0);

    // Clean Audit added rules.
    if (audit_data->mode == AUDIT_ENABLED) {
        clean_rules();
    }

    return NULL;
}
// LCOV_EXCL_STOP

void *audit_parse_thread() {
    char * audit_logs;

    while (atomic_int_get(&audit_parse_thread_active)) {
        audit_logs = queue_pop_ex(audit_queue);
        audit_parse(audit_logs);
        os_free(audit_logs);
    }
    queue_free(audit_queue);

    return NULL;
}

void audit_read_events(int *audit_sock, atomic_int_t *running) {
    size_t byteRead;
    char * cache;
    char * cache_id = NULL;
    char * line;
    char * endline;
    size_t cache_i = 0;
    size_t buffer_i = 0; // Buffer offset
    size_t len;
    fd_set fdset;
    struct timeval timeout;
    count_reload_retries = 0;
    int conn_retries;
    char * eoe_found = NULL;
    char * cache_dup = NULL;

    char *buffer;
    os_malloc(BUF_SIZE * sizeof(char), buffer);
    os_malloc(BUF_SIZE, cache);

    while (atomic_int_get(running)) {
        FD_ZERO(&fdset);
        FD_SET(*audit_sock, &fdset);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(*audit_sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            merror(SELECT_ERROR, errno, strerror(errno));
            sleep(1);
            continue;

        case 0:
            if (cache_i) {
                // Flush cache
                os_strdup(cache, cache_dup);
                if (queue_push_ex(audit_queue, cache_dup)) {
                    if (!audit_queue_full_reported) {
                        mwarn(FIM_FULL_AUDIT_QUEUE);
                        audit_queue_full_reported = 1;
                    }
                    os_free(cache_dup);
                }
                cache_i = 0;
            }

            continue;

        default:
            if (atomic_int_get(running) == 0) {
                continue;
            }

            break;
        }

        if (byteRead = recv(*audit_sock, buffer + buffer_i, BUF_SIZE - buffer_i - 1, 0), !byteRead) {
            // Connection closed
            mwarn(FIM_WARN_AUDIT_CONNECTION_CLOSED);
            // Reconnect
            conn_retries = 0;
            sleep(1);
            minfo(FIM_AUDIT_RECONNECT, ++conn_retries);
            *audit_sock = init_auditd_socket();
            while (conn_retries < MAX_CONN_RETRIES && *audit_sock < 0) {
                minfo(FIM_AUDIT_RECONNECT, ++conn_retries);
                sleep(1);
                *audit_sock = init_auditd_socket();
            }
            if (*audit_sock >= 0) {
                minfo(FIM_AUDIT_CONNECT);
                // Reload rules
                fim_audit_reload_rules();
                continue;
            }
            // Send alert
            char msg_alert[512 + 1];
            snprintf(msg_alert, 512, "wazuh: Audit: Connection closed");
            SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
            break;
        }

        buffer[buffer_i += byteRead] = '\0';

        // Find first endline

        if (endline = strchr(buffer, '\n'), !endline) {
            // No complete line yet.
            continue;
        }

        // Get all the lines
        line = buffer;

        char * id;
        char *event_too_long_id = NULL;

        do {
            *endline = '\0';

            if (id = audit_get_id(line), id) {
                // If there was cached data and the ID is different, parse cache first

                if (cache_id && strcmp(cache_id, id) && cache_i) {
                    if (!event_too_long_id) {
                        os_strdup(cache, cache_dup);
                        if (queue_push_ex(audit_queue, cache_dup)) {
                            if (!audit_queue_full_reported) {
                                mwarn(FIM_FULL_AUDIT_QUEUE);
                                audit_queue_full_reported = 1;
                            }
                            os_free(cache_dup);
                        }
                    }
                    cache_i = 0;
                }

                // Append to cache
                len = endline - line;
                if (cache_i + len + 1 <= BUF_SIZE) {
                    strncpy(cache + cache_i, line, len);
                    cache_i += len;
                    cache[cache_i++] = '\n';
                    cache[cache_i] = '\0';
                } else if (!event_too_long_id){
                    mwarn(FIM_WARN_WHODATA_EVENT_TOOLONG, id);
                    os_strdup(id, event_too_long_id);
                }
                eoe_found = strstr(line, "type=EOE");

                free(cache_id);
                cache_id = id;
            } else {
                mwarn(FIM_WARN_WHODATA_GETID, line);
            }

            line = endline + 1;
        } while (*line && (endline = strchr(line, '\n'), endline));

        // If some audit log remains in the cache and it is complet (line "end of event" is found), flush cache
        if (eoe_found && !event_too_long_id){
            os_strdup(cache, cache_dup);
            if (queue_push_ex(audit_queue, cache_dup)) {
                if (!audit_queue_full_reported) {
                    mwarn(FIM_FULL_AUDIT_QUEUE);
                    audit_queue_full_reported = 1;
                }
                os_free(cache_dup);
            }
            cache_i = 0;
        }

        // If some data remains in the buffer, move it to the beginning
        if (*line) {
            buffer_i = strlen(line);
            memmove(buffer, line, buffer_i);
        } else {
            buffer_i = 0;
        }

        os_free(event_too_long_id);
    }

    free(cache_id);
    free(cache);
    free(buffer);
}

#endif
#endif
