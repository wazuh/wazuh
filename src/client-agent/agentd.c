/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

bool needs_config_reload = false;
void reload_handler(int signum) {
    if (signum == SIGUSR1) {
        minfo("SIGNAL [(%d)-(%s)] Received. Reload agentd.", signum, strsignal(signum));
        needs_config_reload = true;
    }
}

/* Start the agent daemon */
void AgentdStart(int uid, int gid, const char *user, const char *group)
{
    int rc = 0;
    int maxfd = 0;
    fd_set fdset;
    struct timeval fdtimeout;

    available_server = 0;

    /* Initial random numbers must happen before chroot */
    srandom_init();

    /* Initialize sender */
    sender_init();

    /* Going Daemon */
    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Set group ID */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    if (agt->enrollment_cfg && agt->enrollment_cfg->enabled) {
        // If autoenrollment is enabled, we will avoid exit if there is no valid key
        OS_PassEmptyKeyfile();
    } else {
        /* Check auth keys */
        if (!OS_CheckKeys()) {
            merror_exit(AG_NOKEYS_EXIT);
        }
    }

    /* Read private keys */
    minfo(ENC_READ);
    OS_ReadKeys(&keys, W_DUAL_KEY, 0);

    minfo("Using notify time: %d and max time to reconnect: %d", agt->notify_time, agt->max_time_reconnect_try);
    if (agt->force_reconnect_interval) {
        minfo("Using force reconnect interval, Wazuh Agent will reconnect every %ld %s", w_seconds_to_time_value(agt->force_reconnect_interval), w_seconds_to_time_unit(agt->force_reconnect_interval, TRUE));
    }

    if (!getuname()) {
        merror(MEM_ERROR, errno, strerror(errno));
    } else {
        minfo("Version detected -> %s", getuname());
    }

    /* Try to connect to server */
    os_setwait();

    /* Create the queue and read from it. Exit if fails. */
    if ((agt->m_queue = StartMQ(DEFAULTQUEUE, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
    }

#ifdef HPUX
    {
        int flags;
        flags = fcntl(agt->m_queue, F_GETFL, 0);
        fcntl(agt->m_queue, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    maxfd = agt->m_queue;
    agt->sock = -1;

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    os_random();

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    /* Config SIGUSR1 as reload signal */
    struct sigaction action = { .sa_handler = reload_handler, .sa_flags = SA_RESTART };
    sigaction(SIGUSR1, &action, NULL);

    /* Launch rotation thread */
    rotate_log = getDefine_Int("monitord", "rotate_log", 0, 1);
    if (rotate_log) {
        w_create_thread(w_rotate_log_thread, (void *)NULL);
    }

    /* Launch dispatch thread */
    if (agt->buffer){

        buffer_init();

        w_create_thread(dispatch_buffer, (void *)NULL);
    } else {
        minfo(DISABLED_BUFFER);
    }

    /* Configure and start statistics */
    w_agentd_state_init();
    w_create_thread(state_main, NULL);

    /* Set max fd for select */
    if (agt->sock > maxfd) {
        maxfd = agt->sock;
    }

    start_agent(1);

    os_delwait();
    w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);

    // Ignore SIGPIPE signal to prevent the process from crashing
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

    // Start request module
    req_init();
    w_create_thread(req_receiver, NULL);

    /* Send agent stopped message at exit */
    atexit(send_agent_stopped_message);

    /* Send first notification */
    run_notify();

    /* Maxfd must be higher socket +1 */
    maxfd++;

    /* Monitor loop */
    while (1) {

        /* Continuously send notifications */
        run_notify();

        if (agt->sock > maxfd - 1) {
            maxfd = agt->sock + 1;
        }

        /* Monitor all available sockets from here */
        FD_ZERO(&fdset);
        FD_SET(agt->sock, &fdset);
        FD_SET(agt->m_queue, &fdset);

        fdtimeout.tv_sec = 1;
        fdtimeout.tv_usec = 0;

        /* Wait with a timeout for any descriptor */
        do {
            rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        } while (rc < 0 && errno == EINTR);

        if (rc == -1) {
            merror_exit(SELECT_ERROR, errno, strerror(errno));
        } else if (rc == 0) {
            continue;
        }

        /* Check the flag for pending configuration reload */
        if (needs_config_reload) {
            needs_config_reload = false;

            close(agt->execdq);
            agt->execdq=-1;

            // Update buffer configuration
            const char *cfg = OSSECCONF;
            unsigned int current_capacity = agt->buflength;
            int current_buffer_flag = agt->buffer;

            mdebug2("Buffer pre-update, enable: %i size: %i ", agt->buffer, current_capacity);

            if (ReadConfig(CBUFFER, cfg, NULL, agt) < 0) {
                mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
            }

            #ifdef CLIENT
            if (agt->flags.remote_conf) {
                ReadConfig(CBUFFER | CAGENT_CONFIG, AGENTCONFIG, NULL, agt);
                minfo("Buffer agent.conf updated, enable: %i size: %i ", agt->buffer, agt->buflength);
            }
            #endif

            //  Buffer was enabled, needs to be disabled
            if (agt->buffer == 0 && current_buffer_flag != 0) {
                w_agentd_buffer_free(current_capacity);
            } else if (current_buffer_flag == 0 && agt->buffer != 0) {
                // Buffer was disabled, needs to be enabled
                buffer_init();
                w_create_thread(dispatch_buffer, (void *)NULL);
            } else if (agt->buffer != 0) {
                // Buffer was enabled, stays enabled (potential resize)
                w_agentd_buffer_resize(current_capacity, agt->buflength);
            }

            mdebug2("Buffer updated, enable: %i size: %i ", agt->buffer, agt->buflength);
        }

        /* Connect to the execd queue */
        if (agt->execdq <= 0) {
            if ((agt->execdq = StartMQ(EXECQUEUE, WRITE, 1)) < 0) {
                minfo("Unable to connect to the active response queue (disabled).");
                agt->execdq = -1;
            }
        }

        /* For the receiver */
        if (FD_ISSET(agt->sock, &fdset)) {
            if (receive_msg() < 0) {
                w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_NACTIVE);
                merror(LOST_ERROR);
                os_setwait();
                start_agent(0);
                minfo(SERVER_UP);
                os_delwait();
                w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
            }
        }

        /* For the forwarder */
        if (FD_ISSET(agt->m_queue, &fdset)) {
            EventForward();
        }
    }
}

#if !defined(HPUX) && !defined(AIX) && !defined(SOLARIS)
bool check_uninstall_permission(const char *token, const char *host, bool ssl_verify) {
    char url[OS_SIZE_8192];
    snprintf(url, sizeof(url), "https://%s/agents/uninstall", host);

    char header[OS_SIZE_8192] = { '\0' };
    snprintf(header, sizeof(header), "Authorization: Bearer %s", token);

    char* headers[] = { NULL, NULL };
    os_strdup(header, headers[0]);

    curl_response *response = wurl_http_request(WURL_GET_METHOD, headers, url, NULL, OS_SIZE_8192, 30, NULL, ssl_verify);

    if (response) {
        if (response->status_code == 200) {
            minfo(AG_UNINSTALL_VALIDATION_GRANTED);
            wurl_free_response(response);
            os_free(headers[0]);
            return false;
        } else if (response->status_code == 403) {
            minfo(AG_UNINSTALL_VALIDATION_DENIED);
        } else {
            merror(AG_API_ERROR_CODE, response->status_code);
        }
        wurl_free_response(response);
    } else {
        merror(AG_REQUEST_FAIL);
    }

    os_free(headers[0]);
    return true;
}

char* authenticate_and_get_token(const char *userpass, const char *host, bool ssl_verify) {
    char url[OS_SIZE_8192];
    char *token = NULL;
    char* headers[] = { NULL };

    snprintf(url, sizeof(url), "https://%s/security/user/authenticate?raw=true", host);
    curl_response *response = wurl_http_request(WURL_POST_METHOD, headers, url, NULL, OS_SIZE_8192, 30, userpass, ssl_verify);

    if (response) {
        if (response->status_code == 200) {
            os_strdup(response->body, token);
        } else {
            merror(AG_API_ERROR_CODE, response->status_code);
        }
        wurl_free_response(response);
    } else {
        merror(AG_REQUEST_FAIL);
    }

    return token;
}

bool package_uninstall_validation(const char *uninstall_auth_token, const char *uninstall_auth_login, const char *uninstall_auth_host, bool ssl_verify) {
    bool validate_result = true;

    minfo(AG_UNINSTALL_VALIDATION_START);
    if (uninstall_auth_token) {
        validate_result = check_uninstall_permission(uninstall_auth_token, uninstall_auth_host, ssl_verify);
        if (validate_result) {
            return validate_result;
        }
    }
    if (uninstall_auth_login) {
        char *new_token = authenticate_and_get_token(uninstall_auth_login, uninstall_auth_host, ssl_verify);
        if (new_token) {
            validate_result = check_uninstall_permission(new_token, uninstall_auth_host, ssl_verify);
            os_free(new_token);
        } else {
            merror(AG_TOKEN_FAIL, uninstall_auth_login);
        }
    }
    return validate_result;
}
#endif
