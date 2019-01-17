/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

int rotate_log;

/* Start the agent daemon */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group)
{
    int rc = 0;
    int maxfd = 0;
    fd_set fdset;
    struct timeval fdtimeout;

    available_server = 0;

    /* Initial random numbers must happen before chroot */
    srandom_init();

    /* Going Daemon */
    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    minfo("Using notify time: %d and max time to reconnect: %d", agt->notify_time, agt->max_time_reconnect_try);

    if (!getuname()) {
        merror(MEM_ERROR, errno, strerror(errno));
    } else
        minfo("Version detected -> %s", getuname());

    /* Set group ID */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }
    nowChroot();

    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* Try to connect to server */
    os_setwait();

    /* Create the queue and read from it. Exit if fails. */
    if ((agt->m_queue = StartMQ(DEFAULTQUEUE, READ)) < 0) {
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

    /* Read private keys  */
    minfo(ENC_READ);

    OS_StartCounter(&keys);

    os_write_agent_info(keys.keyentries[0]->name, NULL, keys.keyentries[0]->id,
                        agt->profile);

    /*Set the crypto method for the agent */
    os_set_agent_crypto_method(&keys,agt->crypto_method);

    switch (agt->crypto_method) {
        case W_METH_AES:
            minfo("Using AES as encryption method.");
            break;
        case W_METH_BLOWFISH:
            minfo("Using Blowfish as encryption method.");
            break;
        default:
            merror("Invalid encryption method.");
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    os_random();

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    /* Launch rotation thread */

    rotate_log = getDefine_Int("monitord", "rotate_log", 0, 1);
    if (rotate_log && CreateThread(w_rotate_log_thread, (void *)NULL) != 0) {
        merror_exit(THREAD_ERROR);
    }

    /* Launch dispatch thread */
    if (agt->buffer){

        buffer_init();

        if (CreateThread(dispatch_buffer, (void *)NULL) != 0) {
            merror_exit(THREAD_ERROR);
        }
    }else{
        minfo(DISABLED_BUFFER);
    }
    /* Connect remote */
    rc = 0;
    while (rc < agt->rip_id) {
        minfo("Server IP Address: %s", agt->server[rc].rip);
        rc++;
    }

    w_create_thread(state_main, NULL);

    /* Try to connect to the server */
    if (!connect_server(0)) {
        merror_exit(UNABLE_CONN);
    }

    /* Set max fd for select */
    if (agt->sock > maxfd) {
        maxfd = agt->sock;
    }

    /* Connect to the execd queue */
    if (agt->execdq == 0) {
        if ((agt->execdq = StartMQ(EXECQUEUE, WRITE)) < 0) {
            merror("Unable to connect to the active response "
                   "queue (disabled).");
            agt->execdq = -1;
        }
    }

    start_agent(1);

    os_delwait();
    update_status(GA_STATUS_ACTIVE);

    /* Send integrity message for agent configs */
    intcheck_file(OSSECCONF, dir);
    intcheck_file(OSSEC_DEFINES, dir);

    // Start request module
    req_init();
    w_create_thread(req_receiver, NULL);

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
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        if (rc == -1) {
            merror_exit(SELECT_ERROR, errno, strerror(errno));
        } else if (rc == 0) {
            continue;
        }

        /* For the receiver */
        if (FD_ISSET(agt->sock, &fdset)) {
            if (receive_msg() < 0) {
                update_status(GA_STATUS_NACTIVE);
                merror(LOST_ERROR);
                os_setwait();
                start_agent(0);
                minfo(SERVER_UP);
                os_delwait();
                update_status(GA_STATUS_ACTIVE);
            }
        }

        /* For the forwarder */
        if (FD_ISSET(agt->m_queue, &fdset)) {
            EventForward();
        }
    }
}
