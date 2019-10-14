/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remoted.h"
#include "shared_download.h"
#include <unistd.h>

/* Set remote options to default */
static void init_conf()
{
    logr.recv_counter_flush = options.remote.recv_counter_flush.def;
    logr.comp_average_printout = options.remote.comp_average_printout.def;
    logr.verify_msg_id = options.remote.verify_msg_id.def;
    logr.pass_empty_keyfile = options.remote.pass_empty_keyfile.def;
    logr.sender_pool = options.remote.sender_pool.def;
    logr.request_pool = options.remote.request_pool.def;
    logr.request_timeout = options.remote.request_timeout.def;
    logr.response_timeout = options.remote.response_timeout.def;
    logr.request_rto_sec = options.remote.request_rto_sec.def;
    logr.request_rto_msec = options.remote.request_rto_msec.def;
    logr.max_attempts = options.remote.max_attempts.def;
    logr.shared_reload = options.remote.shared_reload.def;
    logr.rlimit_nofile = options.remote.rlimit_nofile.def;
    logr.recv_timeout = options.remote.recv_timeout.def;
    logr.send_timeout = options.remote.send_timeout.def;
    logr.nocmerged = options.remote.nocmerged.def;
    logr.keyupdate_interval = options.remote.keyupdate_interval.def;
    logr.worker_pool = options.remote.worker_pool.def;
    logr.state_interval = options.remote.state_interval.def;
    logr.guess_agent_group = options.remote.guess_agent_group.def;
    logr.group_data_flush = options.remote.group_data_flush.def;
    logr.receive_chunk = options.remote.receive_chunk.def;
    logr.buffer_relax = options.remote.buffer_relax.def;
    logr.tcp_keepidle = options.remote.tcp_keepidle.def;
    logr.tcp_keepintvl = options.remote.tcp_keepintvl.def;
    logr.tcp_keepcnt = options.remote.tcp_keepcnt.def;
    logr.log_level = options.remote.log_level.def;
    logr.thread_stack_size = options.global.thread_stack_size.def;

    return;
}

/* Set remote internal options */
static void read_internal()
{
    int aux;
    if ((aux = getDefine_Int("remoted", "recv_counter_flush", options.remote.recv_counter_flush.min, options.remote.recv_counter_flush.max)) != INT_OPT_NDEF)
        logr.recv_counter_flush = aux;
    if ((aux =  getDefine_Int("remoted", "comp_average_printout", options.remote.comp_average_printout.min, options.remote.comp_average_printout.max)) != INT_OPT_NDEF)
        logr.comp_average_printout = aux;
    if ((aux =  getDefine_Int("remoted", "verify_msg_id", options.remote.verify_msg_id.min, options.remote.verify_msg_id.max)) != INT_OPT_NDEF)
        logr.verify_msg_id = aux;
    if ((aux = getDefine_Int("remoted", "pass_empty_keyfile", options.remote.pass_empty_keyfile.min, options.remote.pass_empty_keyfile.max)) != INT_OPT_NDEF)
        logr.pass_empty_keyfile = aux;
    if ((aux = getDefine_Int("remoted", "sender_pool", options.remote.sender_pool.min, options.remote.sender_pool.max)) != INT_OPT_NDEF)
        logr.sender_pool = aux;
    if ((aux = getDefine_Int("remoted", "request_pool", options.remote.request_pool.min, options.remote.request_pool.max)) != INT_OPT_NDEF)
        logr.request_pool = aux;
    if ((aux = getDefine_Int("remoted", "request_timeout", options.remote.request_timeout.min, options.remote.request_timeout.max)) != INT_OPT_NDEF)
        logr.request_timeout = aux;
    if ((aux = getDefine_Int("remoted", "response_timeout", options.remote.response_timeout.min, options.remote.response_timeout.max)) != INT_OPT_NDEF)
        logr.response_timeout = aux;
    if ((aux = getDefine_Int("remoted", "request_rto_sec", options.remote.request_rto_sec.min, options.remote.request_rto_sec.max)) != INT_OPT_NDEF)
        logr.request_rto_sec = aux;
    if ((aux = getDefine_Int("remoted", "request_rto_msec", options.remote.request_rto_msec.min, options.remote.request_rto_msec.max)) != INT_OPT_NDEF)
        logr.request_rto_msec = aux;
    if ((aux = getDefine_Int("remoted", "max_attempts", options.remote.max_attempts.min, options.remote.max_attempts.max)) != INT_OPT_NDEF)
        logr.max_attempts = aux;
    if ((aux = getDefine_Int("remoted", "shared_reload", options.remote.shared_reload.min, options.remote.shared_reload.max)) != INT_OPT_NDEF)
        logr.shared_reload = aux;
    if ((aux = getDefine_Int("remoted", "rlimit_nofile", options.remote.rlimit_nofile.min, options.remote.rlimit_nofile.max)) != INT_OPT_NDEF)
        logr.rlimit_nofile = aux;
    if ((aux = getDefine_Int("remoted", "recv_timeout", options.remote.recv_timeout.min, options.remote.recv_timeout.max)) != INT_OPT_NDEF)
        logr.recv_timeout = aux;
    if ((aux = getDefine_Int("remoted", "send_timeout", options.remote.send_timeout.min, options.remote.send_timeout.max)) != INT_OPT_NDEF)
        logr.send_timeout = aux;
    if ((aux = getDefine_Int("remoted", "merge_shared", options.remote.nocmerged.min, options.remote.nocmerged.max)) != INT_OPT_NDEF)
        logr.nocmerged = aux;
    if ((aux = getDefine_Int("remoted", "keyupdate_interval", options.remote.keyupdate_interval.min, options.remote.keyupdate_interval.max)) != INT_OPT_NDEF)
        logr.keyupdate_interval = aux;
    if ((aux = getDefine_Int("remoted", "worker_pool", options.remote.worker_pool.min, options.remote.worker_pool.max)) != INT_OPT_NDEF)
        logr.worker_pool = aux;
    if ((aux = getDefine_Int("remoted", "state_interval", options.remote.state_interval.min, options.remote.state_interval.max)) != INT_OPT_NDEF)
        logr.state_interval = aux;
    if ((aux = getDefine_Int("remoted", "guess_agent_group", options.remote.guess_agent_group.min, options.remote.guess_agent_group.max)) != INT_OPT_NDEF)
        logr.guess_agent_group = aux;
    if ((aux = getDefine_Int("remoted", "group_data_flush", options.remote.group_data_flush.min, options.remote.group_data_flush.max)) != INT_OPT_NDEF)
        logr.group_data_flush = aux;
    if ((aux = getDefine_Int("remoted", "receive_chunk", options.remote.receive_chunk.min, options.remote.receive_chunk.max)) != INT_OPT_NDEF)
        logr.receive_chunk = aux;
    if ((aux = getDefine_Int("remoted", "buffer_relax", options.remote.buffer_relax.min, options.remote.buffer_relax.max)) != INT_OPT_NDEF)
        logr.buffer_relax = aux;
    if ((aux = getDefine_Int("remoted", "tcp_keepidle", options.remote.tcp_keepidle.min, options.remote.tcp_keepidle.max)) != INT_OPT_NDEF)
        logr.tcp_keepidle = aux;
    if ((aux = getDefine_Int("remoted", "tcp_keepintvl", options.remote.tcp_keepintvl.min, options.remote.tcp_keepintvl.max)) != INT_OPT_NDEF)
        logr.tcp_keepintvl = aux;
    if ((aux = getDefine_Int("remoted", "tcp_keepcnt", options.remote.tcp_keepintvl.min, options.remote.tcp_keepintvl.max)) != INT_OPT_NDEF)
        logr.tcp_keepcnt = aux;
    if ((aux = getDefine_Int("remoted", "debug", options.remote.log_level.min, options.remote.log_level.max)) != INT_OPT_NDEF)
        logr.log_level = aux;
    if ((aux = getDefine_Int("wazuh", "thread_stack_size", options.global.thread_stack_size.min, options.global.thread_stack_size.max)) != INT_OPT_NDEF)
        logr.thread_stack_size = aux;

    return;
}

/* Prototypes */
static void help_remoted(void) __attribute__((noreturn));


/* Print help statement */
static void help_remoted()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", REMUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -m          Avoid creating shared merged file (read only)");
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int i = 0, c = 0;
    uid_t uid;
    gid_t gid;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;
    int nocmerged = 0;

    const char *cfg = DEFAULTCPATH;
    const char *dir = DEFAULTDIR;
    const char *user = REMUSER;
    const char *group = GROUPGLOBAL;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdthfu:g:c:D:m")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_remoted();
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c need an argument");
                }
                cfg = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                dir = optarg;
                break;
            case 'm':
                nocmerged = 1;
                break;
            default:
                help_remoted();
                break;
        }
    }

    mdebug1(STARTED_MSG);

    init_conf();

    /* Return 0 if not configured */
    if (RemotedConfig(cfg, &logr) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    read_internal();

    logr.nocmerged = nocmerged ? 1 : !logr.nocmerged;

    _s_comp_print = logr.comp_average_printout;
    _s_recv_flush = logr.recv_counter_flush;
    _s_verify_counter = logr.verify_msg_id;

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = logr.log_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }


    // Don`t create the merged file in worker nodes of the cluster

    // Read the cluster status and the node type from the configuration file
    int is_worker = w_is_worker();

    switch (is_worker){
        case 0:
            mdebug1("This is not a worker");
            break;
        case 1:
            mdebug1("Cluster worker node: Disabling the merged.mg creation");
            logr.nocmerged = 1;
            break;
    }

    /* Exit if test_config is set */
    if (test_config) {
        exit(0);
    }

    if (logr.conn == NULL) {
        /* Not configured */
        minfo("Remoted connection is not configured... Exiting.");
        exit(0);
    }

    /* Don't exit when client.keys empty (if set) */
    if (logr.pass_empty_keyfile) {
        OS_PassEmptyKeyfile();
    }

    /* Check if the user and group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group);
    }

    /* Setup random */
    srandom_init();

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Set new group */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }
    nowChroot();

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    os_random();

    /* Start up message */
    mdebug2(STARTUP_MSG, (int)getpid());

    //Start shared download
    w_init_shared_download();

    /* Really start the program */
    i = 0;
    while (logr.conn[i] != 0) {
        /* Fork for each connection handler */
        if (fork() == 0) {
            /* On the child */
            mdebug1("Forking remoted: '%d'.", i);
            logr.position = i;
            HandleRemote(uid);
        } else {
            i++;
            continue;
        }
    }

    return (0);
}
