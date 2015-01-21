/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "dbd.h"

#ifndef ARGV0
#define ARGV0 "ossec-dbd"
#endif

/* Prototypes */
static void print_db_info(void);
static void help_dbd(void) __attribute__((noreturn));


/* Print information regarding enabled databases */
static void print_db_info()
{
#ifdef UMYSQL_DATABASE_ENABLED
    print_out("    Compiled with MySQL support");
#endif

#ifdef PGSQL_DATABASE_ENABLED
    print_out("    Compiled with PostgreSQL support");
#endif

#if !defined(MYSQL_DATABASE_ENABLED) && !defined(PGSQL_DATABASE_ENABLED)
    print_out("    Compiled without any database support");
#endif
}

/* Print help statement */
static void help_dbd()
{
    print_header();
    print_out("  %s: -[Vhdtfv] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", MAILUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    print_out("  Database Support:");
    print_db_info();
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    unsigned int d;

    /* Use MAILUSER (read only) */
    const char *dir  = DEFAULTDIR;
    const char *user = MAILUSER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Database Structure */
    DBConfig db_config;
    db_config.error_count = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_dbd();
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_dbd();
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Read configuration */
    if ((c = OS_ReadDBConf(test_config, cfg, &db_config)) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }

    /* Not configured */
    if (c == 0) {
        verbose("%s: Database not configured. Clean exit.", ARGV0);
        exit(0);
    }

    /* Maybe disable this debug? */
    debug1("%s: DEBUG: Connecting to '%s', using '%s', '%s', '%s', %d,'%s'.",
           ARGV0, db_config.host, db_config.user,
           db_config.pass, db_config.db, db_config.port, db_config.sock);

    /* Set config pointer */
    osdb_setconfig(&db_config);

    /* Get maximum reconnect attempts */
    db_config.maxreconnect = (unsigned int) getDefine_Int("dbd",
                             "reconnect_attempts", 1, 9999);

    /* Connect to the database */
    d = 0;
    while (d <= (db_config.maxreconnect * 10)) {
        db_config.conn = osdb_connect(db_config.host, db_config.user,
                                      db_config.pass, db_config.db,
                                      db_config.port, db_config.sock);

        /* If we are able to reconnect, keep going */
        if (db_config.conn) {
            break;
        }

        d++;
        sleep(d * 60);

    }

    /* If after the maxreconnect attempts, it still didn't work, exit here */
    if (!db_config.conn) {
        merror(DB_CONFIGERR, ARGV0);
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* We must notify that we connected -- easy debugging */
    verbose("%s: Connected to database '%s' at '%s'.",
            ARGV0, db_config.db, db_config.host);

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Now in chroot */
    nowChroot();

    /* Insert server info into the db */
    db_config.server_id = OS_Server_ReadInsertDB(&db_config);
    if (db_config.server_id <= 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Read rules and insert into the db */
    if (OS_InsertRulesDB(&db_config) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Basic start up completed */
    debug1(PRIVSEP_MSG, ARGV0, dir, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* The real daemon now */
    OS_DBD(&db_config);
}

