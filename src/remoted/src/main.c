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
#include "remoted.h"
#include <openssl/crypto.h>
#include "generate_cert.h"
#include <unistd.h>

/* Prototypes */
static void help_remoted(char *home_path) __attribute__((noreturn));


/* Print help statement */
static void help_remoted(char *home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir] [-C days] [-B bits] [-K path] [-X path] [-S subject]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", WAZUHCONF);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", home_path);
    print_out("    -m          Avoid creating shared merged file (read only)");
    print_out("    -C          Specify the certificate validity in days.");
    print_out("    -B          Specify the certificate key size in bits.");
    print_out("    -K          Specify the path to store the certificate key.");
    print_out("    -X          Specify the path to store the certificate.");
    print_out("    -S          Specify the certificate subject.");
    print_out(" ");
    os_free(home_path);
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
    char cert_val[OS_SIZE_32 + 1] = "\0";
    char cert_key_bits[OS_SIZE_32 + 1] = "\0";
    char cert_key_path[PATH_MAX + 1] = "\0";
    char cert_path[PATH_MAX + 1] = "\0";
    char cert_subj[OS_MAXSTR + 1] = "\0";
    bool generate_certificate = false;
    unsigned long days_val = 0;
    unsigned long key_bits = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL) != 1) {
        merror_exit("Could not initialize OpenSSL");
    }

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    /* Isolated-test override: honor the same environment variable the Engine uses
     * (WAZUH_MANAGER_FORCE_HOME, see engine/source/base/src/process.cpp getWazuhHome()),
     * so one variable relocates both daemons into the same sandboxed tree.
     * Takes precedence over WAZUH_MANAGER_HOME (already resolved by w_homedir());
     * an explicit -D on the command line below still wins over both. */
    {
        const char *forced_home = getenv("WAZUH_MANAGER_FORCE_HOME");
        if (forced_home && *forced_home) {
            os_free(home_path);
            os_strdup(forced_home, home_path);
        }
    }

    const char *cfg = WAZUHCONF;
    const char *user = USER;
    const char *group = GROUPGLOBAL;

    while ((c = getopt(argc, argv, "Vdthfu:g:c:D:mC:B:K:X:S:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_remoted(home_path);
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
                os_free(home_path);
                os_strdup(optarg, home_path);
                break;
            case 'm':
                nocmerged = 1;
                break;
            case 'C':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                if (w_str_is_number(optarg)) {
                    generate_certificate = true;
                    if (snprintf(cert_val, OS_SIZE_32 + 1, "%s", optarg) > OS_SIZE_32) {
                        mwarn("-%c argument exceeds %d bytes. Certificate validity info truncated", c, OS_SIZE_32);
                    }
                }
                else {
                    merror_exit("-%c needs a numeric argument", c);
                }
                break;
            case 'B':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                if (w_str_is_number(optarg)) {
                    generate_certificate = true;
                    if (snprintf(cert_key_bits, OS_SIZE_32 + 1, "%s", optarg) > OS_SIZE_32) {
                        mwarn("-%c argument exceeds %d bytes. Certificate key size info truncated", c, OS_SIZE_32);
                    }
                }
                else {
                    merror_exit("-%c needs a numeric argument", c);
                }
                break;
            case 'K':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                generate_certificate = true;
                if (snprintf(cert_key_path, PATH_MAX + 1, "%s", optarg) > PATH_MAX) {
                    mwarn("-%c argument exceeds %d bytes. Certificate key path info truncated", c, PATH_MAX);
                }
                break;
            case 'X':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                generate_certificate = true;
                if (snprintf(cert_path, PATH_MAX + 1, "%s", optarg) > PATH_MAX) {
                    mwarn("-%c argument exceeds %d bytes. Certificate path info truncated", c, PATH_MAX);
                }
                break;
            case 'S':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                generate_certificate = true;
                if (snprintf(cert_subj, OS_MAXSTR + 1, "%s", optarg) > OS_MAXSTR) {
                    mwarn("-%c argument exceeds %d bytes. Certificate subject info truncated", c, OS_MAXSTR);
                }
                break;
            default:
                help_remoted(home_path);
                break;
        }
    }

    if (generate_certificate) {
        // Sanitize parameters
        if (strlen(cert_val) == 0) {
            merror_exit("Certificate expiration time not defined.");
        }

        if (strlen(cert_key_bits) == 0) {
            merror_exit("Certificate key size not defined.");
        }

        if (strlen(cert_key_path) == 0) {
            merror_exit("Key path not defined.");
        }

        if (strlen(cert_path) == 0) {
            merror_exit("Certificate path not defined.");
        }

        if (strlen(cert_subj) == 0) {
            merror_exit("Certificate subject not defined.");
        }

        if (days_val = strtol(cert_val, NULL, 10), days_val == 0) {
            merror_exit("Unable to set certificate validity to 0 days.");
        }

        if (key_bits = strtol(cert_key_bits, NULL, 10), key_bits == 0) {
            merror_exit("Unable to set certificate private key size to 0 bits.");
        }

        if (generate_cert(days_val, key_bits, cert_key_path, cert_path, cert_subj) == 0) {
            mdebug2("Certificates generated successfully.");
            exit(0);
        } else {
            merror_exit("Unable to generate HTTPS server certificates.");
        }
    }

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int_default("remoted", "debug", 0, 2, 0);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Return 0 if not configured */
    if (RemotedConfig(cfg, &logr) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    /* Exit if verify msg id is set and worker pool is greater than one */
    if ((worker_pool > 1) && (_s_verify_counter == 1)) {
        merror_exit("Message id verification can't be guaranteed when worker_pool is greater than 1.");
    }

    // Determine merge behavior: disabled by -m flag or by merge_shared config
    merge_shared = nocmerged ? 0 : merge_shared;

    // Read the cluster status and the node type from the configuration file
    switch (w_is_worker()){
        case 0:
            logr.worker_node = false;
            mdebug1("This is not a worker");
            break;
        case 1:
            logr.worker_node = true;
            mdebug1("Cluster worker node: Disabling the merged.mg creation");
            merge_shared = 0;
            break;
    }

    /* Exit if test_config is set */
    if (test_config) {
        exit(0);
    }


    /* Don't exit when client.keys empty (if set) */
    if (pass_empty_keyfile) {
        OS_PassEmptyKeyfile();
    }

    /* Check if the user and group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
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
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }
    nowChroot();
    os_free(home_path);

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    os_random();

    /* Start up message */
    mdebug2(STARTUP_MSG, (int)getpid());

    /* Really start the program */
    HandleRemote(uid);

    return (0);
}
