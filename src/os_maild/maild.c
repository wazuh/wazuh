/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "maild.h"
#include "mail_list.h"

#ifndef ARGV0
#define ARGV0 "wazuh-maild"
#endif

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

/* Prototypes */
static void OS_Run(MailConfig *mail) __attribute__((nonnull)) __attribute__((noreturn));
static void help_maild(char *home_path) __attribute__((noreturn));

/* Mail Structure */
MailConfig mail;

/* Print help statement */
static void help_maild(char *home_path)
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
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out("    -D <dir>    Directory to chroot and chdir into (default: %s)", home_path);
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    char *home_path = w_homedir(argv[0]);
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_maild(home_path);
                break;
            case 'd':
                nowDebug();
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
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                os_free(home_path);
                os_strdup(optarg, home_path);
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_maild(home_path);
                break;
        }
    }

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror(CHDIR_ERROR, home_path, errno, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Read configuration */
    if (MailConf(test_config, cfg, &mail) < 0) {
        merror_exit(CONFIG_ERROR, OSSECCONF);
    }

    /* Read internal options */
    mail.strict_checking = getDefine_Int("maild",
                                         "strict_checking",
                                         0, 1);

    /* Get grouping */
    mail.grouping = getDefine_Int("maild",
                                   "grouping",
                                   0, 1);

    /* Get subject type */
    mail.subject_full = getDefine_Int("maild",
                                      "full_subject",
                                      0, 1);


    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }


    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    if (!mail.mn) {
        minfo("Mail notifications are disabled. Exiting.");
        exit(0);
    }

    if (!mail.smtpserver) {
        merror_exit("SMTP server not set. Exiting.");
    }
    else if (mail.smtpserver[0] != '/') {

        char * aux_smtp_server;
        aux_smtp_server = mail.smtpserver;

        mail.smtpserver = OS_GetHost(aux_smtp_server, 5);
        if (!mail.smtpserver) {
            merror_exit(INVALID_SMTP, aux_smtp_server);
        }

        free(aux_smtp_server);

        /* chroot */
        if (Privsep_Chroot(home_path) < 0) {
            merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
        }
        nowChroot();
        mdebug1(PRIVSEP_MSG, home_path, user);
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    mdebug1(PRIVSEP_MSG, home_path, user);
    os_free(home_path);

    // Start com request thread
    w_create_thread(mailcom_main, NULL);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real daemon now */
    OS_Run(&mail);

    return (0);
}

/* Read the queue and send the appropriate alerts
 * Not supposed to return
 */
static void OS_Run(MailConfig *mail)
{
    MailMsg *msg;
    MailMsg *s_msg = NULL;
    MailMsg *msg_sms = NULL;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    int i = 0;
    int mailtosend = 0;
    int childcount = 0;
    int thishour = 0;

    int n_errs = 0;

    file_queue *fileq;

    /* Get current time before starting */
    tm = time(NULL);
    localtime_r(&tm, &tm_result);
    thishour = tm_result.tm_hour;

    /* Initialize file queue */
    os_calloc(1, sizeof(file_queue), fileq);

    switch (mail->source) {
    case MAIL_SOURCE_LOGS:
        minfo("Getting alerts in log format.");
        Init_FileQueue(fileq, &tm_result, CRALERT_MAIL_SET);
        break;

    case MAIL_SOURCE_JSON:
        minfo("Getting alerts in JSON format.");
        jqueue_init(fileq);

        if (jqueue_open(fileq, 1) < 0) {
            merror("Could not open JSON alerts file.");
        }

        break;

    default:
        merror_exit("At OS_Run(): invalid source.");
    }

    /* Create the list */
    OS_CreateMailList(MAIL_LIST_SIZE);

    /* Set default timeout */
    mail_timeout = DEFAULT_TIMEOUT;

    /* Clear global variables */
    _g_subject_level = 0;
    memset(_g_subject, '\0', SUBJECT_SIZE + 2);

    while (1) {
        tm = time(NULL);
        localtime_r(&tm, &tm_result);

        /* SMS messages are sent without delay */
        if (msg_sms) {
            pid_t pid;

            pid = fork();

            if (pid < 0) {
                merror(FORK_ERROR, errno, strerror(errno));
                sleep(30);
                continue;
            } else if (pid == 0) {
                if (OS_Sendsms(mail, &tm_result, msg_sms) < 0) {
                    merror(SNDMAIL_ERROR, mail->smtpserver);
                }

                exit(0);
            }

            /* Free SMS structure */
            FreeMailMsg(msg_sms);
            msg_sms = NULL;

            /* Increase child count */
            childcount++;
        }

        /* If mail_timeout == NEXTMAIL_TIMEOUT, we will try to get
         * more messages, before sending anything
         */
        if ((mail_timeout == NEXTMAIL_TIMEOUT) && (tm_result.tm_hour == thishour)) {
            /* Get more messages */
        }

        /* Hour changed: send all suppressed mails */
        else if (((mailtosend < mail->maxperhour) && (mailtosend != 0)) ||
                 ((tm_result.tm_hour != thishour) && (childcount < MAXCHILDPROCESS))) {
            MailNode *mailmsg;
            pid_t pid;

            /* Check if we have anything to send */
            mailmsg = OS_CheckLastMail();
            if (mailmsg == NULL) {
                /* Don't fork in here */
                goto snd_check_hour;
            }

            pid = fork();
            if (pid < 0) {
                merror(FORK_ERROR, errno, strerror(errno));
                sleep(30);
                continue;
            } else if (pid == 0) {
                if (OS_Sendmail(mail, &tm_result) < 0) {
                    merror(SNDMAIL_ERROR, mail->smtpserver);
                }

                exit(0);
            }

            /* Clean the memory */
            mailmsg = OS_PopLastMail();
            do {
                FreeMail(mailmsg);
                mailmsg = OS_PopLastMail();
            } while (mailmsg);

            /* Increase child count */
            childcount++;

            /* Clear global variables */
            _g_subject[0] = '\0';
            _g_subject[SUBJECT_SIZE - 1] = '\0';
            _g_subject_level = 0;

            /* Clean up set values */
            if (mail->gran_to) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if (s_msg && mail->gran_set[i] == DONOTGROUP) {
                        mail->gran_set[i] = FULL_FORMAT;
                    } else {
                        mail->gran_set[i] = 0;
                    }
                    i++;
                }
            }

snd_check_hour:
            /* If we sent everything */
            if (tm_result.tm_hour != thishour) {
                thishour = tm_result.tm_hour;

                mailtosend = 0;
            }
        }

        /* Saved message for the do_not_group option */
        if (s_msg) {
            /* Set the remaining do no group to full format */
            if (mail->gran_to) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if (mail->gran_set[i] == DONOTGROUP) {
                        mail->gran_set[i] = FULL_FORMAT;
                    }
                    i++;
                }
            }

            OS_AddMailtoList(s_msg);

            s_msg = NULL;
            mailtosend++;
            continue;
        }

        /* Receive message from queue */
        if (msg = mail->source == MAIL_SOURCE_LOGS ? OS_RecvMailQ(fileq, &tm_result, mail, &msg_sms) : OS_RecvMailQ_JSON(fileq, mail, &msg_sms), msg) {
            /* If the e-mail priority is do_not_group,
             * flush all previous entries and then send it.
             * Use s_msg to hold the pointer to the message while we flush it.
             */
            if (mail->priority == DONOTGROUP) {
                s_msg = msg;
            } else {
                OS_AddMailtoList(msg);
            }

            /* Change timeout to see if any new message is coming shortly */
            if (mail->grouping) {
                /* If priority is set, send email now */
                if (mail->priority) {
                    mail_timeout = DEFAULT_TIMEOUT;

                    /* If do_not_group is set, we do not increase the list count */
                    if (mail->priority != DONOTGROUP) {
                        mailtosend++;
                    }
                } else {
                    /* 5 seconds only */
                    mail_timeout = NEXTMAIL_TIMEOUT;
                }
            } else {
                /* Send message by itself */
                mailtosend++;
            }
        } else {
            if (mail_timeout == NEXTMAIL_TIMEOUT) {
                mailtosend++;

                /* Default timeout */
                mail_timeout = DEFAULT_TIMEOUT;
            }
        }

        /* Wait for the children */
        while (childcount) {
            int wp;
            int p_status;
            wp = waitpid((pid_t) - 1, &p_status, WNOHANG);
            if (wp < 0) {
                merror(WAITPID_ERROR, errno, strerror(errno));
                n_errs++;
            }

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0) {
                break;
            } else {
                if (p_status != 0) {
                    merror(CHLDWAIT_ERROR, p_status);
                    merror(SNDMAIL_ERROR, mail->smtpserver);
                    n_errs++;
                }
                childcount--;
            }

            /* Too many errors */
            if (n_errs > 6) {
                merror(TOOMANY_WAIT_ERROR);
                merror(SNDMAIL_ERROR, mail->smtpserver);
                exit(1);
            }
        }

    }
}
