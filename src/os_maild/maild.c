/* @(#) $Id: ./src/os_maild/maild.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef MAILD
   #define MAILD
#endif

#ifndef ARGV0
   #define ARGV0 "ossec-maild"
#endif

#include "shared.h"
#include "maild.h"
#include "mail_list.h"

void OS_Run(MailConfig *mail);

int main(int argc, char **argv)
{
    int c, test_config = 0,run_foreground = 0;
    int uid = 0,gid = 0;
    char *dir  = DEFAULTDIR;
    char *user = MAILUSER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    /* Mail Structure */
    MailConfig mail;


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help(ARGV0);
                break;
        }

    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);

    /* Reading configuration */
    if(MailConf(test_config, cfg, &mail) < 0)
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);


    /* Reading internal options */
    mail.strict_checking = getDefine_Int("maild",
                                         "strict_checking",
                                          0, 1);

    /* Get groupping */
    mail.groupping = getDefine_Int("maild",
                                   "groupping",
                                    0, 1);

    /* Getting subject type */
    mail.subject_full = getDefine_Int("maild",
                                      "full_subject",
                                      0, 1);

#ifdef GEOIP
    /* Get GeoIP */
    mail.geoip = getDefine_Int("maild",
                               "geoip",
                               0, 1);
#endif


    /* Exit here if test config is set */
    if(test_config)
        exit(0);


    if(!run_foreground)
    {
        nowDaemon();
        goDaemon();
    }


    /* Privilege separation */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    nowChroot();



    /* Changing user */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    debug1(PRIVSEP_MSG,ARGV0,dir,user);



    /* Signal manipulation */
    StartSIG(ARGV0);



    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR, ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* the real daemon now */
    OS_Run(&mail);
    exit(0);
}


/* OS_Run: Read the queue and send the appropriate alerts.
 * not supposed to return..
 */
void OS_Run(MailConfig *mail)
{
    MailMsg *msg;
    MailMsg *s_msg = NULL;
    MailMsg *msg_sms = NULL;

    time_t tm;
    struct tm *p;

    int i = 0;
    int mailtosend = 0;
    int childcount = 0;
    int thishour = 0;

    int n_errs = 0;

    file_queue *fileq;


    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);
    thishour = p->tm_hour;


    /* Init file queue */
    i = 0;
    i |= CRALERT_MAIL_SET;
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, i);


    /* Creating the list */
    OS_CreateMailList(MAIL_LIST_SIZE);


    /* Setting default timeout */
    mail_timeout = DEFAULT_TIMEOUT;


    /* Clearing global vars */
    _g_subject_level = 0;
    memset(_g_subject, '\0', SUBJECT_SIZE +2);


    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);


        /* SMS messages are sent without delay */
        if(msg_sms)
        {
            pid_t pid;

            pid = fork();

            if(pid < 0)
            {
                merror("%s: Fork failed. cause: %d - %s", ARGV0, errno, strerror(errno));
                merror(FORK_ERROR, ARGV0);
                sleep(30);
                continue;
            }
            else if (pid == 0)
            {
                if(OS_Sendsms(mail, p, msg_sms) < 0)
                    merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);

                exit(0);
            }


            /* Freeing sms structure */
            FreeMailMsg(msg_sms);
            msg_sms = NULL;


            /* Increasing child count */
            childcount++;
        }


        /* If mail_timeout == NEXTMAIL_TIMEOUT, we will try to get
         * more messages, before sending anything
         */
        if((mail_timeout == NEXTMAIL_TIMEOUT) && (p->tm_hour == thishour))
        {
            /* getting more messages */
        }


        /* Hour changed. Send all supressed mails */
        else if(((mailtosend < mail->maxperhour) && (mailtosend != 0))||
                ((p->tm_hour != thishour) && (childcount < MAXCHILDPROCESS)))
        {
            MailNode *mailmsg;
            pid_t pid;

            /* Checking if we have anything to sent */
            mailmsg = OS_CheckLastMail();
            if(mailmsg == NULL)
            {
                /* dont fork in here */
                goto snd_check_hour;
            }

            pid = fork();
            if(pid < 0)
            {
                merror("%s: Fork failed. cause: %d - %s", ARGV0, errno, strerror(errno));
                merror(FORK_ERROR, ARGV0);
                sleep(30);
                continue;
            }
            else if (pid == 0)
            {
                if(OS_Sendmail(mail, p) < 0)
                    merror(SNDMAIL_ERROR,ARGV0,mail->smtpserver);

                exit(0);
            }

            /* Cleaning the memory */
            mailmsg = OS_PopLastMail();
            do
            {
                FreeMail(mailmsg);
                mailmsg = OS_PopLastMail();
            }while(mailmsg);


            /* Increasing child count */
            childcount++;


            /* Clearing global vars */
            _g_subject[0] = '\0';
            _g_subject[SUBJECT_SIZE -1] = '\0';
            _g_subject_level = 0;


            /* Cleaning up set values */
            if(mail->gran_to)
            {
                i = 0;
                while(mail->gran_to[i] != NULL)
                {
                    if(s_msg && mail->gran_set[i] == DONOTGROUP)
                    {
                        mail->gran_set[i] = FULL_FORMAT;
                    }
                    else
                    {
                        mail->gran_set[i] = 0;
                    }
                    i++;
                }
            }

            snd_check_hour:
            /* If we sent everything */
            if(p->tm_hour != thishour)
            {
                thishour = p->tm_hour;

                mailtosend = 0;
            }
        }

        /* Saved message for the do_not_group option.
         */
        if(s_msg)
        {
            /* We need to set the remaining do no group to
             * full format.
             */
            if(mail->gran_to)
            {
                i = 0;
                while(mail->gran_to[i] != NULL)
                {
                    if(mail->gran_set[i] == DONOTGROUP)
                    {
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
        if((msg = OS_RecvMailQ(fileq, p, mail, &msg_sms)) != NULL)
        {
            /* If the e-mail priority is do_not_group, we first will
             * flush all previous entries and then send it.
             * We use s_msg to hold the pointer to the message
             * while we flush it.
             */
            if(mail->priority == DONOTGROUP)
            {
                s_msg = msg;
            }
            else
            {
                OS_AddMailtoList(msg);
            }


            /* Change timeout to see if any new message is coming shortly */
            if(mail->groupping)
            {
                /* If priority is set, send email now */
                if(mail->priority)
                {
                    mail_timeout = DEFAULT_TIMEOUT;

                    /* If do_not_group is set, we do not increase the
                     * list count in here.
                     */
                    if(mail->priority != DONOTGROUP)
                    {
                        mailtosend++;
                    }
                }
                else
                {
                    /* 5 seconds only */
                    mail_timeout = NEXTMAIL_TIMEOUT;
                }
            }
            else
            {
                /* Send message by itself */
                mailtosend++;
            }
        }
        else
        {
            if(mail_timeout == NEXTMAIL_TIMEOUT)
            {
                mailtosend++;

                /* Default timeout */
                mail_timeout = DEFAULT_TIMEOUT;
            }
        }


        /* Waiting for the childs .. */
        while (childcount)
        {
            int wp;
            int p_status;
            wp = waitpid((pid_t) -1, &p_status, WNOHANG);
            if (wp < 0)
            {
                merror(WAITPID_ERROR, ARGV0);
                n_errs++;
            }

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0)
                break;
            else
            {
                if(p_status != 0)
                {
                    merror(CHLDWAIT_ERROR,ARGV0,p_status);
                    merror(SNDMAIL_ERROR,ARGV0,mail->smtpserver);
                    n_errs++;
                }
                childcount--;
            }

            /* Too many errors */
            if(n_errs > 6)
            {
                merror(TOOMANY_WAIT_ERROR,ARGV0);
                merror(SNDMAIL_ERROR,ARGV0,mail->smtpserver);
                exit(1);
            }
        }

    }
}

/* EOF */
