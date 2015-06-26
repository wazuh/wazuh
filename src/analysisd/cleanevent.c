/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cleanevent.h"

#include "shared.h"
#include "os_regex/os_regex.h"
#include "analysisd.h"
#include "fts.h"
#include "config.h"

/* To translate between month (int) to month (char) */
static const char *(month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                  };


/* Format a received message in the Eventinfo structure */
int OS_CleanMSG(char *msg, Eventinfo *lf)
{
    size_t loglen;
    char *pieces;
    struct tm *p;

    /* The message is formatted in the following way:
     * id:location:message.
     */

    /* Ignore the id of the message in here */
    msg += 2;

    /* Set pieces as the message */
    pieces = strchr(msg, ':');
    if (!pieces) {
        merror(FORMAT_ERROR, ARGV0);
        return (-1);
    }

    /* Is this from an agent? */
    if ( *msg == '(' )
    {   /* look past '->' for the first ':' */
        pieces = strchr(strstr(msg, "->"), ':');
        if(!pieces)
        {
            merror(FORMAT_ERROR, ARGV0);
            return(-1);
        }
    }

    *pieces = '\0';
    pieces++;

    os_strdup(msg, lf->location);

    /* Get the log length */
    loglen = strlen(pieces) + 1;

    /* Assign the values in the strucuture (lf->full_log) */
    os_malloc((2 * loglen) + 1, lf->full_log);

    /* Set the whole message at full_log */
    strncpy(lf->full_log, pieces, loglen);

    /* Log is the one used for parsing in the decoders and rules */
    lf->log = lf->full_log + loglen;
    strncpy(lf->log, pieces, loglen);

    /* check if month contains an umlaut and repair
     * umlauts are non-ASCII and use 2 slots in the char array
     * repair to only one slot so we can detect the correct date format in the next step
     * ex: Mär 02 17:30:52
     */
    if (pieces[1] == (char) 195) {
        if (pieces[2] == (char) 164) {
            pieces[0] = '\0';
            pieces[1] = 'M';
            pieces[2] = 'a';
            pieces++;
        }
    }

    /* Check for the syslog date format
     * ( ex: Dec 29 10:00:01
     *   or  2007-06-14T15:48:55-04:00 for syslog-ng isodate
     *   or  2009-05-22T09:36:46.214994-07:00 for rsyslog )
     *   or  2015-04-16 21:51:02,805 (proftpd 1.3.5)
     */
    if (
        (
            (loglen > 17) &&
            (pieces[3] == ' ') &&
            (pieces[6] == ' ') &&
            (pieces[9] == ':') &&
            (pieces[12] == ':') &&
            (pieces[15] == ' ') && (lf->log += 16)
        )
        ||
	(
	    (loglen > 24) && 
	    (pieces[4] == '-') &&
	    (pieces[7] == '-') &&
	    (pieces[10] == ' ') &&
	    (pieces[13] == ':') &&
	    (pieces[16] == ':') &&
	    (pieces[19] == ',') &&
	    (lf->log += 23)
	)
	||
        (
            (loglen > 33) &&
            (pieces[4] == '-') &&
            (pieces[7] == '-') &&
            (pieces[10] == 'T') &&
            (pieces[13] == ':') &&
            (pieces[16] == ':') &&

            (
                ((pieces[22] == ':') &&
                 (pieces[25] == ' ') && (lf->log += 26)) ||

                ((pieces[19] == '.') &&
                 (pieces[29] == ':') && (lf->log += 32))
            )
        )
    ) {
        /* Check for an extra space in here */
        if (*lf->log == ' ') {
            lf->log++;
        }


        /* Hostname */
        pieces = lf->hostname = lf->log;


        /* Check for a valid hostname */
        while (isValidChar(*pieces) == 1) {
            pieces++;
        }

        /* Check if it is a syslog without hostname (common on Solaris) */
        if (*pieces == ':' && pieces[1] == ' ') {
            /* Getting solaris 8/9 messages without hostname.
             * In these cases, the process_name should be there.
             * http://www.ossec.net/wiki/index.php/Log_Samples_Solaris
             */
            lf->program_name = lf->hostname;
            lf->hostname = NULL;

            /* End the program name string */
            *pieces = '\0';

            pieces += 2;
            lf->log = pieces;
        }

        /* Extract the hostname */
        else if (*pieces != ' ') {
            /* Invalid hostname */
            lf->hostname = NULL;
            pieces = NULL;
        } else {
            /* End the hostname string */
            *pieces = '\0';

            /* Move pieces to the beginning of the log message */
            pieces++;
            lf->log = pieces;

            /* Get program_name */
            lf->program_name = pieces;

            /* Extract program_name */
            /* Valid names:
             * p_name:
             * p_name[pid]:
             * p_name[pid]: [ID xx facility.severity]
             * auth|security:info p_name:
             */
            while (isValidChar(*pieces) == 1) {
                pieces++;
            }

            /* Check for the first format: p_name: */
            if ((*pieces == ':') && (pieces[1] == ' ')) {
                *pieces = '\0';
                pieces += 2;
            }

            /* Check for the second format: p_name[pid]: */
            else if ((*pieces == '[') && (isdigit((int)pieces[1]))) {
                *pieces = '\0';
                pieces += 2;
                while (isdigit((int)*pieces)) {
                    pieces++;
                }

                if ((*pieces == ']') && (pieces[1] == ':') && (pieces[2] == ' ')) {
                    pieces += 3;
                }
                /* Some systems are not terminating the program name with
                 * a ':'. Working around this in here...
                 */
                else if ((*pieces == ']') && (pieces[1] == ' ')) {
                    pieces += 2;
                } else {
                    /* Fix for some weird log formats */
                    pieces--;
                    while (isdigit((int)*pieces)) {
                        pieces--;
                    }

                    if (*pieces == '\0') {
                        *pieces = '[';
                    }
                    pieces = NULL;
                    lf->program_name = NULL;
                }
            }
            /* AIX syslog */
            else if ((*pieces == '|') && islower((int)pieces[1])) {
                pieces += 2;

                /* Remove facility */
                while (isalnum((int)*pieces)) {
                    pieces++;
                }

                if (*pieces == ':') {
                    /* Remove severity */
                    pieces++;
                    while (isalnum((int)*pieces)) {
                        pieces++;
                    }

                    if (*pieces == ' ') {
                        pieces++;
                        lf->program_name = pieces;


                        /* Get program name again */
                        while (isValidChar(*pieces) == 1) {
                            pieces++;
                        }

                        /* Check for the first format: p_name: */
                        if ((*pieces == ':') && (pieces[1] == ' ')) {
                            *pieces = '\0';
                            pieces += 2;
                        }

                        /* Check for the second format: p_name[pid]: */
                        else if ((*pieces == '[') && (isdigit((int)pieces[1]))) {
                            *pieces = '\0';
                            pieces += 2;
                            while (isdigit((int)*pieces)) {
                                pieces++;
                            }

                            if ((*pieces == ']') && (pieces[1] == ':') &&
                                    (pieces[2] == ' ')) {
                                pieces += 3;
                            } else {
                                pieces = NULL;
                            }
                        }
                    } else {
                        pieces = NULL;
                        lf->program_name = NULL;
                    }
                }
                /* Invalid AIX */
                else {
                    pieces = NULL;
                    lf->program_name = NULL;
                }
            } else {
                pieces = NULL;
                lf->program_name = NULL;
            }
        }

        /* Remove [ID xx facility.severity] */
        if (pieces) {
            /* Set log after program name */
            lf->log = pieces;

            if ((pieces[0] == '[') &&
                    (pieces[1] == 'I') &&
                    (pieces[2] == 'D') &&
                    (pieces[3] == ' ')) {
                pieces += 4;

                /* Going after the ] */
                pieces = strchr(pieces, ']');
                if (pieces) {
                    pieces += 2;
                    lf->log = pieces;
                }
            }
        }

        /* Get program name size */
        if (lf->program_name) {
            lf->p_name_size = strlen(lf->program_name);
        }
    }

    /* xferlog date format
     * Mon Apr 17 18:27:14 2006 1 64.160.42.130
     */
    else if ((loglen > 28) &&
             (pieces[3] == ' ') &&
             (pieces[7] == ' ') &&
             (pieces[10] == ' ') &&
             (pieces[13] == ':') &&
             (pieces[16] == ':') &&
             (pieces[19] == ' ') &&
             (pieces[24] == ' ') &&
             (pieces[26] == ' ')) {
        /* Move log to the beginning of the message */
        lf->log += 24;
    }

    /* Check for snort date format
     * ex: 01/28-09:13:16.240702  [**]
     */
    else if ( (loglen > 24) &&
              (pieces[2] == '/') &&
              (pieces[5] == '-') &&
              (pieces[8] == ':') &&
              (pieces[11] == ':') &&
              (pieces[14] == '.') &&
              (pieces[21] == ' ') ) {
        lf->log += 23;
    }

    /* Check for suricata (new) date format
     * ex: 01/28/1979-09:13:16.240702  [**]
     */
    else if ( (loglen > 26) &&
              (pieces[2] == '/') &&
              (pieces[5] == '/') &&
              (pieces[10] == '-') &&
              (pieces[13] == ':') &&
              (pieces[16] == ':') &&
              (pieces[19] == '.') &&
              (pieces[26] == ' ') ) {
        lf->log += 28;
    }


    /* Check for apache log format */
    /* [Fri Feb 11 18:06:35 2004] [warn] */
    else if ( (loglen > 27) &&
              (pieces[0] == '[') &&
              (pieces[4] == ' ') &&
              (pieces[8] == ' ') &&
              (pieces[11] == ' ') &&
              (pieces[14] == ':') &&
              (pieces[17] == ':') &&
              (pieces[20] == ' ') &&
              (pieces[25] == ']') ) {
        lf->log += 27;
    }

    /* Check for the osx asl log format.
     * Examples:
     * [Time 2006.12.28 15:53:55 UTC] [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: Authentication failure for username from 192.168.0.2] [Level 3] [UID -2] [GID -2] [Host Hostname]
     * [Time 2006.11.02 14:02:11 UTC] [Facility auth] [Sender sshd] [PID 856]
     [Message refused connect from 59.124.44.34] [Level 4] [UID -2] [GID -2]
     [Host robert-wyatts-emac]
     */
    else if ((loglen > 26) &&
             (pieces[0] == '[')  &&
             (pieces[1] == 'T')  &&
             (pieces[5] == ' ')  &&
             (pieces[10] == '.') &&
             (pieces[13] == '.') &&
             (pieces[16] == ' ') &&
             (pieces[19] == ':')) {
        /* Do not read more than 1 message entry -> log tampering */
        short unsigned int done_message = 0;

        /* Remove the date */
        lf->log += 25;

        /* Get the desired values */
        pieces = strchr(lf->log, '[');
        while (pieces) {
            pieces++;

            /* Get the sender (set to program name) */
            if ((strncmp(pieces, "Sender ", 7) == 0) &&
                    (lf->program_name == NULL)) {
                pieces += 7;
                lf->program_name = pieces;

                /* Get the closing brackets */
                pieces = strchr(pieces, ']');
                if (pieces) {
                    *pieces = '\0';

                    /* Set program_name size */
                    lf->p_name_size = strlen(lf->program_name);

                    pieces++;
                }
                /* Invalid program name */
                else {
                    lf->program_name = NULL;
                    break;
                }
            }

            /* Get message */
            else if ((strncmp(pieces, "Message ", 8) == 0) &&
                     (done_message == 0)) {
                pieces += 8;
                done_message = 1;

                lf->log = pieces;

                /* Get the closing brackets */
                pieces = strchr(pieces, ']');
                if (pieces) {
                    *pieces = '\0';
                    pieces++;
                }
                /* Invalid log closure */
                else {
                    break;
                }
            }

            /* Get hostname */
            else if (strncmp(pieces, "Host ", 5) == 0) {
                pieces += 5;
                lf->hostname = pieces;

                /* Get the closing brackets */
                pieces = strchr(pieces, ']');
                if (pieces) {
                    *pieces = '\0';
                    pieces++;
                }

                /* Invalid hostname */
                else {
                    lf->hostname = NULL;
                }
                break;
            }

            /* Get next entry */
            pieces = strchr(pieces, '[');
        }
    }

    /* Check for squid date format
     * 1140804070.368  11623
     * seconds from 00:00:00 1970-01-01 UTC
     */
    else if ((loglen > 32) &&
             (pieces[0] == '1') &&
             (isdigit((int)pieces[1])) &&
             (isdigit((int)pieces[2])) &&
             (isdigit((int)pieces[3])) &&
             (pieces[10] == '.') &&
             (isdigit((int)pieces[13])) &&
             (pieces[14] == ' ') &&
             ((pieces[21] == ' ') || (pieces[22] == ' '))) {
        lf->log += 14;

        /* We need to start at the size of the event */
        while (*lf->log == ' ') {
            lf->log++;
        }
    }

    /* Every message must be in the format
     * hostname->location or
     * (agent) ip->location.
     */

    /* Set hostname for local messages */
    if (lf->location[0] == '(') {
        /* Messages from an agent */
        lf->hostname = lf->location;
    } else if (lf->hostname == NULL) {
        lf->hostname = __shost;
    }

    /* Set up the event data */
    lf->time = c_time;
    p = localtime(&c_time);

    /* Assign hour, day, year and month values */
    lf->day = p->tm_mday;
    lf->year = p->tm_year + 1900;
    strncpy(lf->mon, month[p->tm_mon], 3);
    snprintf(lf->hour, 9, "%02d:%02d:%02d",
             p->tm_hour,
             p->tm_min,
             p->tm_sec);

    /* Set the global hour/weekday */
    __crt_hour = p->tm_hour;
    __crt_wday = p->tm_wday;

#ifdef TESTRULE
    if (!alert_only) {
        print_out("**Phase 1: Completed pre-decoding.");
        print_out("       full event: '%s'", lf->full_log);
        print_out("       hostname: '%s'", lf->hostname);
        print_out("       program_name: '%s'", lf->program_name);
        print_out("       log: '%s'", lf->log);
    }
#endif
    return (0);
}

