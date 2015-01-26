/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"


#ifndef WIN32

/* Start the Message Queue. type: WRITE||READ */
int StartMQ(const char *path, short int type)
{
    if (type == READ) {
        return (OS_BindUnixDomain(path, 0660, OS_MAXSTR + 512));
    }

    /* We give up to 21 seconds for the other end to start */
    else {
        int rc = 0;
        if (File_DateofChange(path) < 0) {
            sleep(1);
            if (File_DateofChange(path) < 0) {
                sleep(5);
                if (File_DateofChange(path) < 0) {
                    merror(QUEUE_ERROR, __local_name, path, "Queue not found");
                    sleep(15);
                    if (File_DateofChange(path) < 0) {
                        return (-1);
                    }
                }
            }
        }

        /* Wait up to 3 seconds to connect to the unix domain.
         * After three errors, exit.
         */
        if ((rc = OS_ConnectUnixDomain(path, OS_MAXSTR + 256)) < 0) {
            sleep(1);
            if ((rc = OS_ConnectUnixDomain(path, OS_MAXSTR + 256)) < 0) {
                sleep(2);
                if ((rc = OS_ConnectUnixDomain(path, OS_MAXSTR + 256)) < 0) {
                    merror(QUEUE_ERROR, __local_name, path,
                           strerror(errno));
                    return (-1);
                }
            }
        }

        debug1(MSG_SOCKET_SIZE, __local_name, OS_getsocketsize(rc));
        return (rc);
    }
}

/* Send a message to the queue */
int SendMSG(int queue, const char *message, const char *locmsg, char loc)
{
    int __mq_rcode;
    char tmpstr[OS_MAXSTR + 1];

    tmpstr[OS_MAXSTR] = '\0';

    /* Check for global locks */
    os_wait();

    if (loc == SECURE_MQ) {
        loc = message[0];
        message++;

        if (message[0] != ':') {
            merror(FORMAT_ERROR, __local_name);
            return (0);
        }
        message++; /* Pointing now to the location */

        if (strncmp(message, "keepalive", 9) == 0) {
            return (0);
        }

        snprintf(tmpstr, OS_MAXSTR, "%c:%s->%s", loc, locmsg, message);
    } else {
        snprintf(tmpstr, OS_MAXSTR, "%c:%s:%s", loc, locmsg, message);
    }

    /* Queue not available */
    if (queue < 0) {
        return (-1);
    }

    /* We attempt 5 times to send the message if
     * the receiver socket is busy.
     * After the first error, we wait 1 second.
     * After the second error, we wait more 3 seconds.
     * After the third error, we wait 5 seconds.
     * After the fourth error, we wait 10 seconds.
     * If we failed again, the message is not going
     * to be delivered and an error is sent back.
     */
    if ((__mq_rcode = OS_SendUnix(queue, tmpstr, 0)) < 0) {
        /* Error on the socket */
        if (__mq_rcode == OS_SOCKTERR) {
            merror("%s: socketerr (not available).", __local_name);
            close(queue);
            return (-1);
        }

        /* Unable to send. Socket busy */
        sleep(1);
        if (OS_SendUnix(queue, tmpstr, 0) < 0) {
            /* When the socket is to busy, we may get some
             * error here. Just sleep 2 second and try
             * again.
             */
            sleep(3);
            /* merror("%s: socket busy", __local_name); */
            if (OS_SendUnix(queue, tmpstr, 0) < 0) {
                sleep(5);
                merror("%s: socket busy ..", __local_name);
                if (OS_SendUnix(queue, tmpstr, 0) < 0) {
                    sleep(10);
                    merror("%s: socket busy ..", __local_name);
                    if (OS_SendUnix(queue, tmpstr, 0) < 0) {
                        /* Message is going to be lost
                         * if the application does not care
                         * about checking the error
                         */
                        close(queue);
                        return (-1);
                    }
                }
            }
        }
    }

    return (0);
}

#endif /* !WIN32 */
