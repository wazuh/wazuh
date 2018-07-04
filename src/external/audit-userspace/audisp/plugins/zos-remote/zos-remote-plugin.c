/***************************************************************************
*   Copyright (C) 2007 International Business Machines  Corp.             *
*   All Rights Reserved.                                                  *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
*                                                                         *
* Authors:                                                                *
*   Klaus Heinrich Kiwi <klausk@br.ibm.com>                               *
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <lber.h>
#include <netinet/in.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "auparse.h"
#include "zos-remote-log.h"
#include "zos-remote-ldap.h"
#include "zos-remote-config.h"
#include "zos-remote-queue.h"

#define UNUSED(x) (void)(x)

/*
 * Global vars 
 */
volatile int stop = 0;
volatile int hup = 0;
volatile ZOS_REMOTE zos_remote_inst;
static plugin_conf_t conf;
static const char *def_config_file = "/etc/audisp/zos-remote.conf";
static pthread_t submission_thread;
pid_t mypid = 0;

/*
 * SIGTERM handler 
 */
static void term_handler(int sig)
{
	UNUSED(sig);
        log_info("Got Termination signal - shutting down plugin");
        stop = 1;
        nudge_queue();
}

/*
 * SIGHUP handler - re-read config, reconnect to ITDS
 */
static void hup_handler(int sig)
{
	UNUSED(sig);
        log_info("Got Hangup signal - flushing plugin configuration");
        hup = 1;
        nudge_queue();
}

/*
 * SIGALRM handler - help force exit when terminating daemon
 */
static void alarm_handler(int sig)
{
	UNUSED(sig);
        log_err("Timeout waiting for submission thread - Aborting (some events may have been dropped)");
        pthread_cancel(submission_thread);
}

/*
 * The submission thread
 * It's job is to dequeue the events from the queue
 * and sync submit them to ITDS
 */
static void *submission_thread_main(void *arg)
{
        int rc;

	UNUSED(arg);
        log_debug("Starting event submission thread");
        
        rc = zos_remote_init(&zos_remote_inst, conf.server, 
                          conf.port, conf.user,
                          conf.password,
                          conf.timeout);
                          
        if (rc != ICTX_SUCCESS) {
                log_err("Error - Failed to initialize session to z/OS ITDS Server");
                stop = 1;
                return 0;
        }
        
        while (stop == 0) {
                /* block until we have an event */
                BerElement *ber = dequeue();

                if (ber == NULL) {
                        if (hup) {
                                break;
                        }
                        continue;
                }
                debug_ber(ber);
                rc = submit_request_s(&zos_remote_inst, ber);
                if (rc == ICTX_E_FATAL) {
                        log_err("Error - Fatal error in event submission. Aborting");
                        stop = 1;
                } else if (rc != ICTX_SUCCESS) {
                        log_warn("Warning - Event submission failure - event dropped");
                }
                else {
                        log_debug("Event submission success");
                }
                ber_free(ber, 1);        /* also free BER buffer */
        }
        log_debug("Stopping event submission thread");
        zos_remote_destroy(&zos_remote_inst);
        
        return 0;
}
            

/* 
 * auparse library callback that's called when an event is ready
 */
void
push_event(auparse_state_t * au, auparse_cb_event_t cb_event_type,
           void *user_data)
{
        int rc;
        BerElement *ber;
        int qualifier;
        char timestamp[26];
        char linkValue[ZOS_REMOTE_LINK_VALUE_SIZE];
        char logString[ZOS_REMOTE_LOGSTRING_SIZE];
        unsigned long linkValue_tmp;

	UNUSED(user_data);
        if (cb_event_type != AUPARSE_CB_EVENT_READY)
                return;
                
        const au_event_t *e = auparse_get_timestamp(au);
        if (e == NULL)
                return;
        /*
         * we have an event. Each record will result in a different 'Item'
         * (refer ASN.1 definition in zos-remote-ldap.h) 
         */
        
        /*
         * Create a new BER element to encode the request
         */
        ber = ber_alloc_t(LBER_USE_DER);
        if (ber == NULL) {
            log_err("Error allocating memory for BER element");
            goto fatal;
        }

        /*
         * Collect some information to fill in every item
         */
        const char *node = auparse_get_node(au);
        const char *orig_type = auparse_find_field(au, "type");
        /* roll back event to get 'success' */
        auparse_first_record(au);
        const char *success = auparse_find_field(au, "success");
        /* roll back event to get 'res' */
        auparse_first_record(au);
        const char *res = auparse_find_field(au, "res");
        
        /* check if this event is a success or failure one */
        if (success) {
                if (strncmp(success, "0", 1) == 0 ||
                    strncmp(success, "no", 2) == 0)
                        qualifier = ZOS_REMOTE_QUALIF_FAIL;
                else
                        qualifier = ZOS_REMOTE_QUALIF_SUCCESS;
        } else if (res) {
                if (strncmp(res, "0", 1) == 0
                    || strncmp(res, "failed", 6) == 0)
                        qualifier = ZOS_REMOTE_QUALIF_FAIL;
                else
                        qualifier = ZOS_REMOTE_QUALIF_SUCCESS;
        } else
                qualifier = ZOS_REMOTE_QUALIF_INFO;
                
        /* get timestamp text */
        ctime_r(&e->sec, timestamp);
        timestamp[24] = '\0';    /* strip \n' */
        
        /* prepare linkValue which will be used for every item */
        linkValue_tmp = htonl(e->serial);        /* padronize to use network
                                                  * byte order 
                                                  */
        memset(&linkValue, 0, ZOS_REMOTE_LINK_VALUE_SIZE);
        memcpy(&linkValue, &linkValue_tmp, sizeof(unsigned long));        

        /* 
         * Prepare the logString with some meaningful text
         * We assume the first record type found is the
         * 'originating' audit record
         */
        sprintf(logString, "Linux (%s): type: %s", node, orig_type);
	free((void *)node);

        /* 
         * Start writing to BER element.
         * There's only one field (version) out of the item sequence.
         * Also open item sequence
         */
        rc = ber_printf(ber, "{i{", ICTX_REQUESTVER);
        if (rc < 0)
                goto skip_event;

        /* 
         * Roll back to first record and iterate through all records
         */
        auparse_first_record(au);
        do {
                const char *type = auparse_find_field(au, "type");
                if (type == NULL)
                        goto skip_event;
                
                log_debug("got record: %s", auparse_get_record_text(au));

                /* 
                 * First field is item Version, same as global version
                 */
                rc = ber_printf(ber, "{i", ICTX_REQUESTVER);

                /*
                 * Second field is the itemTag
                 * use our internal event counter, increasing it
                 */
                rc |= ber_printf(ber, "i", conf.counter++);

                /*
                 * Third field is the linkValue
                 * using ber_put_ostring since it is not null-terminated
                 */
                rc |= ber_put_ostring(ber, linkValue,
                                      ZOS_REMOTE_LINK_VALUE_SIZE,
                                      LBER_OCTETSTRING);
                /*
                 * Fourth field is the violation
                 * Don't have anything better yet to put here
                 */
                rc |= ber_printf(ber, "b", 0);
                
                /* 
                 * Fifth field is the event.
                 * FIXME: this might be the place to switch on the
                 * audit record type and map to a more meaningful
                 * SMF type 83, subtype 4 event here
                 */
                rc |= ber_printf(ber, "i", ZOS_REMOTE_EVENT_AUTHORIZATION);
                
                /*
                 * Sixth field is the qualifier. We map 'success' or
                 * 'res' to this field
                 */
                rc |= ber_printf(ber, "i", qualifier);
                
                /* 
                 * Seventh field is the Class
                 * always use '@LINUX' for this version
                 * max size ZOS_REMOTE_CLASS_SIZE
                 */
                rc |= ber_printf(ber, "t", ASN1_IA5STRING_TAG);
                rc |= ber_printf(ber, "s", "@LINUX");
                
                /* 
                 * Eighth field is the resource
                 * use the record type (name) as the resource
                 * max size ZOS_REMOTE_RESOURCE_SIZE
                 */
                rc |= ber_printf(ber, "t", ASN1_IA5STRING_TAG);
                rc |= ber_printf(ber, "s", type);
                
                /* 
                 * Nineth field is the LogString
                 * we try to put something meaningful here
                 * we also start the relocations sequence
                 */
                rc |= ber_printf(ber, "t", ASN1_IA5STRING_TAG);
                rc |= ber_printf(ber, "s{", logString);

                /*
                 * Now we start adding the relocations.
                 * Let's add the timestamp as the first one
                 * so it's out of the field loop
                 */
                rc |= ber_printf(ber, "{i", ZOS_REMOTE_RELOC_TIMESTAMP);
                rc |= ber_printf(ber, "t", ASN1_IA5STRING_TAG);
                rc |= ber_printf(ber, "s}", timestamp);

                /* 
                 * Check that encoding is going OK until now
                 */
                if (rc < 0)
                        goto skip_event;

                /* 
                 * Now go to first field,
                 * and iterate through all fields
                 */
                auparse_first_field(au);
                do {
                        /* 
                         * we set a maximum of 1024 chars for
                         * relocation data (field=value pairs)
                         * Hopefuly this wont overflow too often
                         */
                        char data[1024];
                        const char *name = auparse_get_field_name(au);
                        const char *value = auparse_interpret_field(au);
                        if (name == NULL || value == NULL)
                                goto skip_event;
                        
                        /*
                         * First reloc field is the Relocation type
                         * We use 'OTHER' here since we don't have
                         * anything better
                         */
                        rc |= ber_printf(ber, "{i", ZOS_REMOTE_RELOC_OTHER);
                        
                        /*
                         * Second field is the relocation data
                         * We use a 'name=value' pair here
                         * Use up to 1023 chars (one char left for '\0')
                         */
                        snprintf(data, 1023, "%s=%s", name, value);
                        rc |= ber_printf(ber, "t", ASN1_IA5STRING_TAG);
                        rc |= ber_printf(ber, "s}", data);
                        
                        /*
                         * Check encoding status
                         */
                        if (rc < 0)
                                goto skip_event;
                } while (auparse_next_field(au) > 0);
                
                /* 
                 * After adding all relocations we are done with
                 * this item - finalize relocs and item 
                 */
                rc |= ber_printf(ber, "}}");
                
                /*
                 * Check if we are doing well with encoding
                 */
                if (rc < 0)
                        goto skip_event;            

        } while (auparse_next_record(au) > 0);
        
        /*
         * We have all items in - finalize item sequence & request
         */
        rc |= ber_printf(ber, "}}");

        /*
         * Check if everything went alright with encoding
         */
        if (rc < 0)
                goto skip_event;

        /* 
         * finally, enqueue request and let the other
         * thread process it
         */
        log_debug("Encoding done, enqueuing event");
        enqueue(ber);

        return;
        
skip_event:
        log_warn("Warning - error encoding request, skipping event");
        ber_free(ber, 1);        /* free it since we're not enqueuing it */
        return;

fatal:
        log_err("Error - Fatal error while encoding request. Aborting");
        stop = 1;
}

int main(int argc, char *argv[])
{
        int rc;
        const char *cpath;
        char buf[1024];
        struct sigaction sa;
        sigset_t ss;
        auparse_state_t *au;
        ssize_t len;

        mypid = getpid();

        log_info("starting with pid=%d", mypid);

        /*
         * install signal handlers
         */
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = term_handler;
        sigaction(SIGTERM, &sa, NULL);
        sa.sa_handler = hup_handler;
        sigaction(SIGHUP, &sa, NULL);
        sa.sa_handler = alarm_handler;
        sigaction(SIGALRM, &sa, NULL);

        /* 
         * the main program accepts a single (optional) argument:
         * it's configuration file (this is NOT the plugin configuration
         * usually located at /etc/audisp/plugin.d)
         * We use the default (def_config_file) if no arguments are given
         */
        if (argc == 1) {
                cpath = def_config_file;
                log_warn("No configuration file specified - using default (%s)", cpath);
        } else if (argc == 2) {
                cpath = argv[1];
                log_info("Using configuration file: %s", cpath);
        } else {
                log_err("Error - invalid number of parameters passed. Aborting");
                return 1;
        }

        /* initialize record counter */
        conf.counter = 1;
        
        /* initialize configuration with default values */
        plugin_clear_config(&conf);
        
        /* initialize the submission queue */
        if (init_queue(conf.q_depth) != 0) {
                log_err("Error - Can't initialize event queue. Aborting");
                return -1;
        }

#ifdef HAVE_LIBCAP_NG
	// Drop all capabilities
        capng_clear(CAPNG_SELECT_BOTH);
        capng_apply(CAPNG_SELECT_BOTH);
#endif

        /* set stdin to O_NONBLOCK */
        if (fcntl(0, F_SETFL, O_NONBLOCK) == -1) {
                log_err("Error - Can't set input to Non-blocking mode: %s. Aborting",
                        strerror(errno));
                return -1;
        }

        do {
                
                hup = 0;        /* don't flush unless hup == 1 */
                
                /* 
                 * initialization is done in 4 steps: 
                 */
                
                /* 
                 * load configuration and
                 * increase queue depth if needed 
                 */
                rc = plugin_load_config(&conf, cpath);
                if (rc != 0) {
                        log_err("Error - Can't load configuration. Aborting");
                        return -1;
                }
                increase_queue_depth(conf.q_depth);                /* 1 */

                /* initialize auparse */
                au = auparse_init(AUSOURCE_FEED, 0);               /* 2 */
                if (au == NULL) {
                        log_err("Error - exiting due to auparse init errors");
                        return -1;
                }
                
                /* 
                 * Block signals for everyone,
                 * Initialize submission thread, and 
                 * Unblock signals for this thread
                 */
                sigfillset(&ss);
                pthread_sigmask(SIG_BLOCK, &ss, NULL);
                pthread_create(&submission_thread, NULL, 
                               submission_thread_main, NULL);
                pthread_sigmask(SIG_UNBLOCK, &ss, NULL);           /* 3 */

                /* add our event consumer callback */
                auparse_add_callback(au, push_event, NULL, NULL);  /* 4 */

                /* main loop */
		rc = -1;
                while (hup == 0 && stop == 0) {
                        fd_set rfds;
                        struct timeval tv;

			if (rc == 0 && auparse_feed_has_data(au))
				auparse_feed_age_events(au);                         

                        FD_ZERO(&rfds);
                        FD_SET(0, &rfds);
                        tv.tv_sec = 5;
                        tv.tv_usec = 0;
                        rc = select(1, &rfds, NULL, NULL, &tv);
                        if (rc == -1) {
                                if (errno == EINTR) {
                                        log_debug("Select call interrupted");
                                        continue;
                                }
                                else {
                                        log_err("Error  - Fatal error while monitoring input: %s. Aborting",
                                                strerror(errno));
                                        stop = 1;
                                }
                        }
                        else if (rc) {
                                len = read(0, buf, 1024);
                                if (len > 0)
                                        /* let our callback know of the new data */
                                        auparse_feed(au, buf, len);
                                else if (len == 0) {
                                        log_debug("End of input - Exiting");
                                        stop = 1;
                                }
                                else {
                                        /* ignore interrupted call or empty pipe */
                                        if (errno != EINTR && errno != EAGAIN) {
                                                log_err("Error - Fatal error while reading input: %s. Aborting",
                                                        strerror(errno));
                                                stop = 1;
                                        }
                                        else {
                                                log_debug("Ignoring read interruption: %s",
                                                          strerror(errno));
                                        }
                                }
                        }
                }
                /* flush everything, in order */
                auparse_flush_feed(au);                            /* 4 */
                alarm(10);             /* 10 seconds to clear the queue */
                pthread_join(submission_thread, NULL);             /* 3 */
                alarm(0);                   /* cancel any pending alarm */
                auparse_destroy(au);                               /* 2 */
                plugin_free_config(&conf);                                /* 1 */
        } while (hup && stop == 0);
        
        /* destroy queue before leaving */
        destroy_queue();

        log_info("Exiting");

        return 0;
}
