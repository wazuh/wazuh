/* @(#) $Id$ */

/* Copyright (C) 2004-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#ifdef PRELUDE

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-message-print.h>

#include "prelude.h"
#include "shared.h"
#include "eventinfo.h"

#define DEFAULT_ANALYZER_NAME "OSSEC"
#define ANALYZER_CLASS "Host IDS, File Integrity Checker, Log Analyzer"
#define ANALYZER_MODEL "Ossec"
#define ANALYZER_MANUFACTURER __site
#define ANALYZER_VERSION __version


/*
 * Ossec to Prelude
 */


/** OSSEC to prelude severity mapping. **/
char *(ossec2prelude_sev[])={"info","info","info","info",
                             "low","low","low","low",
                             "medium", "medium", "medium", "medium",
                             "high", "high", "high", "high", "high"};
                

/* Prelude client */
static prelude_client_t *prelude_client;


void prelude_idmef_debug(idmef_message_t *idmef)
{
	prelude_io_t *pio;

	prelude_io_new(&pio);
	prelude_io_set_file_io(pio, stderr);
	idmef_message_print(idmef, pio);
	prelude_io_destroy(pio);
}



static int 
add_idmef_object(idmef_message_t *msg, const char *object, const char *value)
{
    int ret = 0;
    idmef_value_t *val;
    idmef_path_t *path;

    /* Can value be null? better check in here.  */
    if(value == NULL)
    {
        return(0);
    }

    ret = idmef_path_new_fast(&path, object);
    if(ret < 0)
    {
        return(-1);
    }

    ret = idmef_value_new_from_path(&val, path, value);
    if(ret < 0) 
    {
        idmef_path_destroy(path);
        return(-1);
    }

    ret = idmef_path_set(path, msg, val);
    if(ret < 0) 
    {
        merror("%s: OSSEC2Prelude: IDMEF: Cannot add object '%s': %s.", 
               ARGV0, object, prelude_strerror(ret));
    }

    idmef_value_destroy(val);
    idmef_path_destroy(path);

    return(ret);
}


static int
setup_analyzer(idmef_analyzer_t *analyzer)
{
    int ret;
    prelude_string_t *string;

    ret = idmef_analyzer_new_model(analyzer, &string);
    if ( ret < 0 )
        goto err;
    prelude_string_set_constant(string, ANALYZER_MODEL);

    ret = idmef_analyzer_new_class(analyzer, &string);
    if ( ret < 0 )
        goto err;
    prelude_string_set_constant(string, ANALYZER_CLASS);

    ret = idmef_analyzer_new_manufacturer(analyzer, &string);
    if ( ret < 0 )
        goto err;
    prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

    ret = idmef_analyzer_new_version(analyzer, &string);
    if ( ret < 0 )
        goto err;
    prelude_string_set_constant(string, ANALYZER_VERSION);


    return 0;

    err:
    merror("%s: OSSEC2Prelude: %s: IDMEF error: %s.",
            ARGV0, prelude_strsource(ret), prelude_strerror(ret));

    return -1;
}



void prelude_start(char *profile, int argc, char **argv)
{
    int ret;
    prelude_client = NULL;


    ret = prelude_init(&argc, argv);
    if (ret < 0) 
    {
        merror("%s: %s: Unable to initialize the Prelude library: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));
        return;
    }

    ret = prelude_client_new(&prelude_client, 
                             profile!=NULL?profile:DEFAULT_ANALYZER_NAME);
    if (!prelude_client) 
    {
        merror("%s: %s: Unable to create a prelude client object: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));

        return;
    }


    ret = setup_analyzer(prelude_client_get_analyzer(prelude_client));
    if(ret < 0) 
    {
        merror("%s: %s: Unable to setup analyzer: %s",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));

        prelude_client_destroy(prelude_client, 
                               PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        return;
    }


    ret = prelude_client_set_flags(prelude_client, 
          prelude_client_get_flags(prelude_client) 
          | PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if(ret < 0)
    {
        merror("%s: %s: Unable to set prelude client flags: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret)); 
    }


    /* Setting uid and gid of ossec. */
    prelude_client_profile_set_uid(prelude_client_get_profile(prelude_client),
                                   Privsep_GetUser(USER));
    prelude_client_profile_set_gid(prelude_client_get_profile(prelude_client),
                                   Privsep_GetGroup(GROUPGLOBAL));


    ret = prelude_client_start(prelude_client);
    if (ret < 0) 
    {
        merror("%s: %s: Unable to initialize prelude client: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));

        prelude_client_destroy(prelude_client, 
                               PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        return;
    }


    return;

}



void OS_PreludeLog(Eventinfo *lf)
{
    int ret;
    idmef_message_t *idmef;

    
    /* Generate prelude alert */
    ret = idmef_message_new(&idmef);
    if ( ret < 0 )
    {
        merror("%s: OSSEC2Prelude: Cannot create IDMEF message", ARGV0);
        return;
    }

    
    add_idmef_object(idmef, "alert.assessment.impact.description", 
                            lf->generated_rule->comment);
    
    add_idmef_object(idmef, "alert.assessment.impact.severity", 
                            (lf->generated_rule->level > 15) ? "high": 
                            ossec2prelude_sev[lf->generated_rule->level]);
                    
    add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded");
    
    add_idmef_object(idmef, "alert.classification.text", 
                            lf->generated_rule->comment);
    

    /* Setting source info. */
    add_idmef_object(idmef, "alert.source(0).Spoofed", "no");
    add_idmef_object(idmef, "alert.source(0).Node.Address(0).address", 
                            lf->srcip);
    add_idmef_object(idmef, "alert.source(0).Service.port", lf->srcport);
    add_idmef_object(idmef, "alert.source(0).User.UserId(0).name", lf->srcuser);


    /* Setting target */
    add_idmef_object(idmef, "alert.target(0).Service.name", lf->program_name);
    add_idmef_object(idmef, "alert.target(0).Spoofed", "no");

    if(lf->dstip)
    {
        add_idmef_object(idmef, "alert.target(0).Node.Address(0).address", 
                                lf->dstip);
    }
    else
    {
        char *tmp_str;
        char new_prelude_target[256];

        new_prelude_target[255] = '\0';
        strncpy(new_prelude_target, lf->dstip, 255);

        /* The messages can have the file, so we need to remove it.
         * formats can be:
         * enigma->/var/log/authlog
         * (esqueleto2) 192.168.2.99->/var/log/squid/access.log
         */
        tmp_str = strstr(new_prelude_target, "->");
        if(tmp_str)
        {
            *tmp_str = '\0';
        }
        add_idmef_object(idmef, "alert.target(0).Node.Address(0).address", 
                                new_prelude_target);
    }
    add_idmef_object(idmef, "alert.target(0).Service.name", lf->hostname);
    add_idmef_object(idmef, "alert.target(0).Service.port", lf->dstport);
    add_idmef_object(idmef, "alert.target(0).User.UserId(0).name", lf->dstuser);


    /* Setting source file. */
    add_idmef_object(idmef, "alert.additional_data(0).type", "string");
    add_idmef_object(idmef, "alert.additional_data(0).meaning", "Source file");
    add_idmef_object(idmef, "alert.additional_data(0).data", lf->location);
    

    /* Setting full log. */
    add_idmef_object(idmef, "alert.additional_data(1).type", "string");
    add_idmef_object(idmef, "alert.additional_data(1).meaning", "Full Log");
    add_idmef_object(idmef, "alert.additional_data(1).data", lf->full_log);

    idmef_alert_set_analyzer(idmef_message_get_alert(idmef),
                             idmef_analyzer_ref
                             (prelude_client_get_analyzer(prelude_client)),
                             IDMEF_LIST_PREPEND);

    prelude_client_send_idmef(prelude_client, idmef);
    idmef_message_destroy(idmef);
}



#endif /* PRELUDE */

/* EOF */
