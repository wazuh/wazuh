/* @(#) $Id: ./src/config/global-config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle the configuration files
 */


#include "shared.h"
#include "os_net/os_net.h"
#include "global-config.h"
#include "mail-config.h"


void AssignIgnore_Global(char **ignores, void *configp)
{
    _Config *Config;

    Config = (_Config *)configp;
    if(Config)
    {
        Config->syscheck_ignore = ignores;
    }
}


/* GlobalConfSK v0.1: 2006/04/26
 * v0.1 Getting the ignore fields.
 */
int Read_GlobalSK(XML_NODE node, void *configp, void *mailp)
{
    int i = 0;
    int ign_size = 1;
    char *xml_ignore = "ignore";
    char *xml_auto_ignore = "auto_ignore";
    char *xml_alert_new_files = "alert_new_files";

    _Config *Config;

    Config = (_Config *)configp;


    /* Shouldn't be here if !Config */
    if(!Config)
        return(0);


    /* Getting right white_size */
    if(Config && Config->syscheck_ignore)
    {
        char **ww;
        ww = Config->syscheck_ignore;

        while(*ww != NULL)
        {
            ign_size++;
            ww++;
        }
    }

    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        else if(strcmp(node[i]->element,xml_auto_ignore) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            {
                Config->syscheck_auto_ignore = 1;
            }
            else if(strcmp(node[i]->content, "no") == 0)
            {
                Config->syscheck_auto_ignore = 0;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_alert_new_files) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            {
                Config->syscheck_alert_new = 1;
            }
            else if(strcmp(node[i]->content, "no") == 0)
            {
                Config->syscheck_alert_new = 0;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_ignore) == 0)
        {
            ign_size++;
            Config->syscheck_ignore =
                realloc(Config->syscheck_ignore, sizeof(char *)*ign_size);
            if(!Config->syscheck_ignore)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content,Config->syscheck_ignore[ign_size -2]);
            Config->syscheck_ignore[ign_size -1] = NULL;
        }
        i++;
    }

    return(0);
}


/* GlobalConf v0.2: 2005/03/03
 * v0.2: Changing to support the new OS_XML
 */
int Read_Global(XML_NODE node, void *configp, void *mailp)
{
    int i = 0;

    /* White list size */
    int white_size = 1;
    int hostname_white_size = 1;
    int mailto_size = 1;


    /* XML definitions */
    char *xml_mailnotify = "email_notification";
    char *xml_logall = "logall";
    char *xml_integrity = "integrity_checking";
    char *xml_rootcheckd = "rootkit_detection";
    char *xml_hostinfo = "host_information";
    char *xml_picviz = "picviz_output";
    char *xml_picviz_socket = "picviz_socket";
    char *xml_prelude = "prelude_output";
    char *xml_prelude_profile = "prelude_profile";
    char *xml_prelude_log_level = "prelude_log_level";
    char *xml_zeromq_output = "zeromq_output";
    char *xml_zeromq_output_uri = "zeromq_uri";
    char *xml_stats = "stats";
    char *xml_memorysize = "memory_size";
    char *xml_white_list = "white_list";
    char *xml_compress_alerts = "compress_alerts";
    char *xml_custom_alert_output = "custom_alert_output";

    char *xml_emailto = "email_to";
    char *xml_emailfrom = "email_from";
    char *xml_emailidsname = "email_idsname";
    char *xml_smtpserver = "smtp_server";
    char *xml_mailmaxperhour = "email_maxperhour";

#ifdef GEOIP
    /* GeoIP */
    char *xml_geoip_db_path = "geoip_db_path";
    char *xml_geoip6_db_path = "geoip6_db_path";
#endif

    _Config *Config;
    MailConfig *Mail;

    Config = (_Config *)configp;
    Mail = (MailConfig *)mailp;

    /* Getting right white_size */
    if(Config && Config->white_list)
    {
        os_ip **ww;
        ww = Config->white_list;

        while(*ww != NULL)
        {
            white_size++;
            ww++;
        }
    }

     /* Getting right white_size */
    if(Config && Config->hostname_white_list)
    {
        OSMatch **ww;
        ww = Config->hostname_white_list;

        while(*ww != NULL)
        {
            hostname_white_size++;
            ww++;
        }
    }

    /* Getting mail_to size */
    if(Mail && Mail->to)
    {
        char **ww;
        ww = Mail->to;
        while(*ww != NULL)
        {
            mailto_size++;
            ww++;
        }
    }

    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, xml_custom_alert_output) == 0)
        {
          if(Config)
          {
            Config->custom_alert_output= 1;
            os_strdup(node[i]->content, Config->custom_alert_output_format);
          }
        }
        /* Mail notification */
        else if(strcmp(node[i]->element, xml_mailnotify) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            {
                if(Config) Config->mailnotify = 1;
                if(Mail) Mail->mn = 1;
            }
            else if(strcmp(node[i]->content, "no") == 0)
            {
                if(Config) Config->mailnotify = 0;
                if(Mail) Mail->mn = 0;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        /* Picviz support */
        else if(strcmp(node[i]->element, xml_picviz) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            {
                if(Config) Config->picviz = 1;
            }
            else if(strcmp(node[i]->content, "no") == 0)
            {
                if(Config) Config->picviz = 0;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element, node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_picviz_socket) == 0)
        {
            if(Config)
            {
                os_strdup(node[i]->content, Config->picviz_socket);
            }
        }
        /* Prelude support */
        else if(strcmp(node[i]->element, xml_prelude) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            {
                if(Config) Config->prelude = 1;
            }
            else if(strcmp(node[i]->content, "no") == 0)
            {
                if(Config) Config->prelude = 0;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element, node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_prelude_profile) == 0)
        {
            if(Config)
            {
                Config->prelude_profile = strdup(node[i]->content);
            }
        }
        else if(strcmp(node[i]->element, xml_prelude_log_level) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            if(Config)
            {
                Config->prelude_log_level = atoi(node[i]->content);
            }
        }
        /* ZeroMQ output */
        else if(strcmp(node[i]->element, xml_zeromq_output) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
            { 
                if(Config) Config->zeromq_output = 1; 
            }
            else if(strcmp(node[i]->content, "no") == 0)
            { 
                if(Config) Config->zeromq_output = 0; 
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element, node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_zeromq_output_uri) == 0)
        {
            if(Config)
            {
                Config->zeromq_output_uri = strdup(node[i]->content);
            }
        }
        /* Log all */
        else if(strcmp(node[i]->element, xml_logall) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                { if(Config) Config->logall = 1;}
            else if(strcmp(node[i]->content, "no") == 0)
                {if(Config) Config->logall = 0;}
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        /* compress alerts */
        else if(strcmp(node[i]->element, xml_compress_alerts) == 0)
        {
            /* removed from here -- compatility issues only */
        }
        /* Integrity */
        else if(strcmp(node[i]->element, xml_integrity) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            if(Config)
            {
                Config->integrity = atoi(node[i]->content);
            }
        }
        /* rootcheck */
        else if(strcmp(node[i]->element, xml_rootcheckd) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            if(Config)
            {
                Config->rootcheck = atoi(node[i]->content);
            }
        }
        /* hostinfo */
        else if(strcmp(node[i]->element, xml_hostinfo) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            if(Config)
            {
                Config->hostinfo = atoi(node[i]->content);
            }
        }
        /* stats */
        else if(strcmp(node[i]->element, xml_stats) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            if(Config)
            {
                Config->stats = atoi(node[i]->content);
            }
        }
        else if(strcmp(node[i]->element, xml_memorysize) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            if(Config)
            {
                Config->memorysize = atoi(node[i]->content);
            }
        }
        /* whitelist */
        else if(strcmp(node[i]->element, xml_white_list) == 0)
        {
            /* Windows do not need it */
            #ifndef WIN32

            char *ip_address_regex =
             "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/?"
             "([0-9]{0,2}|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})$";

            if(Config && OS_PRegex(node[i]->content, ip_address_regex))
            {
                white_size++;
                Config->white_list =
                    realloc(Config->white_list, sizeof(os_ip *)*white_size);
                if(!Config->white_list)
                {
                    merror(MEM_ERROR, ARGV0);
                    return(OS_INVALID);
                }

                os_calloc(1, sizeof(os_ip), Config->white_list[white_size -2]);
                Config->white_list[white_size -1] = NULL;

                if(!OS_IsValidIP(node[i]->content,
                                 Config->white_list[white_size -2]))
                {
                    merror(INVALID_IP, ARGV0,
                                       node[i]->content);
                    return(OS_INVALID);
                }
            }
            /* Adding hostname */
            else if(Config)
            {
                hostname_white_size++;
                Config->hostname_white_list =
                    realloc(Config->hostname_white_list,
                    sizeof(OSMatch *)*hostname_white_size);

                if(!Config->hostname_white_list)
                {
                    merror(MEM_ERROR, ARGV0);
                    return(OS_INVALID);
                }
                os_calloc(1,
                          sizeof(OSMatch),
                          Config->hostname_white_list[hostname_white_size -2]);
                Config->hostname_white_list[hostname_white_size -1] = NULL;

                if(!OSMatch_Compile(
                        node[i]->content,
                        Config->hostname_white_list[hostname_white_size -2],
                        0))
                {
                    merror(REGEX_COMPILE, ARGV0, node[i]->content,
                           Config->hostname_white_list
                           [hostname_white_size -2]->error);
                    return(-1);
                }
            }

            #endif

        }

        /* For the email now
         * email_to, email_from, idsname, smtp_Server and maxperhour.
         * We will use a separate structure for that.
         */
        else if(strcmp(node[i]->element, xml_emailto) == 0)
        {
            #ifndef WIN32
            if(!OS_PRegex(node[i]->content, "[a-zA-Z0-9\\._-]+@[a-zA-Z0-9\\._-]"))
            {
                merror("%s: ERROR: Invalid Email address: %s.", ARGV0, node[i]->content);
                return(OS_INVALID);
            }
            #endif

            if(Mail)
            {
                mailto_size++;
                Mail->to = realloc(Mail->to, sizeof(char *)*mailto_size);
                if(!Mail->to)
                {
                    merror(MEM_ERROR, ARGV0);
                    return(OS_INVALID);
                }

                os_strdup(node[i]->content, Mail->to[mailto_size - 2]);
                Mail->to[mailto_size - 1] = NULL;
            }
        }
        else if(strcmp(node[i]->element, xml_emailfrom) == 0)
        {
            if(Mail)
            {
                if(Mail->from)
                {
                    free(Mail->from);
                }
                os_strdup(node[i]->content, Mail->from);
            }
        }
        else if(strcmp(node[i]->element, xml_emailidsname) == 0)
        {
            if(Mail)
            {
                if(Mail->idsname)
                {
                    free(Mail->idsname);
                }
                os_strdup(node[i]->content, Mail->idsname);
            }
        }
        else if(strcmp(node[i]->element, xml_smtpserver) == 0)
        {
            #ifndef WIN32
            if(Mail && (Mail->mn))
            {
                Mail->smtpserver = OS_GetHost(node[i]->content, 5);
                if(!Mail->smtpserver)
                {
                    merror(INVALID_SMTP, ARGV0, node[i]->content);
                    return(OS_INVALID);
                }
            }
            #endif
        }
        else if(strcmp(node[i]->element, xml_mailmaxperhour) == 0)
        {
            if(Mail)
            {
                if(!OS_StrIsNum(node[i]->content))
                {
                   merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                   return(OS_INVALID);
                }
                Mail->maxperhour = atoi(node[i]->content);

                if((Mail->maxperhour <= 0) || (Mail->maxperhour > 9999))
                {
                   merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                   return(OS_INVALID);
                }
            }
        }
#ifdef GEOIP
        /* GeoIP v4 DB location */
        else if(strcmp(node[i]->element, xml_geoip_db_path) == 0)
        {
            if(Config)
            {
                os_strdup(node[i]->content, Config->geoip_db_path);
            }
        }
        /* GeoIP v6 DB location */
        else if(strcmp(node[i]->element, xml_geoip6_db_path) == 0)
        {
            if(Config)
            {
                os_strdup(node[i]->content, Config->geoip6_db_path);
            }
        }
#endif
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }

    return(0);
}


/* EOF */
