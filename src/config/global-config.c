/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "global-config.h"
#include "mail-config.h"
#include "config.h"


int Read_GlobalSK(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;
    int j = 0;
    unsigned int ign_size = 1;
    const char *xml_ignore = "ignore";
    const char *xml_auto_ignore = "auto_ignore";
    const char *xml_ignore_frequency = "frequency";
    const char *xml_ignore_time = "timeframe";
    const char *xml_alert_new_files = "alert_new_files";

    _Config *Config;
    Config = (_Config *)configp;

    if (!Config) {
        return (0);
    }

    /* Get right white_size */
    if (Config && Config->syscheck_ignore) {
        char **ww;
        ww = Config->syscheck_ignore;

        while (*ww != NULL) {
            ign_size++;
            ww++;
        }
    }

    if (!node)
        return 0;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_auto_ignore) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->syscheck_auto_ignore = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->syscheck_auto_ignore = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            for (j = 0; node[i]->attributes && node[i]->attributes[j]; ++j) {
                if (strcmp(node[i]->attributes[j], xml_ignore_frequency) == 0) {
                    if (!OS_StrIsNum(node[i]->values[0])) {
                        merror(XML_VALUEERR, node[i]->attributes[j], node[i]->values[j]);
                        return (OS_INVALID);
                    }
                    Config->syscheck_ignore_frequency = atoi(node[i]->values[0]);
                    if (Config->syscheck_ignore_frequency < 1 || Config->syscheck_ignore_frequency > 99) {
                        merror(XML_VALUEERR, node[i]->attributes[j], node[i]->values[j]);
                        return (OS_INVALID);
                    }
                } else if (strcmp(node[i]->attributes[j], xml_ignore_time) == 0) {
                    if (!OS_StrIsNum(node[i]->values[j])) {
                        merror(XML_VALUEERR, node[i]->attributes[j], node[i]->values[j]);
                        return (OS_INVALID);
                    }
                    Config->syscheck_ignore_time = atoi(node[i]->values[1]);
                    if (Config->syscheck_ignore_time < 0 || Config->syscheck_ignore_time > 43200) {
                        merror(XML_VALUEERR, node[i]->attributes[j], node[i]->values[j]);
                        return (OS_INVALID);
                    }
                } else {
                    merror(XML_INVATTR, node[i]->attributes[j], node[i]->element);
                    return OS_INVALID;
                }
            }

        } else if (strcmp(node[i]->element, xml_alert_new_files) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->syscheck_alert_new = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->syscheck_alert_new = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_ignore) == 0) {
            ign_size++;
            Config->syscheck_ignore = (char **)
                                      realloc(Config->syscheck_ignore, sizeof(char *)*ign_size);
            if (!Config->syscheck_ignore) {
                merror(MEM_ERROR, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, Config->syscheck_ignore[ign_size - 2]);
            Config->syscheck_ignore[ign_size - 1] = NULL;
        }
        i++;
    }

    return (0);
}

int Read_Global(XML_NODE node, void *configp, void *mailp)
{
    int i = 0;

    /* Whitelist size */
    unsigned int white_size = 1;
    unsigned int hostname_white_size = 1;
    unsigned int mailto_size = 1;

    /* XML definitions */
    const char *xml_mailnotify = "email_notification";
    const char *xml_logall = "logall";
    const char *xml_logall_json = "logall_json";
    const char *xml_integrity = "integrity_checking";
    const char *xml_rootcheckd = "rootkit_detection";
    const char *xml_hostinfo = "host_information";
    const char *xml_prelude = "prelude_output";
    const char *xml_prelude_profile = "prelude_profile";
    const char *xml_prelude_log_level = "prelude_log_level";
    const char *xml_geoipdb_file = "geoipdb";
    const char *xml_zeromq_output = "zeromq_output";
    const char *xml_zeromq_output_uri = "zeromq_uri";
    const char *xml_zeromq_output_server_cert = "zeromq_server_cert";
    const char *xml_zeromq_output_client_cert = "zeromq_client_cert";
    const char *xml_jsonout_output = "jsonout_output";
    const char *xml_alerts_log = "alerts_log";
    const char *xml_stats = "stats";
    const char *xml_memorysize = "memory_size";
    const char *xml_white_list = "white_list";
    const char *xml_compress_alerts = "compress_alerts";
    const char *xml_custom_alert_output = "custom_alert_output";
    const char *xml_rotate_interval = "rotate_interval";
    const char *xml_max_output_size = "max_output_size";

    const char *xml_emailto = "email_to";
    const char *xml_emailfrom = "email_from";
    const char *xml_emailreplyto = "email_reply_to";
    const char *xml_emailidsname = "email_idsname";
    const char *xml_smtpserver = "smtp_server";
    const char *xml_heloserver = "helo_server";
    const char *xml_mailmaxperhour = "email_maxperhour";
    const char *xml_maillogsource = "email_log_source";
    const char *xml_queue_size = "queue_size";

#ifdef LIBGEOIP_ENABLED
    const char *xml_geoip_db_path = "geoip_db_path";
    const char *xml_geoip6_db_path = "geoip6_db_path";
#endif

    _Config *Config;
    MailConfig *Mail;

    Config = (_Config *)configp;
    Mail = (MailConfig *)mailp;

    /* Get right white_size */
    if (Config && Config->white_list) {
        os_ip **ww;
        ww = Config->white_list;

        while (*ww != NULL) {
            white_size++;
            ww++;
        }
    }

    /* Get right white_size */
    if (Config && Config->hostname_white_list) {
        OSMatch **ww;
        ww = Config->hostname_white_list;

        while (*ww != NULL) {
            hostname_white_size++;
            ww++;
        }
    }

    /* Get mail_to size */
    if (Mail && Mail->to) {
        char **ww;
        ww = Mail->to;
        while (*ww != NULL) {
            mailto_size++;
            ww++;
        }
    }

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_custom_alert_output) == 0) {
            if (Config) {
                Config->custom_alert_output = 1;
                os_strdup(node[i]->content, Config->custom_alert_output_format);
            }
        }
        /* Mail notification */
        else if (strcmp(node[i]->element, xml_mailnotify) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->mailnotify = 1;
                }
                if (Mail) {
                    Mail->mn = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->mailnotify = 0;
                }
                if (Mail) {
                    Mail->mn = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        /* Prelude support */
        else if (strcmp(node[i]->element, xml_prelude) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->prelude = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->prelude = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        /* GeoIP */
        } else if(strcmp(node[i]->element, xml_geoipdb_file) == 0) {
            if(Config)
            {
                Config->geoipdb_file = strdup(node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_prelude_profile) == 0) {
            if (Config) {
                Config->prelude_profile = strdup(node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_prelude_log_level) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            if (Config) {
                Config->prelude_log_level = (u_int8_t) atoi(node[i]->content);
            }
        }
        /* ZeroMQ output */
        else if (strcmp(node[i]->element, xml_zeromq_output) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->zeromq_output = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->zeromq_output = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_zeromq_output_uri) == 0) {
            if (Config) {
                Config->zeromq_output_uri = strdup(node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_zeromq_output_server_cert) == 0) {
            if (Config) {
                Config->zeromq_output_server_cert = strdup(node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_zeromq_output_client_cert) == 0) {
            if (Config) {
                Config->zeromq_output_client_cert = strdup(node[i]->content);
            }
        }
        /* jsonout output */
        else if (strcmp(node[i]->element, xml_jsonout_output) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->jsonout_output = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->jsonout_output = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        /* Standard alerts output */
        else if (strcmp(node[i]->element, xml_alerts_log) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->alerts_log = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->alerts_log = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        /* Log all */
        else if (strcmp(node[i]->element, xml_logall) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->logall = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->logall = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        /* Log all JSON*/
        else if (strcmp(node[i]->element, xml_logall_json) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                if (Config) {
                    Config->logall_json = 1;
                }
            } else if (strcmp(node[i]->content, "no") == 0) {
                if (Config) {
                    Config->logall_json = 0;
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        /* Compress alerts */
        else if (strcmp(node[i]->element, xml_compress_alerts) == 0) {
            /* removed from here -- compatibility issues only */
        }
        /* Integrity */
        else if (strcmp(node[i]->element, xml_integrity) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            if (Config) {
                Config->integrity = (u_int8_t) atoi(node[i]->content);
            }
        }
        /* rootcheck */
        else if (strcmp(node[i]->element, xml_rootcheckd) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            if (Config) {
                Config->rootcheck = (u_int8_t) atoi(node[i]->content);
            }
        }
        /* hostinfo */
        else if (strcmp(node[i]->element, xml_hostinfo) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            if (Config) {
                Config->hostinfo = (u_int8_t) atoi(node[i]->content);
            }
        }
        /* stats */
        else if (strcmp(node[i]->element, xml_stats) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            if (Config) {
                Config->stats = (u_int8_t) atoi(node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_memorysize) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            if (Config) {
                Config->memorysize = atoi(node[i]->content);
            }
        }
        /* whitelist */
        else if (strcmp(node[i]->element, xml_white_list) == 0) {
            /* Windows do not need it */
#ifndef WIN32

            const char *ip_address_regex =
                "^!?[[:digit:]]{1,3}(\\.[[:digit:]]{1,3}){3}"
                "(/[[:digit:]]{1,2}([[:digit:]](\\.[[:digit:]]{1,3}){3})?)?$";

            if (Config && OS_PRegex(node[i]->content, ip_address_regex)) {
                white_size++;
                Config->white_list = (os_ip **)
                                     realloc(Config->white_list, sizeof(os_ip *)*white_size);
                if (!Config->white_list) {
                    merror(MEM_ERROR, errno, strerror(errno));
                    return (OS_INVALID);
                }

                os_calloc(1, sizeof(os_ip), Config->white_list[white_size - 2]);
                Config->white_list[white_size - 1] = NULL;

                if (!OS_IsValidIP(node[i]->content,
                                  Config->white_list[white_size - 2])) {
                    merror(INVALID_IP,
                           node[i]->content);
                    return (OS_INVALID);
                }
            }
            /* Add hostname */
            else if (Config) {
                hostname_white_size++;
                Config->hostname_white_list = (OSMatch **)
                                              realloc(Config->hostname_white_list,
                                                      sizeof(OSMatch *)*hostname_white_size);

                if (!Config->hostname_white_list) {
                    merror(MEM_ERROR, errno, strerror(errno));
                    return (OS_INVALID);
                }
                os_calloc(1,
                          sizeof(OSMatch),
                          Config->hostname_white_list[hostname_white_size - 2]);
                Config->hostname_white_list[hostname_white_size - 1] = NULL;

                if (!OSMatch_Compile(
                            node[i]->content,
                            Config->hostname_white_list[hostname_white_size - 2],
                            0)) {
                    merror(REGEX_COMPILE, node[i]->content,
                           Config->hostname_white_list
                           [hostname_white_size - 2]->error);
                    return (-1);
                }
            }
#endif

        }

        /* For the email now
         * email_to, email_from, email_replyto, idsname, smtp_Server and maxperhour.
         * We will use a separate structure for that.
         */
        else if (strcmp(node[i]->element, xml_emailto) == 0) {
#ifndef WIN32
            if (!OS_PRegex(node[i]->content, "[a-zA-Z0-9\\._-]+@[a-zA-Z0-9\\._-]")) {
                merror("Invalid Email address: %s.", node[i]->content);
                return (OS_INVALID);
            }
#endif
            if (Mail) {
                mailto_size++;
                Mail->to = (char **) realloc(Mail->to, sizeof(char *)*mailto_size);
                if (!Mail->to) {
                    merror(MEM_ERROR, errno, strerror(errno));
                    return (OS_INVALID);
                }

                os_strdup(node[i]->content, Mail->to[mailto_size - 2]);
                Mail->to[mailto_size - 1] = NULL;
            }
        } else if (strcmp(node[i]->element, xml_emailfrom) == 0) {
            if (Mail) {
                if (Mail->from) {
                    free(Mail->from);
                }
                os_strdup(node[i]->content, Mail->from);
            }
        } else if (strcmp(node[i]->element, xml_emailreplyto) == 0) {
            if (Mail) {
                if (Mail->reply_to) {
                    free(Mail->reply_to);
                }
                os_strdup(node[i]->content, Mail->reply_to);
            }
        } else if (strcmp(node[i]->element, xml_emailidsname) == 0) {
            if (Mail) {
                if (Mail->idsname) {
                    free(Mail->idsname);
                }
                os_strdup(node[i]->content, Mail->idsname);
            }
        } else if (strcmp(node[i]->element, xml_smtpserver) == 0) {
#ifndef WIN32
            if (Mail && (Mail->mn)) {
                if (node[i]->content[0] == '/') {
                    os_strdup(node[i]->content, Mail->smtpserver);
                } else {
                    Mail->smtpserver = OS_GetHost(node[i]->content, 5);
                    if (!Mail->smtpserver) {
                        merror(INVALID_SMTP, node[i]->content);
                        return (OS_INVALID);
                    }
                }
            }
#endif
        } else if (strcmp(node[i]->element, xml_heloserver) == 0) {
            if (Mail && (Mail->mn)) {
                os_strdup(node[i]->content, Mail->heloserver);
            }
        } else if (strcmp(node[i]->element, xml_mailmaxperhour) == 0) {
            if (Mail) {
                if (!OS_StrIsNum(node[i]->content)) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
                Mail->maxperhour = atoi(node[i]->content);

                if ((Mail->maxperhour <= 0) || (Mail->maxperhour > 9999)) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
        } else if (strcmp(node[i]->element, xml_maillogsource) == 0) {
            if (Mail) {
                if (OS_StrIsNum(node[i]->content)) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }

                if(strncmp(node[i]->content,"alerts.log",10) == 0){
                    Mail->source = MAIL_SOURCE_LOGS;
                }
                else if(strncmp(node[i]->content,"alerts.json",11) == 0){
                    Mail->source = MAIL_SOURCE_JSON;
                }
                else{
                    Mail->source = MAIL_SOURCE_JSON;
                }
            }
        }
#ifdef LIBGEOIP_ENABLED
        /* GeoIP v4 DB location */
        else if (strcmp(node[i]->element, xml_geoip_db_path) == 0) {
            if (Config) {
                os_strdup(node[i]->content, Config->geoip_db_path);
            }
        }
        /* GeoIP v6 DB location */
        else if (strcmp(node[i]->element, xml_geoip6_db_path) == 0) {
            if (Config) {
                os_strdup(node[i]->content, Config->geoip6_db_path);
            }
        }
#endif
        else if (strcmp(node[i]->element, xml_rotate_interval) == 0) {
            if (Config) {
                char c;

                switch (sscanf(node[i]->content, "%d%c", &Config->rotate_interval, &c)) {
                case 1:
                    break;

                case 2:
                    switch (c) {
                    case 'd':
                        Config->rotate_interval *= 86400;
                        break;
                    case 'h':
                        Config->rotate_interval *= 3600;
                        break;
                    case 'm':
                        Config->rotate_interval *= 60;
                        break;
                    case 's':
                        break;
                    default:
                        merror(XML_VALUEERR, node[i]->element, node[i]->content);
                        return (OS_INVALID);
                    }

                    break;

                default:
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }

                if (Config->rotate_interval < 0) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
        } else if (strcmp(node[i]->element, xml_max_output_size) == 0) {
            if (Config) {
                char c;

                switch (sscanf(node[i]->content, "%zd%c", &Config->max_output_size, &c)) {
                case 1:
                    break;

                case 2:
                    switch (c) {
                    case 'G':
                    case 'g':
                        Config->max_output_size *= 1073741824;
                        break;
                    case 'M':
                    case 'm':
                        Config->max_output_size *= 1048576;
                        break;
                    case 'K':
                    case 'k':
                        Config->max_output_size *= 1024;
                        break;
                    case 'B':
                    case 'b':
                        break;
                    default:
                        merror(XML_VALUEERR, node[i]->element, node[i]->content);
                        return (OS_INVALID);
                    }

                    break;

                default:
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
        } else if (strcmp(node[i]->element, xml_queue_size) == 0) {
            if (Config) {
                char * end;

                Config->queue_size = strtol(node[i]->content, &end, 10);

                if (*end || Config->queue_size < 1) {
                    merror("Invalid value for option '<%s>'", xml_queue_size);
                    return OS_INVALID;
                }

            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    return (0);
}


void config_free(_Config *config) {

    if (!config) {
        return;
    }

    if (config->prelude_profile) {
        free(config->prelude_profile);
    }

    if (config->geoipdb_file) {
        free(config->geoipdb_file);
    }

    if (config->zeromq_output_uri) {
        free(config->zeromq_output_uri);
    }

    if (config->zeromq_output_server_cert) {
        free(config->zeromq_output_server_cert);
    }

    if (config->zeromq_output_client_cert) {
        free(config->zeromq_output_client_cert);
    }

    if (config->custom_alert_output_format) {
        free(config->custom_alert_output_format);
    }

    if (config->syscheck_ignore) {
        int i = 0;
        while (config->syscheck_ignore[i]) {
            free(config->syscheck_ignore[i]);
            i++;
        }
        free(config->syscheck_ignore);
    }

    if (config->white_list) {
        int i = 0;
        while (config->white_list[i]) {
            free(config->white_list[i]->ip);
            i++;
        }
        free(config->white_list);
    }

    if (config->includes) {
        int i = 0;
        while (config->includes[i]) {
            free(config->includes[i]);
            i++;
        }
        free(config->includes);
    }

    if (config->lists) {
        int i = 0;
        while (config->lists[i]) {
            free(config->lists[i]);
            i++;
        }
        free(config->lists);
    }

    if (config->decoders) {
        int i = 0;
        while (config->decoders[i]) {
            free(config->decoders[i]);
            i++;
        }
        free(config->decoders);
    }

    if (config->g_rules_hash) {
        OSHash_Free(config->g_rules_hash);
    }

    if (config->hostname_white_list) {
        int i = 0;
        while (config->hostname_white_list[i]) {
            OSMatch_FreePattern(config->hostname_white_list[i]);
            i++;
        }
        free(config->hostname_white_list);
    }

#ifdef LIBGEOIP_ENABLED
    if (config->geoip_db_path) {
        free(config->geoip_db_path);
    }
    if (config->geoip6_db_path) {
        free(config->geoip_db_path);
    }
#endif

    labels_free(config->labels); /* null-ended label set */

    // Cluster configuration
    if (config->cluster_name) {
        free(config->cluster_name);
    }
    if (config->node_name) {
        free(config->node_name);
    }
    if (config->node_type) {
        free(config->node_type);
    }

}
