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
#include "mail-config.h"
#include "config.h"


int Read_EmailAlerts(XML_NODE node, __attribute__((unused)) void *configp, void *mailp)
{
    int i = 0;
    unsigned int granto_size = 0;
    unsigned int granto_email_counter = 0;

    /* XML definitions */
    const char *xml_email_to = "email_to";
    const char *xml_email_format = "format";
    const char *xml_email_level = "level";
    const char *xml_email_id = "rule_id";
    const char *xml_email_group = "group";
    const char *xml_email_location = "event_location";
    const char *xml_email_donotdelay = "do_not_delay";
    const char *xml_email_donotgroup = "do_not_group";

    MailConfig *Mail;

    Mail = (MailConfig *)mailp;
    if (!Mail) {
        return (0);
    }

    /* Get Granular mail_to size */
    if (Mail && Mail->gran_to) {
        char **ww;
        ww = Mail->gran_to;
        while (*ww != NULL) {
            ww++;
            granto_size++;
        }
        granto_email_counter = granto_size;
    }

    if (Mail) {
        os_realloc(Mail->gran_id,
                   sizeof(unsigned int *) * (granto_size + 2), Mail->gran_id);
        os_realloc(Mail->gran_level,
                   sizeof(unsigned int) * (granto_size + 2), Mail->gran_level);
        os_realloc(Mail->gran_set,
                   sizeof(int) * (granto_size + 2), Mail->gran_set);
        os_realloc(Mail->gran_format,
                   sizeof(int) * (granto_size + 2), Mail->gran_format);
        os_realloc(Mail->gran_location,
                   sizeof(OSMatch *) * (granto_size + 2), Mail->gran_location);
        os_realloc(Mail->gran_group,
                   sizeof(OSMatch *) * (granto_size + 2), Mail->gran_group);

        Mail->gran_id[granto_size] = NULL;
        Mail->gran_id[granto_size + 1] = NULL;

        Mail->gran_location[granto_size] = NULL;
        Mail->gran_location[granto_size + 1] = NULL;

        Mail->gran_group[granto_size] = NULL;
        Mail->gran_group[granto_size + 1] = NULL;

        Mail->gran_level[granto_size] = 0;
        Mail->gran_level[granto_size + 1] = 0;

        Mail->gran_format[granto_size] = FULL_FORMAT;
        Mail->gran_format[granto_size + 1] = FULL_FORMAT;

        Mail->gran_set[granto_size] = 0;
        Mail->gran_set[granto_size + 1] = 0;
    }

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }
        /* Mail notification */
        else if (strcmp(node[i]->element, xml_email_level) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            Mail->gran_level[granto_size] = atoi(node[i]->content);
        } else if (strcmp(node[i]->element, xml_email_to) == 0) {
            os_realloc(Mail->gran_to,
                   sizeof(char *) * (granto_email_counter + 2), Mail->gran_to);

            os_strdup(node[i]->content, Mail->gran_to[granto_email_counter]);
            Mail->gran_to[granto_email_counter + 1] = NULL;

            granto_email_counter++;
        } else if (strcmp(node[i]->element, xml_email_id) == 0) {
            int r_id = 0;
            char *str_pt = node[i]->content;

            while (*str_pt != '\0') {
                /* We allow spaces in between */
                if (*str_pt == ' ') {
                    str_pt++;
                    continue;
                }

                /* If is digit, we get the value and
                 * search for the next digit available
                 */
                else if (isdigit((int)*str_pt)) {
                    unsigned int id_i = 0;

                    r_id = atoi(str_pt);
                    mdebug1("Adding '%d' to granular e-mail", r_id);

                    if (!Mail->gran_id[granto_size]) {
                        os_calloc(2, sizeof(unsigned int), Mail->gran_id[granto_size]);
                        Mail->gran_id[granto_size][0] = 0;
                        Mail->gran_id[granto_size][1] = 0;
                    } else {
                        while (Mail->gran_id[granto_size][id_i] != 0) {
                            id_i++;
                        }

                        os_realloc(Mail->gran_id[granto_size],
                                   (id_i + 2) * sizeof(unsigned int),
                                   Mail->gran_id[granto_size]);
                        Mail->gran_id[granto_size][id_i + 1] = 0;
                    }
                    Mail->gran_id[granto_size][id_i] = r_id;

                    str_pt = strchr(str_pt, ',');
                    if (str_pt) {
                        str_pt++;
                    } else {
                        break;
                    }
                }

                /* Check for duplicate commas */
                else if (*str_pt == ',') {
                    str_pt++;
                    continue;
                }

                else {
                    break;
                }
            }

        } else if (strcmp(node[i]->element, xml_email_format) == 0) {
            if (strcmp(node[i]->content, "sms") == 0) {
                Mail->gran_format[granto_size] = SMS_FORMAT;
            } else if (strcmp(node[i]->content, "default") == 0 || strcmp(node[i]->content, "full") == 0) {
                /* Default is full format */
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_email_donotdelay) == 0) {
            if ((Mail->gran_format[granto_size] != SMS_FORMAT) &&
                    (Mail->gran_format[granto_size] != DONOTGROUP)) {
                Mail->gran_format[granto_size] = FORWARD_NOW;
            }
        } else if (strcmp(node[i]->element, xml_email_donotgroup) == 0) {
            if (Mail->gran_format[granto_size] != SMS_FORMAT) {
                Mail->gran_format[granto_size] = DONOTGROUP;
            }
        } else if (strcmp(node[i]->element, xml_email_location) == 0) {
            os_calloc(1, sizeof(OSMatch), Mail->gran_location[granto_size]);
            if (!OSMatch_Compile(node[i]->content,
                                 Mail->gran_location[granto_size], 0)) {
                merror(REGEX_COMPILE, node[i]->content,
                       Mail->gran_location[granto_size]->error);
                return (-1);
            }
        } else if (strcmp(node[i]->element, xml_email_group) == 0) {
            os_calloc(1, sizeof(OSMatch), Mail->gran_group[granto_size]);
            if (!OSMatch_Compile(node[i]->content,
                                 Mail->gran_group[granto_size], 0)) {
                merror(REGEX_COMPILE, node[i]->content,
                       Mail->gran_group[granto_size]->error);
                return (-1);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    // Expand multimail attributes
    while (granto_size < (granto_email_counter - 1)) {
        granto_size++;
        // Clone alerts id
        os_realloc(Mail->gran_id, sizeof(unsigned int *) * (granto_size + 2), Mail->gran_id);
        Mail->gran_id[granto_size] = Mail->gran_id[granto_size + 1] = NULL;
        for (i = 0; Mail->gran_id[granto_size - 1] && Mail->gran_id[granto_size - 1][i]; i++) {
            if (!Mail->gran_id[granto_size]) {
                os_calloc(2, sizeof(unsigned int), Mail->gran_id[granto_size]);
            } else {
                os_realloc(Mail->gran_id[granto_size], (i + 2) * sizeof(unsigned int), Mail->gran_id[granto_size]);
            }
            Mail->gran_id[granto_size][i] = Mail->gran_id[granto_size - 1][i];
            Mail->gran_id[granto_size][i + 1] = 0;
        }
        // Clone alerts levels
        os_realloc(Mail->gran_level, sizeof(unsigned int) * (granto_size + 2), Mail->gran_level);
        Mail->gran_level[granto_size] = Mail->gran_level[granto_size - 1];
        Mail->gran_level[granto_size + 1] = 0;
        // Clone set attr
        os_realloc(Mail->gran_set, sizeof(int) * (granto_size + 2), Mail->gran_set);
        Mail->gran_set[granto_size] = Mail->gran_set[granto_size - 1];
        Mail->gran_set[granto_size + 1] = 0;
        // Clone mail format
        os_realloc(Mail->gran_format, sizeof(int) * (granto_size + 2), Mail->gran_format);
        Mail->gran_format[granto_size] = Mail->gran_format[granto_size - 1];
        Mail->gran_format[granto_size + 1] = 0;
        // Clone alert location
        os_realloc(Mail->gran_location, sizeof(OSMatch *) * (granto_size + 2), Mail->gran_location);
        Mail->gran_location[granto_size] = Mail->gran_location[granto_size - 1];
        Mail->gran_location[granto_size + 1] = NULL;
        // Clone alert group
        os_realloc(Mail->gran_group, sizeof(OSMatch *) * (granto_size + 2), Mail->gran_group);
        Mail->gran_group[granto_size] = Mail->gran_group[granto_size - 1];
        Mail->gran_group[granto_size + 1] = NULL;
    }

    /* We must have at least one entry set */
    if ((Mail->gran_location[granto_size] == NULL &&
            Mail->gran_level[granto_size] == 0 &&
            Mail->gran_group[granto_size] == NULL &&
            Mail->gran_id[granto_size] == NULL &&
            Mail->gran_format[granto_size] == FULL_FORMAT) ||
            Mail->gran_to == NULL ||
            Mail->gran_to[granto_size] == NULL) {
        merror(XML_INV_GRAN_MAIL);
        return (OS_INVALID);
    }

    return (0);
}
