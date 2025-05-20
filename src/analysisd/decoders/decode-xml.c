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
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "decoder.h"
#include "plugin_decoders.h"
#include "config.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/* Internal functions */

/**
 * @brief Appends a copy of *str to the *at string and return the new string
 * @details Allocate memory at "*at" and copy *str to it
 *          If *at already exist, realloc the memory and cat str on it.
 * @param at original string (Null an acceptable Value).
 * @param str source string to append at.
 * @param log_msg list to save log messages.
 * @return char* The new string.
 * @warning This function assumes that "at" reserved memory is `OS_SIZE_1024`.
 */
STATIC char *_loadmemory(char *at, char* str, OSList* log_msg);

/**
 * @brief Get offset attribute value of a node
 * @param node node to find offset value
 * @retval AFTER_PARENT if offset is "after_parent"
 * @retval AFTER_PREMATCH if offset is "after_prematch"
 * @retval AFTER_PREVREGEX if offset is "after_regex"
 * @retval AFTER_ERROR if offset is not any previously listed values
 * @retval 0 if the attribute is not present
 */
STATIC int w_get_attr_offset(xml_node * node);

/**
 * @brief Get regex type attribute of a node
 * @param node node to find regex type value
 * @param type if it is defined, return regex type
 * @return true if it is defined. false otherwise
 */
STATIC bool w_get_attr_regex_type(xml_node * node, w_exp_type_t * type);

int getDecoderfromlist(const char *name, OSStore **decoder_store) {

    if (*decoder_store) {
        return (OSStore_GetPosition_ex(*decoder_store, name));
    }

    return (0);
}

STATIC int addDecoder2list(const char *name, OSStore **decoder_store) {

    if (*decoder_store == NULL) {
        *decoder_store = OSStore_Create();
        if (*decoder_store == NULL) {
            merror(LIST_ERROR);
            return (0);
        }
    }

    /* Store data */
    if (!OSStore_Put_ex(*decoder_store, name, NULL)) {
        merror(LIST_ADD_ERROR);
        return (0);
    }

    return (1);
}

STATIC int os_setdecoderids(OSDecoderNode **decoderlist, OSStore **decoder_list)
{
    OSDecoderNode *node;
    OSDecoderNode *child_node;
    OSDecoderInfo *nnode;

    if (node = *decoderlist, !node) {
        return 0;
    }

    do {
        int p_id = 0;
        char *tmp_name;

        nnode = node->osdecoder;
        nnode->id = getDecoderfromlist(nnode->name, decoder_list);

        /* Id cannot be 0 */
        if (nnode->id == 0) {
            return (0);
        }

        child_node = node->child;

        if (!child_node) {
            continue;
        }

        /* Set parent id */
        p_id = nnode->id;
        tmp_name = nnode->name;

        /* Also set on the child nodes */
        while (child_node) {
            nnode = child_node->osdecoder;

            if (nnode->use_own_name) {
                nnode->id = getDecoderfromlist(nnode->name, decoder_list);
            } else {
                nnode->id = p_id;

                /* Set parent name */
                free(nnode->name);
                os_strdup(tmp_name, nnode->name);
            }

            /* Id cannot be 0 */
            if (nnode->id == 0) {
                return (0);
            }
            child_node = child_node->next;
        }
    } while ((node = node->next) != NULL);

    return (1);
}

int ReadDecodeXML(const char *file, OSDecoderNode **decoderlist_pn,
                  OSDecoderNode **decoderlist_nopn, OSStore **decoder_list,
                  OSList* log_msg)
{
    OS_XML xml;
    XML_NODE node = NULL;
    int retval = 0; // 0 means error

    /* XML variables */
    /* These are the available options for the rule configuration */

    const char *xml_plugindecoder = "plugin_decoder";
    const char *xml_decoder = "decoder";
    const char *xml_decoder_name = "name";
    const char *xml_decoder_status = "status";
    const char *xml_usename = "use_own_name";
    const char *xml_parent = "parent";
    const char *xml_program_name = "program_name";
    const char *xml_prematch = "prematch";
    const char *xml_regex = "regex";
    const char *xml_order = "order";
    const char *xml_type = "type";
    const char *xml_fts = "fts";
    const char *xml_ftscomment = "ftscomment";
    const char *xml_accumulate = "accumulate";
    const char *xml_nullfield = "json_null_field";
    const char *xml_arraystructure = "json_array_structure";

    int i = 0;
    OSDecoderInfo *NULL_Decoder_tmp = NULL;

    char * regex_str = NULL;
    char * prematch_str = NULL;
    char * p_name_str = NULL;

    w_exp_type_t regex_type;
    w_exp_type_t prematch_type;
    w_exp_type_t p_name_type;

    XML_NODE elements = NULL;
    OSDecoderInfo *pi = NULL;

    /* Read the XML */
    switch(OS_ReadXML(file, &xml)) {
        case -2:
            smwarn(log_msg, FOPEN_ERROR, file, errno, strerror(errno));
            retval = 1;
            goto cleanup;
        case -1:
            smerror(log_msg, XML_ERROR, file, xml.err, xml.err_line);
            goto cleanup;
        case 0:
        default:
            break;
    }

    /* Apply any variables found */
    if (OS_ApplyVariables(&xml) != 0) {
        smerror(log_msg, XML_ERROR_VAR, file, xml.err);
        goto cleanup;
    }

    /* Check if the file is empty */
    if (FileSize(file) == 0) {
        if (strcmp(file, XML_LDECODER) != 0) {
            goto cleanup;
        }
    }

    /* Get the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        if (strcmp(file, XML_LDECODER) != 0) {
            smerror(log_msg, XML_ELEMNULL);
            goto cleanup;
        }

        return (-2);
    }

    /* Zero NULL_decoder */

    if (!NULL_Decoder) {
        os_calloc(1, sizeof(OSDecoderInfo), NULL_Decoder_tmp);
        NULL_Decoder_tmp->id = 0;
        NULL_Decoder_tmp->type = SYSLOG;
        NULL_Decoder_tmp->name = NULL;
        NULL_Decoder_tmp->fts = 0;
        NULL_Decoder = NULL_Decoder_tmp;
    }

    i = 0;

    while (node[i]) {
        int j = 0;

        if (!node[i]->element) {
            goto cleanup;
        }

        /* Only process a decoder node */
        if (strcasecmp(node[i]->element, xml_decoder) != 0) {
            smerror(log_msg, XML_INVELEM, node[i]->element);
            goto cleanup;
        }

        /* Get name */
        if ((!node[i]->attributes) || (!node[i]->values)
                || (!node[i]->values[0]) || (!node[i]->attributes[0])
                || (strcasecmp(node[i]->attributes[0], xml_decoder_name) != 0)) {
            smerror(log_msg, XML_INVELEM, node[i]->element);
            goto cleanup;
        }

        /* Check for additional attributes */
        if (node[i]->attributes[1] && node[i]->values[1]) {
            if (strcasecmp(node[i]->attributes[1], xml_decoder_status) != 0) {
                smerror(log_msg, XML_INVELEM, node[i]->element);
                goto cleanup;
            }

            if (node[i]->attributes[2]) {
                smerror(log_msg, XML_INVELEM, node[i]->element);
                goto cleanup;
            }
        }

        /* Get decoder options */
        elements = OS_GetElementsbyNode(&xml, node[i]);
        if (elements == NULL) {
            smerror(log_msg, XML_ELEMNULL);
            goto cleanup;
        }

        /* Create the OSDecoderInfo */
        os_calloc(1, sizeof(OSDecoderInfo), pi);

        /* Default values to the list */
        pi->parent = NULL;
        pi->id = 0;
        os_strdup(node[i]->values[0], pi->name);
        pi->order = NULL;
        pi->plugindecoder = NULL;
        pi->fts = 0;
        pi->accumulate = 0;
        pi->type = SYSLOG;
        pi->prematch = NULL;
        pi->program_name = NULL;
        pi->regex = NULL;
        pi->use_own_name = 0;
        pi->get_next = 0;
        pi->regex_offset = 0;
        pi->prematch_offset = 0;
        pi->flags = JSON_TREAT_NULL_DEFAULT | JSON_TREAT_ARRAY_DEFAULT;
        pi->internal_saving = false;

        regex_str = NULL;
        prematch_str = NULL;
        p_name_str = NULL;

        /* Default regex types */
        regex_type = EXP_TYPE_OSREGEX;
        prematch_type = EXP_TYPE_OSREGEX;
        p_name_type = EXP_TYPE_OSMATCH;

        /* Add decoder */
        if (!addDecoder2list(pi->name, decoder_list)) {
            merror(MEM_ERROR, errno, strerror(errno));
            goto cleanup;
        }

        /* Loop over all the elements */
        while (elements[j]) {
            if (!elements[j]->element) {
                smerror(log_msg, XML_ELEMNULL);
                goto cleanup;
            } else if (!elements[j]->content) {
                smerror(log_msg, XML_VALUENULL, elements[j]->element);
                goto cleanup;
            }

            /* Check if it is a child of a decoder */
            else if (strcasecmp(elements[j]->element, xml_parent) == 0) {
                pi->parent = _loadmemory(pi->parent, elements[j]->content, log_msg);
            }

            /* Get the regex */
            else if (strcasecmp(elements[j]->element, xml_regex) == 0) {

                int r_offset = w_get_attr_offset(elements[j]);

                if (r_offset & AFTER_ERROR) {
                    smwarn(log_msg, ANALYSISD_INV_VALUE_DEFAULT, "offset", xml_regex, pi->name);
                    r_offset = 0;
                }

                /* Only the first regex entry may have an offset */
                if (regex_str && r_offset) {
                    smerror(log_msg, DUP_REGEX, pi->name);
                    smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }

                if (r_offset) {
                    pi->regex_offset = r_offset;
                }

                /* get type */
                if (!w_get_attr_regex_type(elements[j], &regex_type)) {
                    regex_type = EXP_TYPE_OSREGEX;
                }

                /* Only OSRegex & pcre2 support for regex label */
                if (regex_type != EXP_TYPE_OSREGEX && regex_type != EXP_TYPE_PCRE2) {
                    smwarn(log_msg, ANALYSISD_INV_VALUE_DEFAULT, "type", xml_regex, pi->name);
                    regex_type = EXP_TYPE_OSREGEX;
                }

                /* Assign regex */
                regex_str = _loadmemory(regex_str, elements[j]->content, log_msg);
            }

            /* Get the pre match */
            else if (strcasecmp(elements[j]->element, xml_prematch) == 0) {

                int pre_offset = w_get_attr_offset(elements[j]);

                if (pre_offset & AFTER_ERROR) {
                    smerror(log_msg, ANALYSISD_INV_VALUE_DEFAULT, "offset", xml_prematch,  pi->name);
                    pre_offset = 0;
                }

                /* Only the first prematch entry may have an offset */
                if (prematch_str && pre_offset) {
                    smerror(log_msg, DUP_REGEX, pi->name);
                    smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }

                if (pre_offset) {
                    pi->prematch_offset = pre_offset;
                }

                /* Get type */
                if (!w_get_attr_regex_type(elements[j], &prematch_type)) {
                    prematch_type = EXP_TYPE_OSREGEX;
                }

                /* Only OSRegex & pcre2 support for prematch label */
                if (prematch_type != EXP_TYPE_OSREGEX && prematch_type != EXP_TYPE_PCRE2) {
                    smwarn(log_msg, ANALYSISD_INV_VALUE_DEFAULT, "type", xml_prematch, pi->name);
                    prematch_type = EXP_TYPE_OSREGEX;
                }

                prematch_str = _loadmemory(prematch_str, elements[j]->content, log_msg);
            }

            /* Get program name */
            else if (strcasecmp(elements[j]->element, xml_program_name) == 0) {

                /* Get type */
                if (!w_get_attr_regex_type(elements[j], &p_name_type)) {
                    p_name_type = EXP_TYPE_OSMATCH;
                }

                /* Only OSMatch & EXP_TYPE_OSREGEX & pcre2 support for prematch label */
                if (p_name_type != EXP_TYPE_OSMATCH && p_name_type != EXP_TYPE_OSREGEX &&
                    p_name_type != EXP_TYPE_PCRE2) {

                    smwarn(log_msg, ANALYSISD_INV_VALUE_DEFAULT, "type", xml_program_name, pi->name);
                    p_name_type = EXP_TYPE_OSMATCH;
                }

                p_name_str = _loadmemory(p_name_str, elements[j]->content, log_msg);
            }

            /* Get the FTS comment */
            else if (strcasecmp(elements[j]->element, xml_ftscomment) == 0) {
                pi->ftscomment = _loadmemory(pi->ftscomment, elements[j]->content, log_msg);
            }

            else if (strcasecmp(elements[j]->element, xml_usename) == 0) {
                if (strcmp(elements[j]->content, "true") == 0) {
                    pi->use_own_name = 1;
                }
            }

            else if (strcasecmp(elements[j]->element, xml_plugindecoder) == 0) {
                int ed_c = 0;
                for (ed_c = 0; plugin_decoders[ed_c] != NULL; ed_c++) {
                    if (strcmp(plugin_decoders[ed_c],
                               elements[j]->content) == 0) {
                        /* Initialize plugin */
                        void (*dec_init)(void) = (void (*)(void)) plugin_decoders_init[ed_c];
                        dec_init();
                        pi->plugindecoder = (void (*)(void *, void *, void *)) plugin_decoders_exec[ed_c];
                        break;
                    }
                }

                /* Decoder not found */
                if (pi->plugindecoder == NULL) {
                    smerror(log_msg, INV_DECOPTION, elements[j]->element, elements[j]->content);
                    goto cleanup;
                }

                pi->plugin_offset = w_get_attr_offset(elements[j]);

                if (pi->plugin_offset & AFTER_ERROR) {
                    smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }
            }

            else if (strcasecmp(elements[j]->element, xml_nullfield) == 0) {

                /* clearing json null treat bits */
                pi->flags = (pi->flags) & (~JSON_TREAT_NULL_MASK);
                if (strcasecmp(elements[j]->content, "discard") == 0) {
                    pi->flags |= JSON_TREAT_NULL_AS_DISCARD;
                } else if (strcasecmp(elements[j]->content, "empty") == 0) {
                    smwarn(log_msg, ANALYSISD_DEC_DEPRECATED_OPT_VALUE, elements[j]->content, xml_nullfield, pi->name);
                    pi->flags |= JSON_TREAT_NULL_DEFAULT;
                } else if (strcasecmp(elements[j]->content, "string") == 0) {
                    pi->flags |= JSON_TREAT_NULL_AS_STRING;
                } else {
                    smwarn(log_msg, ANALYSISD_INV_OPT_VALUE_DEFAULT, elements[j]->content, xml_nullfield, pi->name);
                    pi->flags |= JSON_TREAT_NULL_DEFAULT;
                }
            }

            else if (strcasecmp(elements[j]->element, xml_arraystructure) == 0) {
                /* clear default value */
                pi->flags = (pi->flags) & (~JSON_TREAT_ARRAY_MASK);
                if (strcasecmp(elements[j]->content, "csv") == 0) {
                    pi->flags |= JSON_TREAT_ARRAY_AS_CSV_STRING;
                } else if (strcasecmp(elements[j]->content, "array") == 0) {
                    pi->flags |= JSON_TREAT_ARRAY_AS_ARRAY;
                } else {
                    smwarn(log_msg, ANALYSISD_INV_OPT_VALUE_DEFAULT, elements[j]->content, xml_arraystructure, pi->name);
                    pi->flags |= JSON_TREAT_ARRAY_DEFAULT;
                }
            }

            /* Get the type */
            else if (strcmp(elements[j]->element, xml_type) == 0) {
                if (strcmp(elements[j]->content, "firewall") == 0) {
                    pi->type = FIREWALL;
                } else if (strcmp(elements[j]->content, "ids") == 0) {
                    pi->type = IDS;
                } else if (strcmp(elements[j]->content, "web-log") == 0) {
                    pi->type = WEBLOG;
                } else if (strcmp(elements[j]->content, "syslog") == 0) {
                    pi->type = SYSLOG;
                } else if (strcmp(elements[j]->content, "squid") == 0) {
                    pi->type = SQUID;
                } else if (strcmp(elements[j]->content, "windows") == 0) {
                    pi->type = DECODER_WINDOWS;
                } else if (strcmp(elements[j]->content, "host-information") == 0) {
                    pi->type = HOST_INFO;
                } else if (strcmp(elements[j]->content, "ossec") == 0) {
                    pi->type = OSSEC_RL;
                } else {
                    smerror(log_msg, "Invalid decoder type '%s'.", elements[j]->content);
                    goto cleanup;
                }
            }

            /* Get the order */
            else if (strcasecmp(elements[j]->element, xml_order) == 0) {
                char **norder, **s_norder;
                int order_int = 0;

                /* Maximum number for the order is limited by decoder_order_size */

                if (os_strcnt(elements[j]->content, ',') >= (size_t)Config.decoder_order_size) {
                    smerror(log_msg, "Order has too many fields.");
                    goto cleanup;
                }

                norder = OS_StrBreak(',', elements[j]->content, Config.decoder_order_size);
                s_norder = norder;
                os_calloc(Config.decoder_order_size, sizeof(void *(*)(struct _Eventinfo *, char *, const char *)), pi->order);
                os_calloc(Config.decoder_order_size, sizeof(char *), pi->fields);

                /* Check the values from the order */
                while (*norder) {
                    char *word = &(*norder)[strspn(*norder, " ")];
                    word[strcspn(word, " ")] = '\0';

                    if (strlen(word) == 0) {
                        smerror(log_msg, "decode-xml: Wrong field '%s' in the order"
                                  " of decoder '%s'", *norder, pi->name);
                        for (int i = 0; i < Config.decoder_order_size; i++) {
                            os_free(s_norder[i]);
                        }
                        os_free(s_norder);
                        goto cleanup;
                    }

                    if (!strcmp(word, "dstuser")) {
                        pi->order[order_int] = DstUser_FP;
                    } else if (!strcmp(word, "srcuser")) {
                        pi->order[order_int] = SrcUser_FP;
                    }
                    /* User is an alias to dstuser */
                    else if (!strcmp(word, "user")) {
                        pi->order[order_int] = DstUser_FP;
                    } else if (!strcmp(word, "srcip")) {
                        pi->order[order_int] = SrcIP_FP;
                    } else if (!strcmp(word, "dstip")) {
                        pi->order[order_int] = DstIP_FP;
                    } else if (!strcmp(word, "srcport")) {
                        pi->order[order_int] = SrcPort_FP;
                    } else if (!strcmp(word, "dstport")) {
                        pi->order[order_int] = DstPort_FP;
                    } else if (!strcmp(word, "protocol")) {
                        pi->order[order_int] = Protocol_FP;
                    } else if (!strcmp(word, "action")) {
                        pi->order[order_int] = Action_FP;
                    } else if (!strcmp(word, "id")) {
                        pi->order[order_int] = ID_FP;
                    } else if (!strcmp(word, "url")) {
                        pi->order[order_int] = Url_FP;
                    } else if (!strcmp(word, "data")) {
                        pi->order[order_int] = Data_FP;
                    } else if (!strcmp(word, "extra_data")) {
                        pi->order[order_int] = Extra_Data_FP;
                    } else if (!strcmp(word, "status")) {
                        pi->order[order_int] = Status_FP;
                    } else if (!strcmp(word, "system_name")) {
                        pi->order[order_int] = SystemName_FP;
                    } else {
                        pi->order[order_int] = DynamicField_FP;
                        os_strdup(word, pi->fields[order_int]);
                    }

                    os_free(*norder);
                    norder++;

                    order_int++;
                }

                os_free(s_norder);
            }

            else if (strcasecmp(elements[j]->element, xml_accumulate) == 0) {
                /* Enable Accumulator */
                pi->accumulate = 1;
            }

            /* Get the FTS order */
            else if (strcasecmp(elements[j]->element, xml_fts) == 0) {
                char **norder;
                char **s_norder;

                /* Maximum number for the FTS is limited by decoder_order_size */
                norder = OS_StrBreak(',', elements[j]->content, Config.decoder_order_size);
                if (norder == NULL) {
                    merror_exit(MEM_ERROR, errno, strerror(errno));
                }

                os_calloc(Config.decoder_order_size, sizeof(char), pi->fts_fields);

                /* Save the initial point to free later */
                s_norder = norder;

                /* Check the values from the FTS */
                while (*norder) {
                    char *word = &(*norder)[strspn(*norder, " ")];
                    word[strcspn(word, " ")] = '\0';

                    if (strlen(word) == 0) {
                        smerror(log_msg, "decode-xml: Wrong field '%s' in the fts"
                                  " decoder '%s'", *norder, pi->name);
                        for (int i = 0; i < Config.decoder_order_size; i++ ) {
                            os_free(s_norder[i]);
                        }
                        os_free(s_norder);
                        goto cleanup;
                    }

                    if (!strcmp(word, "dstuser")) {
                        pi->fts |= FTS_DSTUSER;
                    } else if (!strcmp(word, "user")) {
                        pi->fts |= FTS_DSTUSER;
                    } else if (!strcmp(word, "srcuser")) {
                        pi->fts |= FTS_SRCUSER;
                    } else if (!strcmp(word, "srcip")) {
                        pi->fts |= FTS_SRCIP;
                    } else if (!strcmp(word, "dstip")) {
                        pi->fts |= FTS_DSTIP;
                    } else if (!strcmp(word, "id")) {
                        pi->fts |= FTS_ID;
                    } else if (!strcmp(word, "location")) {
                        pi->fts |= FTS_LOCATION;
                    } else if (!strcmp(word, "data")) {
                        pi->fts |= FTS_DATA;
                    } else if (!strcmp(word, "extra_data")) {
                        pi->fts |= FTS_DATA;
                    } else if (!strcmp(word, "system_name")) {
                        pi->fts |= FTS_SYSTEMNAME;
                    } else if (!strcmp(word, "name")) {
                        pi->fts |= FTS_NAME;
                    } else {
                        int i;
                        if (pi->fields) {
                            for (i = 0; pi->fields[i]; i++)
                                if (!strcasecmp(pi->fields[i], word))
                                    break;


                            if (!pi->fields[i]) {
                                smerror(log_msg, "decode-xml: Wrong field '%s' in the fts"
                                        " decoder '%s'", *norder, pi->name);
                                for (int i = 0; i < Config.decoder_order_size; i++ ) {
                                    os_free(s_norder[i]);
                                }
                                os_free(s_norder);
                                goto cleanup;
                            }

                            pi->fts |= FTS_DYNAMIC;
                            pi->fts_fields[i] = 1;
                        }
                    }

                    os_free(*norder);
                    norder++;
                }

                /* Clear memory here */
                free(s_norder);
            } else {
                smerror(log_msg, "Invalid element '%s' for decoder '%s'", elements[j]->element, node[i]->element);
                goto cleanup;
            }

            /* NEXT */
            j++;

        } /* while(elements[j]) */

        OS_ClearNode(elements);
        elements = NULL;

        /* Prematch must be set */
        if (!prematch_str && !pi->parent && !p_name_str) {
            smerror(log_msg, DECODE_NOPRE, pi->name);
            smerror(log_msg, DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        /* If pi->regex is not set, fts must not be set too */
        if ((!regex_str && (pi->fts || pi->order)) || (regex_str && !pi->order)) {
            smerror(log_msg, DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        /* For the offsets */
        if ((pi->regex_offset & AFTER_PARENT) && !pi->parent) {
            smerror(log_msg, INV_OFFSET, "after_parent");
            smerror(log_msg, DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        if (pi->regex_offset & AFTER_PREMATCH) {
            /* If after_prematch is set, but rule have
             * no parent, set AFTER_PARENT and unset
             * pre_match.
             */
            if (!pi->parent) {
                pi->regex_offset = 0;
                pi->regex_offset |= AFTER_PARENT;
            } else if (!prematch_str) {
                smerror(log_msg, INV_OFFSET, "after_prematch");
                smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
        }

        /* For the after_regex offset */
        if (pi->regex_offset & AFTER_PREVREGEX) {
            if (!pi->parent || !regex_str) {
                smerror(log_msg, INV_OFFSET, "after_regex");
                smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
        }

        /* Check the prematch offset */
        if (pi->prematch_offset) {
            /* Only the after parent is allowed */
            if (pi->prematch_offset & AFTER_PARENT) {
                if (!pi->parent) {
                    smerror(log_msg, INV_OFFSET, "after_parent");
                    smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }
            } else {
                smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
        }

        // Check the plugin offset
        if ((pi->plugin_offset & AFTER_PARENT) && !pi->parent) {
            smerror(log_msg, INV_OFFSET, "after_parent");
            smerror(log_msg, DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        if (pi->plugin_offset & AFTER_PREMATCH && !prematch_str) {
            smerror(log_msg, INV_OFFSET, "after_prematch");
            smerror(log_msg, DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        /* Compile the regex/prematch */
        if (prematch_str) {
            w_calloc_expression_t(&pi->prematch, prematch_type);

            if (!w_expression_compile(pi->prematch, prematch_str, 0)) {
                smerror(log_msg, REGEX_SYNTAX, prematch_str);
                smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
            os_free(prematch_str);
        }

        /* Compile the p_name */
        if (p_name_str) {
            w_calloc_expression_t(&pi->program_name, p_name_type);

            if (!w_expression_compile(pi->program_name, p_name_str, 0)) {
                smerror(log_msg, REGEX_SYNTAX, p_name_str);
                smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
            os_free(p_name_str);
        }

        /* We may not have the pi->regex */
        if (regex_str) {

            w_calloc_expression_t(&pi->regex, regex_type);

            if (!w_expression_compile(pi->regex, regex_str, OS_RETURN_SUBSTRING)) {
                smerror(log_msg, REGEX_SYNTAX, regex_str);
                smerror(log_msg, DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }

            /* We must have the sub_strings to retrieve the nodes */
            if (pi->regex->exp_type == EXP_TYPE_OSREGEX && !pi->regex->regex->d_sub_strings) {
                smerror(log_msg, REGEX_SUBS, regex_str);
                goto cleanup;
            }

            os_free(regex_str);
        }

        /* Validate arguments */
        if (pi->plugindecoder && (pi->regex || pi->order)) {
            smerror(log_msg, DECODE_ADD, pi->name);
            goto cleanup;
        }

        /* Add osdecoder to the list */

        int r;

        if ((r = OS_AddOSDecoder(pi, decoderlist_pn, decoderlist_nopn, log_msg)) < 1) {
            smerror(log_msg, DECODER_ERROR);

            if (r == -1) {
                pi = NULL;
            }

            goto cleanup;
        }

        pi = NULL;
        i++;
    } /* while (node[i]) */

    retval = 1;

cleanup:

    os_free(p_name_str);
    os_free(prematch_str);
    os_free(regex_str);

    /* Clean node and XML structures */
    OS_ClearNode(elements);
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    FreeDecoderInfo(pi);

    return retval;
}

int SetDecodeXML(OSList* log_msg, OSStore **decoder_list, OSDecoderNode **decoderlist_npn, OSDecoderNode **decoderlist_pn)
{
    /* Add internal decoders to list */
    addDecoder2list(ROOTCHECK_MOD, decoder_list);
    addDecoder2list(FIM_MOD, decoder_list);
    addDecoder2list(FIM_NEW, decoder_list);
    addDecoder2list(FIM_DEL, decoder_list);
    addDecoder2list(FIM_REG_KEY_MOD, decoder_list);
    addDecoder2list(FIM_REG_KEY_NEW, decoder_list);
    addDecoder2list(FIM_REG_KEY_DEL, decoder_list);
    addDecoder2list(FIM_REG_VAL_MOD, decoder_list);
    addDecoder2list(FIM_REG_VAL_NEW, decoder_list);
    addDecoder2list(FIM_REG_VAL_DEL, decoder_list);
    addDecoder2list(HOSTINFO_NEW, decoder_list);
    addDecoder2list(HOSTINFO_MOD, decoder_list);
    addDecoder2list(SYSCOLLECTOR_MOD, decoder_list);
    addDecoder2list(CISCAT_MOD, decoder_list);
    addDecoder2list(WINEVT_MOD, decoder_list);
    addDecoder2list(SCA_MOD, decoder_list);

    /* Set ids - for our two lists */
    if (!os_setdecoderids(decoderlist_npn, decoder_list)) {
        smerror(log_msg, DECODER_ERROR);
        return (0);
    }
    if (!os_setdecoderids(decoderlist_pn, decoder_list)) {
        smerror(log_msg, DECODER_ERROR);
        return (0);
    }

    return (1);
}

char *_loadmemory(char *at, char *str, OSList* log_msg)
{
    if (at == NULL) {
        size_t strsize = 0;
        if ((strsize = strlen(str)) < OS_SIZE_1024) {
            os_calloc(strsize + 1, sizeof(char), at);
            memcpy(at, str, strsize);
            return (at);
        } else {
            smerror(log_msg, SIZE_ERROR, str);
            return (NULL);
        }
    }
    /* At is not null. Need to reallocate its memory and copy str to it */
    else {
        size_t strsize = strlen(str);
        size_t atsize = strlen(at);
        size_t finalsize = atsize + strsize + 1;
        if (finalsize > OS_SIZE_1024) {
            smerror(log_msg, SIZE_ERROR, str);
            return (NULL);
        }
        at = (char *) realloc(at, finalsize * sizeof(char));
        if (at == NULL) {
            merror(MEM_ERROR, errno, strerror(errno));
            return (NULL);
        }
        strcat(at, str);

        return (at);
    }
    return (NULL);
}

void FreeDecoderInfo(OSDecoderInfo *pi) {

    if (pi == NULL) {
        return;
    }

    if (pi->fields) {
        for (int i = 0; i < Config.decoder_order_size; i++) {
            os_free(pi->fields[i]);
        }
        os_free(pi->fields);
    }

    os_free(pi->order);
    os_free(pi->parent);
    os_free(pi->name);
    os_free(pi->fts_fields);
    os_free(pi->ftscomment);

    w_free_expression_t(&pi->regex);
    w_free_expression_t(&pi->prematch);
    w_free_expression_t(&pi->program_name);

    os_free(pi);
}

STATIC int w_get_attr_offset(xml_node * node) {

    int offset = 0;
    const char * xml_after_parent = "after_parent";
    const char * xml_after_prematch = "after_prematch";
    const char * xml_after_regex = "after_regex";

    const char * str_offset = w_get_attr_val_by_name(node, "offset");

    if (!str_offset) {
        return 0;
    }

    /*
     * Offsets can be: after_parent, after_prematch
     * or after_regex.
     */
    if (strcasecmp(str_offset, xml_after_parent) == 0) {
        offset |= AFTER_PARENT;
    } else if (strcasecmp(str_offset, xml_after_prematch) == 0) {
        offset |= AFTER_PREMATCH;
    } else if (strcasecmp(str_offset, xml_after_regex) == 0) {
        offset |= AFTER_PREVREGEX;
    } else {
        offset |= AFTER_ERROR;
    }

    return (offset);
}

STATIC bool w_get_attr_regex_type(xml_node * node, w_exp_type_t * type) {

    const char * xml_osregex_type = OSREGEX_STR;
    const char * xml_osmatch_type = OSMATCH_STR;
    const char * xml_pcre2_type = PCRE2_STR;
    bool retval = false;

    const char * str_type = w_get_attr_val_by_name(node, "type");

    if (!str_type) {
        return retval;
    }
    retval = true;

    if (strcasecmp(str_type, xml_osregex_type) == 0) {
        *type = EXP_TYPE_OSREGEX;
    } else if (strcasecmp(str_type, xml_osmatch_type) == 0) {
        *type = EXP_TYPE_OSMATCH;
    } else if (strcasecmp(str_type, xml_pcre2_type) == 0) {
        *type = EXP_TYPE_PCRE2;
    } else {
        *type = EXP_TYPE_INVALID;
    }

    return retval;
}
