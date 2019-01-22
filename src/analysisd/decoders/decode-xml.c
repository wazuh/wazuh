/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

#ifdef TESTRULE
#undef XML_LDECODER
#define XML_LDECODER "etc/local_decoder.xml"
#endif

/* Internal functions */
static char *_loadmemory(char *at, char *str);
static int addDecoder2list(const char *name);
static int os_setdecoderids(const char *p_name);
static int ReadDecodeAttrs(char *const *names, char *const *values);
static OSStore *os_decoder_store = NULL;

static void FreeDecoderInfo(OSDecoderInfo *pi);

int getDecoderfromlist(const char *name)
{
    if (os_decoder_store) {
        return (OSStore_GetPosition(os_decoder_store, name));
    }

    return (0);
}

static int addDecoder2list(const char *name)
{
    if (os_decoder_store == NULL) {
        os_decoder_store = OSStore_Create();
        if (os_decoder_store == NULL) {
            merror(LIST_ERROR);
            return (0);
        }
    }

    /* Store data */
    if (!OSStore_Put(os_decoder_store, name, NULL)) {
        merror(LIST_ADD_ERROR);
        return (0);
    }

    return (1);
}

static int os_setdecoderids(const char *p_name)
{
    OSDecoderNode *node;
    OSDecoderNode *child_node;
    OSDecoderInfo *nnode;

    node = OS_GetFirstOSDecoder(p_name);

    if (!node) {
        return (0);
    }

    do {
        int p_id = 0;
        char *tmp_name;

        nnode = node->osdecoder;
        nnode->id = getDecoderfromlist(nnode->name);

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
                nnode->id = getDecoderfromlist(nnode->name);
            } else {
                nnode->id = p_id;

                /* Set parent name */
                free(nnode->name);
                nnode->name = strdup(tmp_name);
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

static int ReadDecodeAttrs(char *const *names, char *const *values)
{
    if (!names || !values) {
        return (0);
    }

    if (!names[0] || !values[0]) {
        return (0);
    }

    if (strcmp(names[0], "offset") == 0) {
        int offset = 0;

        /* Offsets can be: after_parent, after_prematch
         * or after_regex.
         */
        if (strcmp(values[0], "after_parent") == 0) {
            offset |= AFTER_PARENT;
        } else if (strcmp(values[0], "after_prematch") == 0) {
            offset |= AFTER_PREMATCH;
        } else if (strcmp(values[0], "after_regex") == 0) {
            offset |= AFTER_PREVREGEX;
        } else {
            merror(INV_OFFSET, values[0]);
            offset |= AFTER_ERROR;
        }

        return (offset);
    }

    /* Invalid attribute */
    merror(INV_ATTR, names[0]);
    return (AFTER_ERROR);
}

int ReadDecodeXML(const char *file)
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

    int i = 0;
    OSDecoderInfo *NULL_Decoder_tmp = NULL;

    char *regex = NULL;
    char *prematch = NULL;
    char *p_name = NULL;
    XML_NODE elements = NULL;
    OSDecoderInfo *pi = NULL;

    /* Read the XML */
    if ((i = OS_ReadXML(file, &xml)) < 0) {
        if ((i == -2) && (strcmp(file, XML_LDECODER) == 0)) {
            return (-2);
        }

        merror(XML_ERROR, file, xml.err, xml.err_line);
        goto cleanup;
    }

    /* Apply any variables found */
    if (OS_ApplyVariables(&xml) != 0) {
        merror(XML_ERROR_VAR, file, xml.err);
        goto cleanup;
    }

    /* Check if the file is empty */
    if(FileSize(file) == 0){
        retval = 0;
        goto cleanup;
    }

    /* Get the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        if (strcmp(file, XML_LDECODER) != 0) {
            merror(XML_ELEMNULL);
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

        if (!node[i]->element ||
                strcasecmp(node[i]->element, xml_decoder) != 0) {
            merror(XML_INVELEM, node[i]->element);
            goto cleanup;
        }

        /* Get name */
        if ((!node[i]->attributes) || (!node[i]->values) ||
                (!node[i]->values[0])  || (!node[i]->attributes[0]) ||
                (strcasecmp(node[i]->attributes[0], xml_decoder_name) != 0)) {
            merror(XML_INVELEM, node[i]->element);
            goto cleanup;
        }

        /* Check for additional entries */
        if (node[i]->attributes[1] && node[i]->values[1]) {
            if (strcasecmp(node[i]->attributes[1], xml_decoder_status) != 0) {
                merror(XML_INVELEM, node[i]->element);
                goto cleanup;
            }

            if (node[i]->attributes[2]) {
                merror(XML_INVELEM, node[i]->element);
                goto cleanup;
            }
        }

        /* Get decoder options */
        elements = OS_GetElementsbyNode(&xml, node[i]);
        if (elements == NULL) {
            merror(XML_ELEMNULL);
            goto cleanup;
        }

        /* Create the OSDecoderInfo */
        pi = (OSDecoderInfo *)calloc(1, sizeof(OSDecoderInfo));
        if (pi == NULL) {
            merror(MEM_ERROR, errno, strerror(errno));
            goto cleanup;
        }

        /* Default values to the list */
        pi->parent = NULL;
        pi->id = 0;
        pi->name = strdup(node[i]->values[0]);
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
        pi->flags = SHOW_STRING;

        regex = NULL;
        prematch = NULL;
        p_name = NULL;

        /* Check if strdup worked */
        if (!pi->name) {
            merror(MEM_ERROR, errno, strerror(errno));
            goto cleanup;
        }

        /* Add decoder */
        if (!addDecoder2list(pi->name)) {
            merror(MEM_ERROR, errno, strerror(errno));
            goto cleanup;
        }

        /* Loop over all the elements */
        while (elements[j]) {
            if (!elements[j]->element) {
                merror(XML_ELEMNULL);
                goto cleanup;
            } else if (!elements[j]->content) {
                merror(XML_VALUENULL, elements[j]->element);
                goto cleanup;
            }

            /* Check if it is a child of a rule */
            else if (strcasecmp(elements[j]->element, xml_parent) == 0) {
                pi->parent = _loadmemory(pi->parent, elements[j]->content);
            }

            /* Get the regex */
            else if (strcasecmp(elements[j]->element, xml_regex) == 0) {
                int r_offset;
                r_offset = ReadDecodeAttrs(elements[j]->attributes,
                                           elements[j]->values);

                if (r_offset & AFTER_ERROR) {
                    merror(DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }

                /* Only the first regex entry may have an offset */
                if (regex && r_offset) {
                    merror(DUP_REGEX, pi->name);
                    merror(DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }

                /* regex offset */
                if (r_offset) {
                    pi->regex_offset = r_offset;
                }

                /* Assign regex */
                regex =
                    _loadmemory(regex,
                                elements[j]->content);
            }

            /* Get the pre match */
            else if (strcasecmp(elements[j]->element, xml_prematch) == 0) {
                int r_offset;

                r_offset = ReadDecodeAttrs(
                               elements[j]->attributes,
                               elements[j]->values);

                if (r_offset & AFTER_ERROR) {
                    merror_exit(DEC_REGEX_ERROR, pi->name);
                }

                /* Only the first prematch entry may have an offset */
                if (prematch && r_offset) {
                    merror(DUP_REGEX, pi->name);
                    merror_exit(DEC_REGEX_ERROR, pi->name);
                }

                if (r_offset) {
                    pi->prematch_offset = r_offset;
                }

                prematch =
                    _loadmemory(prematch,
                                elements[j]->content);
            }

            /* Get program name */
            else if (strcasecmp(elements[j]->element, xml_program_name) == 0) {
                p_name = _loadmemory(p_name, elements[j]->content);
            }

            /* Get the FTS comment */
            else if (strcasecmp(elements[j]->element, xml_ftscomment) == 0) {
                pi->ftscomment = _loadmemory(pi->ftscomment, elements[j]->content);
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
                        pi->plugindecoder = (void (*)(void *, void *)) plugin_decoders_exec[ed_c];
                        break;
                    }
                }

                /* Decoder not found */
                if (pi->plugindecoder == NULL) {
                    merror(INV_DECOPTION, elements[j]->element,
                           elements[j]->content);
                    goto cleanup;
                }

                pi->plugin_offset = ReadDecodeAttrs(elements[j]->attributes, elements[j]->values);

                if (pi->plugin_offset & AFTER_ERROR) {
                    merror_exit(DEC_REGEX_ERROR, pi->name);
                }
            }

            else if (strcasecmp(elements[j]->element, xml_nullfield) == 0) {
                if (strcmp(elements[j]->content, "discard") == 0) {
                    pi->flags = DISCARD;
                } else if (strcmp(elements[j]->content, "empty") == 0) {
                    pi->flags = EMPTY;
                } else if (strcmp(elements[j]->content, "string") == 0) {
                    pi->flags = SHOW_STRING;
                } else {
                    merror(INVALID_ELEMENT, elements[j]->element, elements[j]->content);
                    goto cleanup;
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
                    merror("Invalid decoder type '%s'.", elements[j]->content);
                    goto cleanup;
                }
            }

            /* Get the order */
            else if (strcasecmp(elements[j]->element, xml_order) == 0) {
                char **norder, **s_norder;
                int order_int = 0;

                /* Maximum number for the order is limited by decoder_order_size */

                if (os_strcnt(elements[j]->content, ',') >= (size_t)Config.decoder_order_size) {
                    merror_exit("Order has too many fields.");
                }

                norder = OS_StrBreak(',', elements[j]->content, Config.decoder_order_size);
                s_norder = norder;
                os_calloc(Config.decoder_order_size, sizeof(void *), pi->order);
                os_calloc(Config.decoder_order_size, sizeof(char *), pi->fields);

                /* Check the values from the order */
                while (*norder) {
                    char *word = &(*norder)[strspn(*norder, " ")];
                    word[strcspn(word, " ")] = '\0';

                    if (strlen(word) == 0) {
                        merror_exit("decode-xml: Wrong field '%s' in the order"
                                  " of decoder '%s'", *norder, pi->name);
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
                        pi->order[order_int] = Data_FP;
                    } else if (!strcmp(word, "status")) {
                        pi->order[order_int] = Status_FP;
                    } else if (!strcmp(word, "system_name")) {
                        pi->order[order_int] = SystemName_FP;
                    } else {
                        pi->order[order_int] = DynamicField_FP;
                        pi->fields[order_int] = strdup(word);
                    }

                    free(*norder);
                    norder++;

                    order_int++;
                }

                free(s_norder);
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
                        merror_exit("decode-xml: Wrong field '%s' in the fts"
                                  " decoder '%s'", *norder, pi->name);
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

                        for (i = 0; pi->fields[i]; i++)
                            if (!strcasecmp(pi->fields[i], word))
                                break;


                        if (!pi->fields[i])
                            merror_exit("decode-xml: Wrong field '%s' in the fts"
                                      " decoder '%s'", *norder, pi->name);

                        pi->fts |= FTS_DYNAMIC;
                        pi->fts_fields[i] = 1;
                    }

                    free(*norder);
                    norder++;
                }

                /* Clear memory here */
                free(s_norder);
            } else {
                merror("Invalid element '%s' for decoder '%s'", elements[j]->element, node[i]->element);
                goto cleanup;
            }

            /* NEXT */
            j++;

        } /* while(elements[j]) */

        OS_ClearNode(elements);
        elements = NULL;

        /* Prematch must be set */
        if (!prematch && !pi->parent && !p_name) {
            merror(DECODE_NOPRE, pi->name);
            merror(DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        /* If pi->regex is not set, fts must not be set too */
        if ((!regex && (pi->fts || pi->order)) || (regex && !pi->order)) {
            merror(DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        /* For the offsets */
        if ((pi->regex_offset & AFTER_PARENT) && !pi->parent) {
            merror(INV_OFFSET, "after_parent");
            merror(DEC_REGEX_ERROR, pi->name);
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
            } else if (!prematch) {
                merror(INV_OFFSET, "after_prematch");
                merror(DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
        }

        /* For the after_regex offset */
        if (pi->regex_offset & AFTER_PREVREGEX) {
            if (!pi->parent || !regex) {
                merror(INV_OFFSET, "after_regex");
                merror(DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
        }

        /* Check the prematch offset */
        if (pi->prematch_offset) {
            /* Only the after parent is allowed */
            if (pi->prematch_offset & AFTER_PARENT) {
                if (!pi->parent) {
                    merror(INV_OFFSET, "after_parent");
                    merror(DEC_REGEX_ERROR, pi->name);
                    goto cleanup;
                }
            } else {
                merror(DEC_REGEX_ERROR, pi->name);
                goto cleanup;
            }
        }

        // Check the plugin offset
        if ((pi->plugin_offset & AFTER_PARENT) && !pi->parent) {
            merror(INV_OFFSET, "after_parent");
            merror(DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        if (pi->plugin_offset & AFTER_PREMATCH && !prematch) {
            merror(INV_OFFSET, "after_prematch");
            merror(DEC_REGEX_ERROR, pi->name);
            goto cleanup;
        }

        /* Compile the regex/prematch */
        if (prematch) {
            os_calloc(1, sizeof(OSRegex), pi->prematch);
            if (!OSRegex_Compile(prematch, pi->prematch, 0)) {
                merror(REGEX_COMPILE, prematch, pi->prematch->error);
                goto cleanup;
            }

            free(prematch);
            prematch = NULL;
        }

        /* Compile the p_name */
        if (p_name) {
            os_calloc(1, sizeof(OSMatch), pi->program_name);
            if (!OSMatch_Compile(p_name, pi->program_name, 0)) {
                merror(REGEX_COMPILE, p_name, pi->program_name->error);
                goto cleanup;
            }

            free(p_name);
            p_name = NULL;
        }

        /* We may not have the pi->regex */
        if (regex) {
            os_calloc(1, sizeof(OSRegex), pi->regex);
            if (!OSRegex_Compile(regex, pi->regex, OS_RETURN_SUBSTRING)) {
                merror(REGEX_COMPILE, regex, pi->regex->error);
                goto cleanup;
            }

            /* We must have the sub_strings to retrieve the nodes */
            if (!pi->regex->d_sub_strings) {
                merror(REGEX_SUBS, regex);
                goto cleanup;
            }

            free(regex);
            regex = NULL;
        }

        /* Validate arguments */
        if (pi->plugindecoder && (pi->regex || pi->order)) {
            merror(DECODE_ADD, pi->name);
            goto cleanup;
        }

        /* Add osdecoder to the list */
        if (!OS_AddOSDecoder(pi)) {
            merror(DECODER_ERROR);
            goto cleanup;
        }

        pi = NULL;
        i++;
    } /* while (node[i]) */

    retval = 1;

cleanup:

    free(p_name);
    free(prematch);
    free(regex);

    /* Clean node and XML structures */
    OS_ClearNode(elements);
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    FreeDecoderInfo(pi);

    return retval;
}

int SetDecodeXML()
{
    /* Add rootcheck decoder to list */
    addDecoder2list(ROOTCHECK_MOD);
    addDecoder2list(SYSCHECK_MOD);
    addDecoder2list(SYSCHECK_NEW);
    addDecoder2list(SYSCHECK_DEL);
    addDecoder2list(HOSTINFO_NEW);
    addDecoder2list(HOSTINFO_MOD);
    addDecoder2list(SYSCOLLECTOR_MOD);
    addDecoder2list(CISCAT_MOD);
    addDecoder2list(WINEVT_MOD);

    /* Set ids - for our two lists */
    if (!os_setdecoderids(NULL)) {
        merror(DECODER_ERROR);
        return (0);
    }
    if (!os_setdecoderids(ARGV0)) {
        merror(DECODER_ERROR);
        return (0);
    }

    return (1);
}

/* Allocate memory at "*at" and copy *str to it
 * If *at already exist, realloc the memory and cat str on it
 * Returns the new string
 */
char *_loadmemory(char *at, char *str)
{
    if (at == NULL) {
        size_t strsize = 0;
        if ((strsize = strlen(str)) < OS_SIZE_1024) {
            at = (char *) calloc(strsize + 1, sizeof(char));
            if (at == NULL) {
                merror(MEM_ERROR, errno, strerror(errno));
                return (NULL);
            }
            strncpy(at, str, strsize);
            return (at);
        } else {
            merror(SIZE_ERROR, str);
            return (NULL);
        }
    }
    /* At is not null. Need to reallocate its memory and copy str to it */
    else {
        size_t strsize = strlen(str);
        size_t atsize = strlen(at);
        size_t finalsize = atsize + strsize + 1;
        if (finalsize > OS_SIZE_1024) {
            merror(SIZE_ERROR, str);
            return (NULL);
        }
        at = (char *) realloc(at, (finalsize + 1) * sizeof(char));
        if (at == NULL) {
            merror(MEM_ERROR, errno, strerror(errno));
            return (NULL);
        }
        strncat(at, str, strsize);
        at[finalsize - 1] = '\0';

        return (at);
    }
    return (NULL);
}

void FreeDecoderInfo(OSDecoderInfo *pi) {
    int i;

    if (pi) {
        free(pi->parent);
        free(pi->name);

        if (pi->fields) {
            for (i = 0; i < Config.decoder_order_size; i++) {
                free(pi->fields[i]);
            }

            free(pi->fields);
        }

        free(pi->fts_fields);
        free(pi->regex);
        free(pi->prematch);
        free(pi->program_name);
        free(pi->order);

        free(pi);
    }
}
