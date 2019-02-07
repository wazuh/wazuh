/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * OSSEC to Prelude
 */

#ifdef PRELUDE_OUTPUT_ENABLED

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-message-print.h>

#include "prelude.h"

#include "shared.h"
#include "rules.h"

#define DEFAULT_ANALYZER_NAME "OSSEC"
#define ANALYZER_CLASS "Host IDS, File Integrity Checker, Log Analyzer"
#define ANALYZER_MODEL "Ossec"
#define ANALYZER_MANUFACTURER __site
#define ANALYZER_VERSION __ossec_version

/** OSSEC to prelude severity mapping. **/
static const char *(ossec2prelude_sev[]) = {"info", "info", "info", "info",
                               "low", "low", "low", "low",
                               "medium", "medium", "medium", "medium",
                               "high", "high", "high", "high", "high"
                              };

/* Prelude client */
static prelude_client_t *prelude_client;


/*void prelude_idmef_debug(idmef_message_t *idmef)
{
    prelude_io_t *pio;

    prelude_io_new(&pio);
    prelude_io_set_file_io(pio, stderr);
    idmef_message_print(idmef, pio);
    prelude_io_destroy(pio);
}*/

static int
add_idmef_object(idmef_message_t *msg, const char *object, const char *value)
{
    int ret = 0;
    idmef_value_t *val;
    idmef_path_t *path;

    if (value == NULL) {
        return (0);
    }

    ret = idmef_path_new_fast(&path, object);
    if (ret < 0) {
        return (-1);
    }

    ret = idmef_value_new_from_path(&val, path, value);
    if (ret < 0) {
        idmef_path_destroy(path);
        return (-1);
    }

    ret = idmef_path_set(path, msg, val);
    if (ret < 0) {
        merror("OSSEC2Prelude: IDMEF: Cannot add object '%s': %s.",
               object, prelude_strerror(ret));
    }

    idmef_value_destroy(val);
    idmef_path_destroy(path);

    return (ret);
}

static int
setup_analyzer(idmef_analyzer_t *analyzer)
{
    int ret;
    prelude_string_t *string;

    ret = idmef_analyzer_new_model(analyzer, &string);
    if ( ret < 0 ) {
        goto err;
    }
    prelude_string_set_constant(string, ANALYZER_MODEL);

    ret = idmef_analyzer_new_class(analyzer, &string);
    if ( ret < 0 ) {
        goto err;
    }
    prelude_string_set_constant(string, ANALYZER_CLASS);

    ret = idmef_analyzer_new_manufacturer(analyzer, &string);
    if ( ret < 0 ) {
        goto err;
    }
    prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

    ret = idmef_analyzer_new_version(analyzer, &string);
    if ( ret < 0 ) {
        goto err;
    }
    prelude_string_set_constant(string, ANALYZER_VERSION);

    return 0;

err:
    merror("OSSEC2Prelude: %s: IDMEF error: %s.",
           prelude_strsource(ret), prelude_strerror(ret));

    return -1;
}

void prelude_start(const char *profile, int argc, char **argv)
{
    int ret;
    prelude_client = NULL;

    ret = prelude_init(&argc, argv);
    if (ret < 0) {
        merror("%s: Unable to initialize the Prelude library: %s.",
               prelude_strsource(ret), prelude_strerror(ret));
        return;
    }

    ret = prelude_client_new(&prelude_client,
                             profile != NULL ? profile : DEFAULT_ANALYZER_NAME);
    if (!prelude_client) {
        merror("%s: Unable to create a prelude client object: %s.",
               prelude_strsource(ret), prelude_strerror(ret));

        return;
    }

    ret = setup_analyzer(prelude_client_get_analyzer(prelude_client));
    if (ret < 0) {
        merror("%s: Unable to setup analyzer: %s",
               prelude_strsource(ret), prelude_strerror(ret));

        prelude_client_destroy(prelude_client,
                               PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        return;
    }

    ret = prelude_client_set_flags(prelude_client,
                                   prelude_client_get_flags(prelude_client)
                                   | PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if (ret < 0) {
        merror("%s: Unable to set prelude client flags: %s.",
               prelude_strsource(ret), prelude_strerror(ret));
    }

    /* Set uid and gid of ossec */
    prelude_client_profile_set_uid(prelude_client_get_profile(prelude_client),
                                   Privsep_GetUser(USER));
    prelude_client_profile_set_gid(prelude_client_get_profile(prelude_client),
                                   Privsep_GetGroup(GROUPGLOBAL));

    ret = prelude_client_start(prelude_client);
    if (ret < 0) {
        merror("%s: Unable to initialize prelude client: %s.",
               prelude_strsource(ret), prelude_strerror(ret));

        prelude_client_destroy(prelude_client,
                               PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        return;
    }

    return;
}

static void FileAccess_PreludeLog(idmef_message_t *idmef,
                           const char *category,
                           const char *filename,
                           const char *md5,
                           const char *sha1,
                           const char *sha256,
                           const char *owner,
                           const char *gowner,
                           int perm)
{

    mdebug1("filename = %s.", filename);
    mdebug1("category = %s.", category);
    add_idmef_object(idmef, "alert.target(0).file(>>).name", filename);
    add_idmef_object(idmef, "alert.target(0).file(-1).category", category);

    /* Add the hashes */
    if (md5) {
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(>>).algorithm", "MD5");
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(-1).value", md5);
    }
    if (sha1) {
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(>>).algorithm", "SHA1");
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(-1).value", sha1);
    }
    if (sha256) {
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(>>).algorithm", "SHA256");
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(-1).value", sha256);
    }

    /* Add the owner */
    if (owner) {
        mdebug1("owner = %s.", owner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(>>).user_id.number", owner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).user_id.type", "user-privs");

        if (perm) {
            /* Add the permissions */
            if (perm & S_IWUSR) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "write");
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "delete");
            }
            if (perm & S_IXUSR) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "execute");
            }
            if (perm & S_IRUSR ) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "read");
            }
            if (perm & S_ISUID) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "executeAs");
            }
        }
    }

    /* Add the group owner */
    if (gowner) {
        mdebug1("gowner = %s.", gowner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(>>).user_id.number", gowner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).user_id.type", "group-privs");

        if (perm) {
            /* Add the permissions */
            if (perm & S_IWGRP) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "write");
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "delete");
            }
            if (perm & S_IXGRP) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "execute");
            }
            if (perm & S_IRGRP ) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "read");
            }
            if (perm & S_ISGID) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "executeAs");
            }
        }
    }

    add_idmef_object(idmef, "alert.target(0).file(-1).file_access(>>).user_id.type", "other-privs");

    if (perm) {
        /* Add the permissions */
        if (perm & S_IWOTH) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "write");
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "delete");
        }
        if (perm & S_IXOTH) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "execute");
        }
        if (perm & S_IROTH ) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "read");
        }
    }
    return;
}

void OS_PreludeLog(const Eventinfo *lf)
{
    int ret;
    char _prelude_data[256];
    char *origin;
    idmef_message_t *idmef;
    RuleInfoDetail *last_info_detail;

    /* Generate prelude alert */
    ret = idmef_message_new(&idmef);
    if ( ret < 0 ) {
        merror("OSSEC2Prelude: Cannot create IDMEF message");
        return;
    }

    add_idmef_object(idmef, "alert.assessment.impact.description",
                     lf->generated_rule->comment);

    add_idmef_object(idmef, "alert.assessment.impact.severity",
                     (lf->generated_rule->level > 15) ? "high" :
                     ossec2prelude_sev[lf->generated_rule->level]);

    add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded");

    if (lf->action) {
        switch (*lf->action) {
            /* discard, drop, deny, */
            case 'd':
            case 'D':
            /* reject, */
            case 'r':
            case 'R':
            /* block */
            case 'b':
            case 'B':
                snprintf(_prelude_data, 256, "DROP: %s", lf->action);
                break;
            /* Closed */
            case 'c':
            case 'C':
            /* Teardown */
            case 't':
            case 'T':
                snprintf(_prelude_data, 256, "CLOSED: %s", lf->action);
                break;
            /* allow, accept, */
            case 'a':
            case 'A':
            /* pass/permitted */
            case 'p':
            case 'P':
            /* open */
            case 'o':
            case 'O':
                snprintf(_prelude_data, 256, "ALLOW: %s", lf->action);
                break;
            default:
                snprintf(_prelude_data, 256, "%s", lf->action);
                break;
        }
        add_idmef_object(idmef, "alert.assessment.action(0).category", "3");
        add_idmef_object(idmef, "alert.assessment.action(0).description", _prelude_data);
    }

    /* Begin Classification Infomations */
    {
        add_idmef_object(idmef, "alert.classification.text",
                         lf->generated_rule->comment);

        /* The Common Vulnerabilities and Exposures (CVE) (http://www.cve.mitre.org/)
         * infomation if present in the triggering rule
         */
        if (lf->generated_rule->cve) {
            add_idmef_object(idmef, "alert.classification.reference(>>).origin", "cve");
            add_idmef_object(idmef, "alert.classification.reference(-1).name", lf->generated_rule->cve);

            snprintf(_prelude_data, 256, "CVE:%s", lf->generated_rule->cve);
            add_idmef_object(idmef, "alert.classification.reference(-1).meaning", _prelude_data);
        }

        /* Rule sid is used to create a link to the rule on the OSSEC wiki */
        if (lf->generated_rule->sigid) {
            add_idmef_object(idmef, "alert.classification.reference(>>).origin", "vendor-specific");

            snprintf(_prelude_data, 256, "Rule:%d", lf->generated_rule->sigid);
            add_idmef_object(idmef, "alert.classification.reference(-1).name", _prelude_data);
            add_idmef_object(idmef, "alert.classification.reference(-1).meaning", "OSSEC Rule Wiki Documentation");

            snprintf(_prelude_data, 256, "http://www.ossec.net/wiki/Rule:%d",
                     lf->generated_rule->sigid);
            add_idmef_object(idmef, "alert.classification.reference(-1).url", _prelude_data);
        }

        /* Extended Info Details */
        for (last_info_detail = lf->generated_rule->info_details;
                last_info_detail != NULL;
                last_info_detail = last_info_detail->next) {
            if (last_info_detail->type == RULEINFODETAIL_LINK) {
                add_idmef_object(idmef, "alert.classification.reference(>>).origin", "vendor-specific");

                snprintf(_prelude_data, 256, "Rule:%d link", lf->generated_rule->sigid);
                add_idmef_object(idmef, "alert.classification.reference(-1).name", _prelude_data);
                add_idmef_object(idmef, "alert.classification.reference(-1).url", last_info_detail->data);

            } else if (last_info_detail->type == RULEINFODETAIL_TEXT) {
                add_idmef_object(idmef, "alert.classification.reference(>>).origin", "vendor-specific");

                snprintf(_prelude_data, 256, "Rule:%d info", lf->generated_rule->sigid);
                add_idmef_object(idmef, "alert.classification.reference(-1).name", _prelude_data);

                add_idmef_object(idmef, "alert.classification.reference(-1).meaning", last_info_detail->data);

            } else {
                switch (last_info_detail->type) {
                    case RULEINFODETAIL_CVE:
                        origin = "cve";
                        break;
                    case RULEINFODETAIL_OSVDB:
                        origin = "osvdb";
                        break;
                    case RULEINFODETAIL_BUGTRACK:
                        origin = "bugtraqid";
                        break;
                    default:
                        origin = "vendor-specific";
                        break;
                }
                add_idmef_object(idmef, "alert.classification.reference(>>).origin", origin);
                add_idmef_object(idmef, "alert.classification.reference(-1).name", last_info_detail->data);
            }
        }

        /* Break up the list of groups on the "," boundary
         * For each section create a prelude reference classification
         * that points back to the the OSSEC wiki for more infomation.
         */
        if (lf->generated_rule->group) {
            char *copy_group;
            char new_generated_rule_group[256];
            new_generated_rule_group[255] = '\0';
            strncpy(new_generated_rule_group, lf->generated_rule->group, 255);
            copy_group = strtok(new_generated_rule_group, ",");
            while (copy_group) {
                add_idmef_object(idmef, "alert.classification.reference(>>).origin", "vendor-specific");

                snprintf(_prelude_data, 256, "Group:%s", copy_group);
                add_idmef_object(idmef, "alert.classification.reference(-1).name", _prelude_data);

                add_idmef_object(idmef, "alert.classification.reference(-1).meaning", "OSSEC Group Wiki Documentation");

                snprintf(_prelude_data, 256, "http://www.ossec.net/wiki/Group:%s",
                         copy_group);
                add_idmef_object(idmef, "alert.classification.reference(-1).url", _prelude_data);

                copy_group = strtok(NULL, ",");
            }
        }
    } /* end classification block */

    /* Begin Node infomation block */
    {
        /* Set source info */
        add_idmef_object(idmef, "alert.source(0).spoofed", "no");
        add_idmef_object(idmef, "alert.source(0).node.address(0).address",
                         lf->srcip);
        add_idmef_object(idmef, "alert.source(0).service.port", lf->srcport);

        if (lf->srcuser) {
            add_idmef_object(idmef, "alert.source(0).user.user_id(0).name", lf->srcuser);
        }

        /* Set target */
        add_idmef_object(idmef, "alert.target(0).service.name", lf->program_name);
        add_idmef_object(idmef, "alert.target(0).spoofed", "no");

        if (lf->dstip) {
            add_idmef_object(idmef, "alert.target(0).node.address(0).address",
                             lf->dstip);
        } else {
            char *tmp_str;
            char new_prelude_target[256];

            new_prelude_target[255] = '\0';
            strncpy(new_prelude_target, lf->hostname, 255);

            /* The messages can have the file, so we need to remove it
             * Formats can be:
             *   enigma->/var/log/authlog
             *   (esqueleto2) 192.168.2.99->/var/log/squid/access.log
             */
            tmp_str = strstr(new_prelude_target, "->");
            if (tmp_str) {
                *tmp_str = '\0';
            }
            add_idmef_object(idmef, "alert.target(0).node.address(0).address",
                             new_prelude_target);
        }
        add_idmef_object(idmef, "alert.target(0).service.name", lf->hostname);
        add_idmef_object(idmef, "alert.target(0).service.port", lf->dstport);

        if (lf->dstuser) {
            add_idmef_object(idmef, "alert.target(0).user.category", "2");
            add_idmef_object(idmef, "alert.target(0).user.user_id(0).name", lf->dstuser);
        }
    } /* end Node infomation block */

    /* Set source file */
    add_idmef_object(idmef, "alert.additional_data(0).type", "string");
    add_idmef_object(idmef, "alert.additional_data(0).meaning", "Source file");
    add_idmef_object(idmef, "alert.additional_data(0).data", lf->location);

    /* Set full log */
    add_idmef_object(idmef, "alert.additional_data(1).type", "string");
    add_idmef_object(idmef, "alert.additional_data(1).meaning", "Full Log");
    add_idmef_object(idmef, "alert.additional_data(1).data", lf->full_log);

    idmef_alert_set_analyzer(idmef_message_get_alert(idmef),
                             idmef_analyzer_ref
                             (prelude_client_get_analyzer(prelude_client)),
                             IDMEF_LIST_PREPEND);
    mdebug1("lf->filename = %s.", lf->filename);
    if (lf->filename) {
        FileAccess_PreludeLog(idmef,
                              "original",
                              lf->filename,
                              lf->md5_before,
                              lf->sha1_before,
                              lf->sha256_before,
                              lf->owner_before,
                              lf->gowner_before,
                              lf->perm_before);
        FileAccess_PreludeLog(idmef,
                              "current",
                              lf->filename,
                              lf->md5_after,
                              lf->sha1_after,
                              lf->sha256_after,
                              lf->owner_after,
                              lf->gowner_after,
                              lf->perm_after);
        mdebug1("Done with alert.target(0).file(1)");
    }

    mdebug1("Sending IDMEF alert");
    prelude_client_send_idmef(prelude_client, idmef);
    mdebug1("Destroying IDMEF alert");
    idmef_message_destroy(idmef);
}

#endif /* PRELUDE_OUTPUT_ENABLED */
