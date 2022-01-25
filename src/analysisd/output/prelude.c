/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Wazuh to Prelude
 */

#ifdef PRELUDE_OUTPUT_ENABLED

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-message-print.h>

#include "prelude.h"

#include "syscheck_op.h"
#include "shared.h"
#include "rules.h"

#define DEFAULT_ANALYZER_NAME "OSSEC"
#define ANALYZER_CLASS "Host IDS, File Integrity Checker, Log Analyzer"
#define ANALYZER_MODEL "Ossec"
#define ANALYZER_MANUFACTURER __site
#define ANALYZER_VERSION __ossec_version

/** Wazuh to prelude severity mapping. **/
static const char *(wazuh2prelude_sev[]) = {"info", "info", "info", "info",
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
        merror("Wazuh2Prelude: IDMEF: Cannot add object '%s': %s.",
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
    merror("Wazuh2Prelude: %s: IDMEF error: %s.",
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
                           const char *perm)
{
    mode_t octal_perms = 0;

    if (perm) {
      sscanf(perm, "%o", &octal_perms);
    }

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
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(>>).algorithm", "SHA2-256");
        add_idmef_object(idmef, "alert.target(0).file(-1).checksum(-1).value", sha256);
    }

    /* Add the owner */
    if (owner) {
        mdebug1("owner = %s.", owner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(>>).user_id.number", owner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).user_id.type", "user-privs");

        if (octal_perms & S_IRWXU) {
            /* Add the permissions */
            if (octal_perms & S_IWUSR) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "write");
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "delete");
            }
            if (octal_perms & S_IXUSR) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "execute");
            }
            if (octal_perms & S_IRUSR ) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "read");
            }
            if (octal_perms & S_ISUID) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "executeAs");
            }
        } else if (perm && *perm) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "noAccess");
        }
    }

    /* Add the group owner */
    if (gowner) {
        mdebug1("gowner = %s.", gowner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(>>).user_id.number", gowner);
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).user_id.type", "group-privs");

        if (octal_perms & S_IRWXG) {
            /* Add the permissions */
            if (octal_perms & S_IWGRP) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "write");
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "delete");
            }
            if (octal_perms & S_IXGRP) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "execute");
            }
            if (octal_perms & S_IRGRP ) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "read");
            }
            if (octal_perms & S_ISGID) {
                add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "executeAs");
            }
        } else if (perm && *perm) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "noAccess");
        }
    }

    add_idmef_object(idmef, "alert.target(0).file(-1).file_access(>>).user_id.type", "other-privs");

    if (octal_perms & S_IRWXO) {
        /* Add the permissions */
        if (octal_perms & S_IWOTH) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "write");
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "delete");
        }
        if (octal_perms & S_IXOTH) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "execute");
        }
        if (octal_perms & S_IROTH ) {
            add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "read");
        }
    } else if (perm && *perm) {
        add_idmef_object(idmef, "alert.target(0).file(-1).file_access(-1).permission(>>)", "noAccess");
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
    char * saveptr;

    /* Generate prelude alert */
    ret = idmef_message_new(&idmef);
    if ( ret < 0 ) {
        merror("Wazuh2Prelude: Cannot create IDMEF message");
        return;
    }

    add_idmef_object(idmef, "alert.assessment.impact.description",
                     lf->generated_rule->comment);

    add_idmef_object(idmef, "alert.assessment.impact.severity",
                     (lf->generated_rule->level > 15) ? "high" :
                     wazuh2prelude_sev[lf->generated_rule->level]);

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
         * information if present in the triggering rule
         */
        if (lf->generated_rule->cve) {
            add_idmef_object(idmef, "alert.classification.reference(>>).origin", "cve");
            add_idmef_object(idmef, "alert.classification.reference(-1).name", lf->generated_rule->cve);

            snprintf(_prelude_data, 256, "CVE:%s", lf->generated_rule->cve);
            add_idmef_object(idmef, "alert.classification.reference(-1).meaning", _prelude_data);
        }

        /* Check Wazuh rules for reference */
        if (lf->generated_rule->sigid) {
            add_idmef_object(idmef, "alert.classification.reference(>>).origin", "vendor-specific");

            snprintf(_prelude_data, 256, "Rule:%d", lf->generated_rule->sigid);
            add_idmef_object(idmef, "alert.classification.reference(-1).name", _prelude_data);
            add_idmef_object(idmef, "alert.classification.reference(-1).meaning", "Wazuh Ruleset");

            snprintf(_prelude_data, 256, "https://github.com/wazuh/wazuh/tree/master/ruleset");
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
         * that points back to Wazuh ruleset for more infomation.
         */
        if (lf->generated_rule->group) {
            char *copy_group;
            char new_generated_rule_group[256];
            new_generated_rule_group[255] = '\0';
            strncpy(new_generated_rule_group, lf->generated_rule->group, 255);
            copy_group = strtok_r(new_generated_rule_group, ",", &saveptr);
            while (copy_group) {
                add_idmef_object(idmef, "alert.classification.reference(>>).origin", "vendor-specific");

                snprintf(_prelude_data, 256, "Group:%s", copy_group);
                add_idmef_object(idmef, "alert.classification.reference(-1).name", _prelude_data);

                add_idmef_object(idmef, "alert.classification.reference(-1).meaning", "Wazuh Ruleset");

                snprintf(_prelude_data, 256, "https://github.com/wazuh/wazuh/tree/master/ruleset");
                add_idmef_object(idmef, "alert.classification.reference(-1).url", _prelude_data);

                copy_group = strtok_r(NULL, ",", &saveptr);
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
    mdebug1("lf->fields[FIM_FILE].value = %s.", lf->fields[FIM_FILE].value);
    if (lf->decoder_info->name != NULL && strncmp(lf->decoder_info->name, "syscheck_", 9) == 0) {
        FileAccess_PreludeLog(idmef,
                              "original",
                              lf->fields[FIM_FILE].value,
                              lf->fields[FIM_MD5_BEFORE].value,
                              lf->fields[FIM_SHA1_BEFORE].value,
                              lf->fields[FIM_SHA256_BEFORE].value,
                              lf->fields[FIM_UID_BEFORE].value,
                              lf->fields[FIM_GID_BEFORE].value,
                              lf->fields[FIM_PERM_BEFORE].value);
        FileAccess_PreludeLog(idmef,
                              "current",
                              lf->fields[FIM_FILE].value,
                              lf->fields[FIM_MD5].value,
                              lf->fields[FIM_SHA1].value,
                              lf->fields[FIM_SHA256].value,
                              lf->fields[FIM_UID].value,
                              lf->fields[FIM_GID].value,
                              lf->fields[FIM_PERM].value);
        mdebug1("Done with alert.target(0).file(1)");
    }

    mdebug1("Sending IDMEF alert");
    prelude_client_send_idmef(prelude_client, idmef);
    mdebug1("Destroying IDMEF alert");
    idmef_message_destroy(idmef);
}

#endif /* PRELUDE_OUTPUT_ENABLED */
