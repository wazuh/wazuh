/* Copyright (C) 2009 Trend Micro Inc.
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
#define ANALYZER_VERSION __version
#define FILE_USER 0
#define FILE_GROUP 1
#define FILE_OTHER 2

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
        merror("%s: OSSEC2Prelude: IDMEF: Cannot add object '%s': %s.",
               ARGV0, object, prelude_strerror(ret));
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
    merror("%s: OSSEC2Prelude: %s: IDMEF error: %s.",
           ARGV0, prelude_strsource(ret), prelude_strerror(ret));

    return -1;
}

void prelude_start(const char *profile, int argc, char **argv)
{
    int ret;
    prelude_client = NULL;

    ret = prelude_init(&argc, argv);
    if (ret < 0) {
        merror("%s: %s: Unable to initialize the Prelude library: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));
        return;
    }

    ret = prelude_client_new(&prelude_client,
                             profile != NULL ? profile : DEFAULT_ANALYZER_NAME);
    if (!prelude_client) {
        merror("%s: %s: Unable to create a prelude client object: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));

        return;
    }

    ret = setup_analyzer(prelude_client_get_analyzer(prelude_client));
    if (ret < 0) {
        merror("%s: %s: Unable to setup analyzer: %s",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));

        prelude_client_destroy(prelude_client,
                               PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        return;
    }

    ret = prelude_client_set_flags(prelude_client,
                                   prelude_client_get_flags(prelude_client)
                                   | PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if (ret < 0) {
        merror("%s: %s: Unable to set prelude client flags: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));
    }

    /* Set uid and gid of ossec */
    prelude_client_profile_set_uid(prelude_client_get_profile(prelude_client),
                                   Privsep_GetUser(USER));
    prelude_client_profile_set_gid(prelude_client_get_profile(prelude_client),
                                   Privsep_GetGroup(GROUPGLOBAL));

    ret = prelude_client_start(prelude_client);
    if (ret < 0) {
        merror("%s: %s: Unable to initialize prelude client: %s.",
               ARGV0, prelude_strsource(ret), prelude_strerror(ret));

        prelude_client_destroy(prelude_client,
                               PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        return;
    }

    return;
}

static void FileAccess_PreludeLog(idmef_message_t *idmef,
                           int filenum,
                           const char *filename,
                           const char *md5,
                           const char *sha1,
                           const char *owner,
                           const char *gowner,
                           int perm)
{

    int _checksum_counter = 0;
    char _prelude_section[128];
    _prelude_section[127] = '\0';

    debug1("%s: DEBUG: filename = %s.", ARGV0, filename);
    debug1("%s: DEBUG: filenum = %d.", ARGV0, filenum);
    if (filenum == 0) {
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).name", filenum);
        add_idmef_object(idmef, _prelude_section, filename);
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).category", filenum);
        add_idmef_object(idmef, _prelude_section, "original");
    } else if (filenum == 1) {
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).name", filenum);
        add_idmef_object(idmef, _prelude_section, filename);
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).category", filenum);
        add_idmef_object(idmef, _prelude_section, "current");
    } else {
        return;
    }

    /* Add the hashes */
    if (md5) {
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).checksum(%d).algorithm", filenum, _checksum_counter);
        add_idmef_object(idmef, _prelude_section, "MD5");
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).checksum(%d).value", filenum, _checksum_counter);
        add_idmef_object(idmef, _prelude_section, md5);
        _checksum_counter++;
    }
    if (sha1) {
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).checksum(%d).algorithm", filenum, _checksum_counter);
        add_idmef_object(idmef, _prelude_section, "SHA1");
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).checksum(%d).value", filenum, _checksum_counter);
        add_idmef_object(idmef, _prelude_section, sha1);
        _checksum_counter++;
    }

    /* Add the owner */
    if (owner) {
        debug1("%s: DEBUG: owner = %s.", ARGV0, owner);
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).user_id.number", filenum, FILE_USER);
        add_idmef_object(idmef, _prelude_section, owner);
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).user_id.type", filenum, FILE_USER);
        add_idmef_object(idmef, _prelude_section, "user-privs");
    }

    /* Add the group owner */
    if (gowner) {
        debug1("%s: DEBUG: gowner = %s.", ARGV0, gowner);
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).user_id.number", filenum, FILE_GROUP);
        add_idmef_object(idmef, _prelude_section, gowner);
        snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).user_id.type", filenum, FILE_GROUP);
        add_idmef_object(idmef, _prelude_section, "group-privs");
    }

    /* Add the permissions */
    if (perm) {
        if (perm & S_IWUSR) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(0)", filenum, FILE_USER);
            add_idmef_object(idmef, _prelude_section, "write");
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(1)", filenum, FILE_USER);
            add_idmef_object(idmef, _prelude_section, "delete");
        }
        if (perm & S_IXUSR) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(2)", filenum, FILE_USER);
            add_idmef_object(idmef, _prelude_section, "execute");
        }
        if (perm & S_IRUSR ) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(3)", filenum, FILE_USER);
            add_idmef_object(idmef, _prelude_section, "read");
        }
        if (perm & S_ISUID) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(4)", filenum, FILE_USER);
            add_idmef_object(idmef, _prelude_section, "executeAs");
        }

        if (perm & S_IWGRP) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(0)", filenum, FILE_GROUP);
            add_idmef_object(idmef, _prelude_section, "write");
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(1)", filenum, FILE_GROUP);
            add_idmef_object(idmef, _prelude_section, "delete");
        }
        if (perm & S_IXGRP) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(2)", filenum, FILE_GROUP);
            add_idmef_object(idmef, _prelude_section, "execute");
        }
        if (perm & S_IRGRP ) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(3)", filenum, FILE_GROUP);
            add_idmef_object(idmef, _prelude_section, "read");
        }
        if (perm & S_ISGID) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(4)", filenum, FILE_GROUP);
            add_idmef_object(idmef, _prelude_section, "executeAs");
        }
        if (perm & S_IWOTH) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(0)", filenum, FILE_OTHER);
            add_idmef_object(idmef, _prelude_section, "write");
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(1)", filenum, FILE_OTHER);
            add_idmef_object(idmef, _prelude_section, "delete");
        }
        if (perm & S_IXOTH) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(2)", filenum, FILE_OTHER);
            add_idmef_object(idmef, _prelude_section, "execute");
        }
        if (perm & S_IROTH ) {
            snprintf(_prelude_section, 128, "alert.target(0).file(%d).File_Access(%d).permission(3)", filenum, FILE_OTHER);
            add_idmef_object(idmef, _prelude_section, "read");
        }
    }
    return;
}

void OS_PreludeLog(const Eventinfo *lf)
{
    int ret;
    int classification_counter = 0;
    int additional_data_counter = 0;
    char _prelude_section[128];
    char _prelude_data[256];
    idmef_message_t *idmef;
    RuleInfoDetail *last_info_detail;

    /* Generate prelude alert */
    ret = idmef_message_new(&idmef);
    if ( ret < 0 ) {
        merror("%s: OSSEC2Prelude: Cannot create IDMEF message", ARGV0);
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
            snprintf(_prelude_section, 128, "alert.classification.reference(%d).origin",
                     classification_counter);
            add_idmef_object(idmef, _prelude_section, "cve");
            snprintf(_prelude_section, 128, "alert.classification.reference(%d).name",
                     classification_counter);
            add_idmef_object(idmef, _prelude_section, lf->generated_rule->cve);
            snprintf(_prelude_section, 128, "alert.classification.reference(%d).meaning",
                     classification_counter);
            snprintf(_prelude_data, 256, "CVE:%s", lf->generated_rule->cve);
            add_idmef_object(idmef, _prelude_section, _prelude_data);
            classification_counter++;
        }

        /* Rule sid is used to create a link to the rule on the OSSEC wiki */
        if (lf->generated_rule->sigid) {
            snprintf(_prelude_section, 128, "alert.classification.reference(%d).origin",
                     classification_counter);
            add_idmef_object(idmef, _prelude_section, "vendor-specific");

            snprintf(_prelude_section, 128, "alert.classification.reference(%d).name",
                     classification_counter);
            snprintf(_prelude_data, 256, "Rule:%d", lf->generated_rule->sigid);
            add_idmef_object(idmef, _prelude_section, _prelude_data);

            snprintf(_prelude_section, 128, "alert.classification.reference(%d).meaning",
                     classification_counter);
            add_idmef_object(idmef, _prelude_section, "OSSEC Rule Wiki Documentation");

            snprintf(_prelude_section, 128, "alert.classification.reference(%d).url",
                     classification_counter);
            snprintf(_prelude_data, 256, "http://www.ossec.net/wiki/Rule:%d",
                     lf->generated_rule->sigid);
            add_idmef_object(idmef, _prelude_section, _prelude_data);

            classification_counter++;
        }

        /* Extended Info Details */
        for (last_info_detail = lf->generated_rule->info_details;
                last_info_detail != NULL;
                last_info_detail = last_info_detail->next) {
            if (last_info_detail->type == RULEINFODETAIL_LINK) {
                snprintf(_prelude_section, 128, "alert.classification.reference(%d).origin",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, "vendor-specific");

                snprintf(_prelude_section, 128, "alert.classification.reference(%d).name",
                         classification_counter);
                snprintf(_prelude_data, 256, "Rule:%d link", lf->generated_rule->sigid);
                add_idmef_object(idmef, _prelude_section, _prelude_data);
                snprintf(_prelude_section, 128, "alert.classification.reference(%d).url",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, last_info_detail->data);

                classification_counter++;
            } else if (last_info_detail->type == RULEINFODETAIL_TEXT) {
                snprintf(_prelude_section, 128, "alert.classification.reference(%d).origin",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, "vendor-specific");

                snprintf(_prelude_section, 128, "alert.classification.reference(%d).name",
                         classification_counter);
                snprintf(_prelude_data, 256, "Rule:%d info", lf->generated_rule->sigid);
                add_idmef_object(idmef, _prelude_section, _prelude_data);

                snprintf(_prelude_section, 128, "alert.classification.reference(%d).meaning",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, last_info_detail->data);
                classification_counter++;
            } else {
                snprintf(_prelude_section, 128, "alert.classification.reference(%d).origin",
                         classification_counter);
                switch (last_info_detail->type) {
                    case RULEINFODETAIL_CVE:
                        add_idmef_object(idmef, _prelude_section, "cve");
                        break;
                    case RULEINFODETAIL_OSVDB:
                        add_idmef_object(idmef, _prelude_section, "osvdb");
                        break;
                    case RULEINFODETAIL_BUGTRACK:
                        add_idmef_object(idmef, _prelude_section, "bugtraqid");
                        break;
                    default:
                        add_idmef_object(idmef, _prelude_section, "vendor-specific");
                        break;
                }
                snprintf(_prelude_section, 128, "alert.classification.reference(%d).name",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, last_info_detail->data);
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
                snprintf(_prelude_section, 128, "alert.classification.reference(%d).origin",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, "vendor-specific");

                snprintf(_prelude_section, 128, "alert.classification.reference(%d).name",
                         classification_counter);
                snprintf(_prelude_data, 256, "Group:%s", copy_group);
                add_idmef_object(idmef, _prelude_section, _prelude_data);

                snprintf(_prelude_section, 128, "alert.classification.reference(%d).meaning",
                         classification_counter);
                add_idmef_object(idmef, _prelude_section, "OSSEC Group Wiki Documenation");

                snprintf(_prelude_section, 128, "alert.classification.reference(%d).url",
                         classification_counter);
                snprintf(_prelude_data, 256, "http://www.ossec.net/wiki/Group:%s",
                         copy_group);
                add_idmef_object(idmef, _prelude_section, _prelude_data);

                classification_counter++;
                copy_group = strtok(NULL, ",");
            }
        }
    } /* end classification block */

    /* Begin Node infomation block */
    {
        /* Set source info */
        add_idmef_object(idmef, "alert.source(0).Spoofed", "no");
        add_idmef_object(idmef, "alert.source(0).Node.Address(0).address",
                         lf->srcip);
        add_idmef_object(idmef, "alert.source(0).Service.port", lf->srcport);

        if (lf->srcuser) {
            add_idmef_object(idmef, "alert.source(0).User.user_id(0).name", lf->srcuser);
        }

        /* Set target */
        add_idmef_object(idmef, "alert.target(0).Service.name", lf->program_name);
        add_idmef_object(idmef, "alert.target(0).Spoofed", "no");

        if (lf->dstip) {
            add_idmef_object(idmef, "alert.target(0).Node.Address(0).address",
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
            add_idmef_object(idmef, "alert.target(0).Node.Address(0).address",
                             new_prelude_target);
        }
        add_idmef_object(idmef, "alert.target(0).Service.name", lf->hostname);
        add_idmef_object(idmef, "alert.target(0).Service.port", lf->dstport);

        if (lf->dstuser) {
            add_idmef_object(idmef, "alert.target(0).User.category", "2");
            add_idmef_object(idmef, "alert.target(0).User.user_id(0).name", lf->dstuser);
        }
    } /* end Node infomation block */

    /* Set source file */
    add_idmef_object(idmef, "alert.additional_data(0).type", "string");
    add_idmef_object(idmef, "alert.additional_data(0).meaning", "Source file");
    add_idmef_object(idmef, "alert.additional_data(0).data", lf->location);
    additional_data_counter++;

    /* Set full log */
    add_idmef_object(idmef, "alert.additional_data(1).type", "string");
    add_idmef_object(idmef, "alert.additional_data(1).meaning", "Full Log");
    add_idmef_object(idmef, "alert.additional_data(1).data", lf->full_log);
    additional_data_counter++;

    idmef_alert_set_analyzer(idmef_message_get_alert(idmef),
                             idmef_analyzer_ref
                             (prelude_client_get_analyzer(prelude_client)),
                             IDMEF_LIST_PREPEND);
    debug1("%s: DEBUG: lf->filename = %s.", ARGV0, lf->filename);
    if (lf->filename) {
        FileAccess_PreludeLog(idmef,
                              0,
                              lf->filename,
                              lf->md5_before,
                              lf->sha1_before,
                              lf->owner_before,
                              lf->gowner_before,
                              lf->perm_before);
        FileAccess_PreludeLog(idmef,
                              1,
                              lf->filename,
                              lf->md5_after,
                              lf->sha1_after,
                              lf->owner_after,
                              lf->gowner_after,
                              lf->perm_after);
        debug1("%s: DEBUG: done with alert.target(0).file(1)", ARGV0);
    }

    debug1("%s: DEBUG: Sending IDMEF alert", ARGV0);
    prelude_client_send_idmef(prelude_client, idmef);
    debug1("%s: DEBUG: destroying IDMEF alert", ARGV0);
    idmef_message_destroy(idmef);
}

#endif /* PRELUDE_OUTPUT_ENABLED */

