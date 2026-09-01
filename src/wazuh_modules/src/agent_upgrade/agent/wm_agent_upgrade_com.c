/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC

#ifdef WIN32
#include "../unit_tests/wrappers/windows/io_wrappers.h"
#endif

#else
#define STATIC static
#endif

#include <shared.h>
#include "zlib.h"
#include "signature.h"
#include "wmodules.h"
#include "wm_agent_upgrade_agent.h"

typedef enum _command_error_codes {
    ERROR_OK = 0,
    ERROR_UPGRADES_NOT_ALLOWED,
    ERROR_UNKNOWN_COMMAND,
    ERROR_PARAMETERS_NOT_FOUND,
    ERROR_INVALID_FILE_NAME,
    ERROR_SIGNATURE,
    ERROR_COMPRESS,
    ERROR_CLEAN_DIRECTORY,
    ERROR_UNMERGE,
    ERROR_CHMOD,
    ERROR_EXEC
} command_error_codes;

STATIC const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_UPGRADES_NOT_ALLOWED] = "Upgrade module is disabled or not ready yet",
    [ERROR_UNKNOWN_COMMAND] = "Command not found",
    [ERROR_PARAMETERS_NOT_FOUND] = "Required parameters were not found",
    [ERROR_INVALID_FILE_NAME] = "Invalid file name",
    [ERROR_SIGNATURE] = "Could not verify signature",
    [ERROR_COMPRESS] = "Could not uncompress package",
    [ERROR_CLEAN_DIRECTORY] = "Could not clean up upgrade directory",
    [ERROR_UNMERGE] = "Error unmerging file",
    [ERROR_CHMOD] = "Could not chmod",
    [ERROR_EXEC] = "Error executing command"
};

// Variable used to allow new upgrades after confirming the result of the previous upgrade
bool allow_upgrades = false;

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @return string meessage with the response format
 * Response format:
 * {
 *    "error": {error_code},
 *    "message": "message",
 *    "data": []
 * }
 * */
STATIC char* wm_agent_upgrade_command_ack(int error_code, const char* message);

/**
 * Process a command that executes an upgrade script
 * @param json_obj expected json format
 * {
 *    "file" : "file_path",
 *    "installer" : "installer_path"
 * }
 * */
STATIC char * wm_agent_upgrade_com_upgrade(const cJSON* json_object) __attribute__((nonnull));

/* Helpers methods */
STATIC int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);
STATIC int _unsign(const char * source, char dest[PATH_MAX + 1]);
STATIC int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]);
STATIC const char * _tmpBareName(const char * path);

size_t wm_agent_upgrade_process_command(const char *buffer, char **output) {
    cJSON *buffer_obj = cJSON_Parse(buffer);

    if (buffer_obj) {
        cJSON *command_obj = cJSON_GetObjectItem(buffer_obj, upgrade_json_keys[WM_UPGRADE_COMMAND]);

        if (command_obj && (command_obj->type == cJSON_String)) {
            const char* command = command_obj->valuestring;

            if (allow_upgrades) {
                const cJSON *parameters = cJSON_GetObjectItem(buffer_obj, upgrade_json_keys[WM_UPGRADE_PARAMETERS]);
                if (!parameters) {
                    *output = wm_agent_upgrade_command_ack(ERROR_PARAMETERS_NOT_FOUND, error_messages[ERROR_PARAMETERS_NOT_FOUND]);
                } else if (strcmp(command, "upgrade") == 0) {
                    *output = wm_agent_upgrade_com_upgrade(parameters);
                }
            } else {
                *output = wm_agent_upgrade_command_ack(ERROR_UPGRADES_NOT_ALLOWED, error_messages[ERROR_UPGRADES_NOT_ALLOWED]);
            }
        }

        cJSON_Delete(buffer_obj);
    }

    if (!(*output)) {
       *output = wm_agent_upgrade_command_ack(ERROR_UNKNOWN_COMMAND, error_messages[ERROR_UNKNOWN_COMMAND]);
    }

    return strlen(*output);
}

STATIC char* wm_agent_upgrade_command_ack(int error_code, const char* message) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, upgrade_json_keys[WM_UPGRADE_ERROR], error_code);
    cJSON_AddStringToObject(root, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE], message);
    cJSON_AddItemToObject(root, upgrade_json_keys[WM_UPGRADE_DATA], cJSON_CreateArray());
    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return msg_string;
}

STATIC char * wm_agent_upgrade_com_upgrade(const cJSON* json_object) {
    char compressed[PATH_MAX + 1];
    char merged[PATH_MAX + 1];
    char installer_j[PATH_MAX + 1];
    const cJSON *package_obj = cJSON_GetObjectItem(json_object, "file");
    const cJSON *installer_obj = cJSON_GetObjectItem(json_object, "installer");
    int status = 0;
    char *out;

    int req_timeout = getDefine_Int("execd", "request_timeout", 1, 3600);

    // Unsign
    if (!package_obj || (package_obj->type != cJSON_String) || _unsign(package_obj->valuestring, compressed) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "upgrade", error_messages[ERROR_SIGNATURE]);
        return wm_agent_upgrade_command_ack(ERROR_SIGNATURE, error_messages[ERROR_SIGNATURE]);
    }

    // Uncompress
    if (_uncompress(compressed, package_obj->valuestring, merged) < 0) {
        unlink(compressed);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "upgrade", error_messages[ERROR_COMPRESS]);
        return wm_agent_upgrade_command_ack(ERROR_COMPRESS, error_messages[ERROR_COMPRESS]);
    }

    // Clean up upgrade folder
    if (cldir_ex(UPGRADE_DIR)) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "upgrade", error_messages[ERROR_CLEAN_DIRECTORY]);
        return wm_agent_upgrade_command_ack(ERROR_CLEAN_DIRECTORY, error_messages[ERROR_CLEAN_DIRECTORY]);
    }

    //Unmerge
    if (UnmergeFiles(merged, UPGRADE_DIR, OS_BINARY, NULL) == 0) {
        unlink(merged);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNMERGING_FILE_ERROR, "upgrade", merged);
        return wm_agent_upgrade_command_ack(ERROR_UNMERGE, error_messages[ERROR_UNMERGE]);
    }

    unlink(merged);

    // Installer executable file
    if (!installer_obj || (installer_obj->type != cJSON_String) || _jailfile(installer_j, UPGRADE_DIR, installer_obj->valuestring) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "upgrade");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    // Execute
#ifndef WIN32
    if (chmod(installer_j, 0750) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CHMOD_ERROR, "upgrade", installer_j);
        return wm_agent_upgrade_command_ack(ERROR_CHMOD, error_messages[ERROR_CHMOD]);
    }
#endif

    if (wm_exec(installer_j, &out, &status, req_timeout, NULL) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_ERROR, "upgrade", installer_j);
        os_free(out);
        return wm_agent_upgrade_command_ack(ERROR_EXEC, error_messages[ERROR_EXEC]);
    } else {
        char status_str[5];
        sprintf(status_str, "%d", status);
        os_free(out);
        return wm_agent_upgrade_command_ack(ERROR_OK, status_str);
    }
}

STATIC int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename) {

    if (w_ref_parent_folder(filename)) {
        return -1;
    }

#ifndef WIN32
    return snprintf(finalpath, PATH_MAX + 1, "%s/%s", basedir, filename) > PATH_MAX ? -1 : 0;
#else
    return snprintf(finalpath, PATH_MAX + 1, "%s\\%s", basedir, filename) > PATH_MAX ? -1 : 0;
#endif
}

STATIC int _unsign(const char * source, char dest[PATH_MAX + 1]) {
    const char TEMPLATE[] = ".gz.XXXXXX";
    char source_j[PATH_MAX + 1];
    size_t length;
    int output = 0;

    if (_jailfile(source_j, INCOMING_DIR, source) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "unsign()");
        return -1;
    }

    if (_jailfile(dest, TMP_DIR, source) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "unsign()");
        return -1;
    }

    // Skipping coverage: In the linux case, the difference between TMP_DIR and INCOMING_DIR is exactly 10
    // which causes an error in the _jailfile instead of here
    // LCOV_EXCL_START
    if (length = strlen(dest), length + 10 > PATH_MAX) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TOO_LONG_TEMP_FILE, "unsign()");
        return -1;
    }
    // LCOV_EXCL_STOP

    memcpy(dest + length, TEMPLATE, sizeof(TEMPLATE));
    mode_t old_mask = umask(0022);
#ifndef WIN32
    int fd;

    if (fd = mkstemp(dest), fd >= 0) {
        // Not chmod(dest, ...): between mkstemp() creating dest and a name-based chmod() looking
        // it up again, dest could be unlinked and replaced with a symlink, making chmod() follow
        // it and change an unrelated target's mode. fd is already open on the exact file mkstemp()
        // created, so fchmod() skips that second lookup entirely.
        if (fchmod(fd, 0640) < 0) {
            close(fd);
            unlink(dest);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CHMOD_ERROR, "unsign()", dest);
            output = -1;
        } else {
            close(fd);
        }
    } else {
#else
    if (_mktemp_s(dest, strlen(dest) + 1)) {
#endif
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMPRESSED_FILE_ERROR, "unsign()");
        output = -1;
    }

    if ((output == 0) && w_wpk_unsign(source_j, dest, (const char **)wcom_ca_store) < 0) {
        unlink(dest);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNSIGN_FILE_ERROR, "unsign()", source_j);
        output = -1;
    }
    umask(old_mask);
    unlink(source);
    return output;
}

// _jailfile() always builds its output as TMP_DIR followed by a path separator and a bare filename;
// this recovers that bare filename instead of blindly skipping strlen(TMP_DIR) + 1 bytes, which would
// walk past the string's NUL terminator (and hand a garbage pointer to w_gzopen_nofollow/w_fopen_nofollow)
// for any path that turns out not to actually start with that prefix.
STATIC const char * _tmpBareName(const char * path) {
    const size_t prefixLen = strlen(TMP_DIR) + 1;
#ifndef WIN32
    const char SEP = '/';
#else
    const char SEP = '\\';
#endif

    if (strlen(path) <= prefixLen || strncmp(path, TMP_DIR, strlen(TMP_DIR)) != 0 || path[strlen(TMP_DIR)] != SEP) {
        return NULL;
    }

    return path + prefixLen;
}

STATIC int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]) {
    const char TEMPLATE[] = ".mg.XXXXXX";
    char buffer[4096];
    gzFile fsource;
    FILE *ftarget;

    if (_jailfile(dest, TMP_DIR, package) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "uncompress()");
        return -1;
    }

    {
        size_t length;

        if (length = strlen(dest), length + 10 > PATH_MAX) {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TOO_LONG_TEMP_FILE, "uncompress()");
            return -1;
        }

        memcpy(dest + length, TEMPLATE, sizeof(TEMPLATE));
    }

    // Not gzopen(): a symlink left at source would be followed, disclosing whatever it points to.
    const char * sourceBareName = _tmpBareName(source);

    if (!sourceBareName || (fsource = w_gzopen_nofollow(TMP_DIR, sourceBareName, "rb"), !fsource)) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_OPEN_ERROR, "uncompress()", source);
        return -1;
    }

    // dest still holds the literal template here: unlike _unsign() above, it was never expanded into a
    // unique name, leaving a predictable path a symlink could be pre-planted at before wfopen() opened
    // it. Expand it now and, on POSIX, reuse the descriptor mkstemp() already vetted instead of a second,
    // name-based open that would reintroduce the same race.
#ifndef WIN32
    {
        int fd;

        if (fd = mkstemp(dest), fd < 0) {
            gzclose(fsource);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMPRESSED_FILE_ERROR, "uncompress()");
            return -1;
        }

        // Not chmod(dest, ...): between mkstemp() creating dest and a name-based chmod() looking
        // it up again, dest could be unlinked and replaced with a symlink, making chmod() follow
        // it and change an unrelated target's mode. fd is already open on the exact file mkstemp()
        // created, so fchmod() skips that second lookup entirely.
        if (fchmod(fd, 0640) < 0) {
            unlink(dest);
            close(fd);
            gzclose(fsource);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CHMOD_ERROR, "uncompress()", dest);
            return -1;
        }

        if (ftarget = fdopen(fd, "wb"), !ftarget) {
            unlink(dest);
            close(fd);
            gzclose(fsource);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_OPEN_ERROR, "uncompress()", dest);
            return -1;
        }
    }
#else
    if (_mktemp_s(dest, strlen(dest) + 1)) {
        gzclose(fsource);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMPRESSED_FILE_ERROR, "uncompress()");
        return -1;
    }

    const char * destBareName = _tmpBareName(dest);

    if (!destBareName || (ftarget = w_fopen_nofollow(TMP_DIR, destBareName, "wb"), !ftarget)) {
        gzclose(fsource);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_OPEN_ERROR, "uncompress()", dest);
        return -1;
    }
#endif

    {
        int length;

        while (length = gzread(fsource, buffer, sizeof(buffer)), length > 0) {
            if ((int)fwrite(buffer, 1, length, ftarget) != length) {
                unlink(dest);
                gzclose(fsource);
                fclose(ftarget);
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CANNOT_WRITE, "uncompress()", source);
                return -1;
            }
        }

        gzclose(fsource);
        fclose(ftarget);

        if (length < 0) {
            unlink(dest);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CANNOT_READ, "uncompress()", source);
            return -1;
        }
    }

    unlink(source);
    return 0;
}
