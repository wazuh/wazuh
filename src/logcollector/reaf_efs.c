#ifdef Darwin

#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h> // Owner of mounted filesystem

#include "logcollector.h"

#define JSON_INDENTIFIER_KEY "origin-module"
#define JSON_INDENTIFIER_VALUE "efs"

typedef void (*w_esf_event_handler_t)(const es_message_t *); ///< Event handler function type

typedef struct
{
    es_event_type_t type;          ///< Event type
    w_esf_event_handler_t handler; ///< Event handler
} event_entry_t;                   ///< Event entry

// Global variables to store the handler events map
event_entry_t *g_handler_event_map = NULL; ///< Handler events map
size_t g_handler_event_map_size = 0;       ///< Size of the handler events map

logtarget * g_target = NULL; ///< Target to send the messages

/**
 * @brief Register an event handler for a specific event
 *
 * @param event Event type
 * @param handler Event handler
 * @return void
 * @warning Caller must ensure that the event is not already registered
 */
void register_event_handler(es_event_type_t event, w_esf_event_handler_t handler)
{
    event_entry_t *new_map = realloc(g_handler_event_map, (g_handler_event_map_size + 1) * sizeof(event_entry_t));
    if (new_map == NULL)
    {
        perror("Failed to allocate memory for event map");
        return;
    }
    g_handler_event_map = new_map;
    g_handler_event_map[g_handler_event_map_size].type = event;
    g_handler_event_map[g_handler_event_map_size].handler = handler;
    g_handler_event_map_size++;
}

char *statfs_flags_to_str(uint32_t flags)
{
    char flags_str[4096] = {0};
    if (flags & MNT_RDONLY)
    {
        strcat(flags_str, "Read-only,");
    }
    if (flags & MNT_SYNCHRONOUS)
    {
        strcat(flags_str, "Synchronous,");
    }
    if (flags & MNT_NOEXEC)
    {
        strcat(flags_str, "noexec,");
    }
    if (flags & MNT_NOSUID)
    {
        strcat(flags_str, "nosetuid,");
    }
    if (flags & MNT_NODEV)
    {
        strcat(flags_str, "nodev,");
    }
    if (flags & MNT_UNION)
    {
        strcat(flags_str, "Union,");
    }
    if (flags & MNT_ASYNC)
    {
        strcat(flags_str, "Asynchronous,");
    }
    if (flags & MNT_EXPORTED)
    {
        strcat(flags_str, "Exported,");
    }
    if (flags & MNT_QUOTA)
    {
        strcat(flags_str, "Quota,");
    }
    if (flags & MNT_QUARANTINE)
    {
        strcat(flags_str, "Quarantine,");
    }
    if (flags & MNT_DOVOLFS)
    {
        strcat(flags_str, "volfs,");
    }
    if (flags & MNT_LOCAL)
    {
        strcat(flags_str, "Local,");
    }
    if (flags & MNT_ROOTFS)
    {
        strcat(flags_str, "rootfs,");
    }
    if (flags & MNT_IGNORE_OWNERSHIP)
    {
        strcat(flags_str, "noowners,");
    }

    if (flags & MNT_DONTBROWSE)
    {
        strcat(flags_str, "nobrowse,");
    }
    if (flags & MNT_AUTOMOUNTED)
    {
        strcat(flags_str, "Automounted,");
    }
    if (flags & MNT_JOURNALED)
    {
        strcat(flags_str, "Journaled,");
    }
    if (flags & MNT_REMOVABLE)
    {
        strcat(flags_str, "Removable,");
    }

    // Remove the last comma
    if (strlen(flags_str) > 0)
    {
        flags_str[strlen(flags_str) - 1] = '\0';
    }

    return strdup(flags_str);
}

cJSON * json_base_event(const char * event_type) {
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, JSON_INDENTIFIER_KEY, JSON_INDENTIFIER_VALUE);
    cJSON_AddStringToObject(json, "event", event_type);
    return json;
}

void send_message_to_queue(cJSON *json) {
    char *message = cJSON_PrintUnformatted(json);
    w_msg_hash_queues_push(message, "MacOS ESF", strlen(message) + 1, g_target, LOCALFILE_MQ);
    mdebug1("EFS Event %s", message);
    cJSON_Delete(json);
    free(message);
}

/************************************************
 * 			Handler of specific events
 ***********************************************/

// event: ES_EVENT_TYPE_NOTIFY_EXEC
void handle_exec(const es_message_t *msg)
{

    cJSON *json = json_base_event("exec");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Parent process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Parent process PID
    cJSON_AddStringToObject(json, "image", msg->event.exec.target->executable->path.data); // New image path

    // Send the message to the queue
    send_message_to_queue(json);

    // printf("%s (pid: %d) | EXEC: New image: %s\n",
    //          msg->process->executable->path.data,            // Parent process path (Who executed the new image)
    //          audit_token_to_pid(msg->process->audit_token),  // Parent process PID (Who executed the new image)
    //          msg->event.exec.target->executable->path.data); // New image path (The new image that was executed)    
}

// event: ES_EVENT_TYPE_NOTIFY_FORK
void handle_fork(const es_message_t *msg)
{
    cJSON *json = json_base_event("fork");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Parent process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Parent process PID
    cJSON_AddNumberToObject(json, "child_pid", audit_token_to_pid(msg->event.fork.child->audit_token)); // forked child PID

    // Send the message to the queue
    send_message_to_queue(json);

    // printf("%s (pid: %d) | FORK: Child pid: %d\n",
    //        msg->process->executable->path.data,                     // Parent process path
    //        audit_token_to_pid(msg->process->audit_token),           // Parent process PID
    //        audit_token_to_pid(msg->event.fork.child->audit_token)); // forked child PID
}

// event: ES_EVENT_TYPE_NOTIFY_EXIT
void handle_exit(const es_message_t *msg)
{
    cJSON *json = json_base_event("exit");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddNumberToObject(json, "status", msg->event.exit.stat); // Exit status

    // Send the message to the queue
    send_message_to_queue(json);


    // printf("%s (pid: %d) | EXIT: status: %d\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        msg->event.exit.stat);                         // Exit status
}

// event: ES_EVENT_TYPE_NOTIFY_CLOSE
void handler_close(const es_message_t *msg)
{
    char *path = NULL;
    if (msg->event.close.target->path.length > 0)
    {
        path = malloc(msg->event.close.target->path.length + 1);
        if (path == NULL)
        {
            perror("Failed to allocate memory for path");
            return;
        }
        memcpy(path, msg->event.close.target->path.data, msg->event.close.target->path.length);
        path[msg->event.close.target->path.length] = '\0';
    }
    else
    {
        path = strdup("Unknown");
    }
    const char *modify = msg->event.close.modified ? "MODIFIED" : "NOT MODIFIED";

    cJSON *json = json_base_event("close");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "file", path); // Path of the file that was closed
    cJSON_AddStringToObject(json, "modify", modify); // File was modified or not

    // Send the message to the queue
    send_message_to_queue(json);

    // printf("%s (pid: %d) | CLOSE: File descriptor: %s, modify: %s\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        path,                                          //  Path of the file that was closed
    //        modify);                                       // File was modified or not

    free(path);
}

// Event: ES_EVENT_TYPE_NOTIFY_CREATE
void handler_create(const es_message_t *msg)
{
    char *path = NULL;
    // save the st_mode
    struct stat fstat = {0};

    if (msg->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE && msg->event.create.destination.existing_file->path.length > 0)
    {
        // If the file doesn’t exist
        path = malloc(msg->event.create.destination.existing_file->path.length + 1);
        memcpy(path, msg->event.create.destination.existing_file->path.data, msg->event.create.destination.existing_file->path.length);
        fstat.st_mode = msg->event.create.destination.existing_file->stat.st_mode;
    }
    else if (msg->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH && msg->event.create.destination.new_path.filename.length > 0)
    {
        // If the file exists (I don't know how get this event)
        path = malloc(msg->event.create.destination.new_path.filename.length + 1);
        memcpy(path, msg->event.create.destination.new_path.filename.data, msg->event.create.destination.new_path.filename.length);
        fstat.st_mode = msg->event.create.destination.new_path.mode;
    }
    else
    {
        path = strdup("Unknown");
    }

    cJSON *json = json_base_event("create");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "file", path); // Path of the file that was created
    cJSON_AddNumberToObject(json, "mode", fstat.st_mode); // File mode

    // Send the message to the queue
    send_message_to_queue(json);


    // printf("%s (pid: %d) | CREATE: File: %s, mode: %07o\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        path,                                          // Path of the file that was created
    //        fstat.st_mode);                                // File mode

    free(path);
}

// Event: ES_EVENT_TYPE_NOTIFY_SETMODE
void handler_setmode(const es_message_t *msg)
{
    char *path = NULL;
    if (msg->event.setmode.target->path.length > 0)
    {
        path = malloc(msg->event.setmode.target->path.length + 1);
        if (path == NULL)
        {
            perror("Failed to allocate memory for path");
            return;
        }
        memcpy(path, msg->event.setmode.target->path.data, msg->event.setmode.target->path.length);
        path[msg->event.setmode.target->path.length] = '\0';
    }
    else
    {
        path = strdup("Unknown");
    }

    cJSON *json = json_base_event("setmode");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "file", path); // Path of the file that was modified
    char *mode = calloc(32, sizeof(char));
    snprintf(mode, 8, "%07o", msg->event.setmode.mode);
    cJSON_AddStringToObject(json, "mode", mode); // New file mode

    // Send the message to the queue
    send_message_to_queue(json);

    // printf("%s (pid: %d) | SETMODE: File: %s, mode: %07o\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        path,                                          // Path of the file that was modified
    //        msg->event.setmode.mode);                      // New file mode

    free(path);
    free(mode);
}

// event: ES_EVENT_TYPE_NOTIFY_UNLINK
void handler_unlink(const es_message_t *msg)
{
    char *path = NULL;
    if (msg->event.unlink.target->path.length > 0)
    {
        path = malloc(msg->event.unlink.target->path.length + 1);
        if (path == NULL)
        {
            perror("Failed to allocate memory for path");
            return;
        }
        memcpy(path, msg->event.unlink.target->path.data, msg->event.unlink.target->path.length);
        path[msg->event.unlink.target->path.length] = '\0';
    }
    else
    {
        path = strdup("Unknown");
    }

    cJSON *json = json_base_event("unlink");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "file", path); // Path of the file that was unlinked

    // Send the message to the queue
    send_message_to_queue(json);

    //printf("%s (pid: %d) | UNLINK: File: %s\n",
    //       msg->process->executable->path.data,           // Process path
    //       audit_token_to_pid(msg->process->audit_token), // Process PID
    //       path);                                         // Path of the file that was unlinked

    free(path);
}

// event: ES_EVENT_TYPE_NOTIFY_MOUNT
void handler_mount(const es_message_t *msg)
{
    // Get the owner of the mounted filesystem
    char *user = NULL;
    uid_t owner = msg->event.mount.statfs->f_owner;
    struct passwd *pwd = getpwuid(owner);
    if (pwd != NULL)
    {
        user = strdup(pwd->pw_name);
    }
    else
    {
        user = strdup("Unknown");
    }

    // The directory providing the mounted file system.
    char *mntfromname = NULL;
    if (msg->event.mount.statfs->f_mntfromname[0] != '\0')
    {
        mntfromname = strdup(msg->event.mount.statfs->f_mntfromname);
    }
    else
    {
        mntfromname = strdup("Unknown");
    }

    // The directory on which the file system is mounted.
    char *mntonname = NULL;
    if (msg->event.mount.statfs->f_mntonname[0] != '\0')
    {
        mntonname = strdup(msg->event.mount.statfs->f_mntonname);
    }
    else
    {
        mntonname = strdup("Unknown");
    }

    // Type of the file system
    char *fstypename = NULL;
    if (msg->event.mount.statfs->f_fstypename[0] != '\0')
    {
        fstypename = strdup(msg->event.mount.statfs->f_fstypename);
    }
    else
    {
        fstypename = strdup("Unknown");
    }

    // Flags
    char *flags = statfs_flags_to_str(msg->event.mount.statfs->f_flags);

    cJSON *json = json_base_event("mount");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "owner", user); // Owner of the mounted filesystem
    cJSON_AddNumberToObject(json, "owner_id", owner); // Owner of the mounted filesystem
    cJSON_AddStringToObject(json, "type", fstypename); // Type of the file system
    cJSON_AddStringToObject(json, "from", mntfromname); // The directory providing the mounted file system
    cJSON_AddStringToObject(json, "on", mntonname); // The directory on which the file system is mounted
    cJSON_AddStringToObject(json, "flags", flags); // Flags

    // Send the message to the queue
    send_message_to_queue(json);


    // printf("%s (pid: %d) | MOUNT: File system mounted by: %s, id: %d, type: %s, from: %s, on: %s Flags: %s\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        user,                                          // Owner of the mounted filesystem
    //        owner,                                         // Owner of the mounted filesystem
    //        fstypename,                                    // Type of the file system
    //        mntfromname,                                   // The directory providing the mounted file system
    //        mntonname,                                     // The directory on which the file system is mounted
    //        flags);                                        // Flags

    free(user);
    free(mntfromname);
    free(mntonname);
    free(fstypename);
    free(flags);
}


// event: ES_EVENT_TYPE_NOTIFY_UNMOUNT
void handler_unmount(const es_message_t *msg)
{
    // The directory providing the mounted file system.
    char *mntfromname = NULL;
    if (msg->event.unmount.statfs->f_mntfromname[0] != '\0')
    {
        mntfromname = strdup(msg->event.unmount.statfs->f_mntfromname);
    }
    else
    {
        mntfromname = strdup("Unknown");
    }

    // The directory on which the file system is mounted.
    char *mntonname = NULL;
    if (msg->event.unmount.statfs->f_mntonname[0] != '\0')
    {
        mntonname = strdup(msg->event.unmount.statfs->f_mntonname);
    }
    else
    {
        mntonname = strdup("Unknown");
    }

    // Type of the file system
    char *fstypename = NULL;
    if (msg->event.unmount.statfs->f_fstypename[0] != '\0')
    {
        fstypename = strdup(msg->event.unmount.statfs->f_fstypename);
    }
    else
    {
        fstypename = strdup("Unknown");
    }

    cJSON *json = json_base_event("unmount");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "type", fstypename); // Type of the file system
    cJSON_AddStringToObject(json, "from", mntfromname); // The directory providing the mounted file system
    cJSON_AddStringToObject(json, "on", mntonname); // The directory on which the file system is mounted

    // Send the message to the queue
    send_message_to_queue(json);

    // printf("%s (pid: %d) | UNMOUNT: File system unmounted, type: %s, from: %s, on: %s\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        fstypename,                                    // Type of the file system
    //        mntfromname,                                   // The directory providing the mounted file system
    //        mntonname);                                    // The directory on which the file system is mounted

    free(mntfromname);
    free(mntonname);
    free(fstypename);
}

// event: ES_EVENT_TYPE_NOTIFY_REMOUNT
void handler_remount(const es_message_t *msg)
{
    // The directory providing the mounted file system.
    char *mntfromname = NULL;
    if (msg->event.remount.statfs->f_mntfromname[0] != '\0')
    {
        mntfromname = strdup(msg->event.remount.statfs->f_mntfromname);
    }
    else
    {
        mntfromname = strdup("Unknown");
    }

    // The directory on which the file system is mounted.
    char *mntonname = NULL;
    if (msg->event.remount.statfs->f_mntonname[0] != '\0')
    {
        mntonname = strdup(msg->event.remount.statfs->f_mntonname);
    }
    else
    {
        mntonname = strdup("Unknown");
    }

    // Type of the file system
    char *fstypename = NULL;
    if (msg->event.remount.statfs->f_fstypename[0] != '\0')
    {
        fstypename = strdup(msg->event.remount.statfs->f_fstypename);
    }
    else
    {
        fstypename = strdup("Unknown");
    }

    cJSON *json = json_base_event("remount");

    cJSON_AddStringToObject(json, "process_image", msg->process->executable->path.data); // Process path
    cJSON_AddNumberToObject(json, "pid", audit_token_to_pid(msg->process->audit_token)); // Process PID
    cJSON_AddStringToObject(json, "type", fstypename); // Type of the file system
    cJSON_AddStringToObject(json, "from", mntfromname); // The directory providing the mounted file system
    cJSON_AddStringToObject(json, "on", mntonname); // The directory on which the file system is mounted

    // Send the message to the queue
    send_message_to_queue(json);

    // printf("%s (pid: %d) | REMOUNT: File system remounted, type: %s, from: %s, on: %s\n",
    //        msg->process->executable->path.data,           // Process path
    //        audit_token_to_pid(msg->process->audit_token), // Process PID
    //        fstypename,                                    // Type of the file system
    //        mntfromname,                                   // The directory providing the mounted file system
    //        mntonname);                                    // The directory on which the file system is mounted

    free(mntfromname);
    free(mntonname);
    free(fstypename);
}

/************************************************
 * 			Handler of all events
 ***********************************************/
void handle_event(__attribute__((unused)) es_client_t *client, const es_message_t *msg)
{
    for (size_t i = 0; i < g_handler_event_map_size; ++i)
    {
        if (g_handler_event_map[i].type == msg->event_type)
        {
            g_handler_event_map[i].handler(msg);
            return;
        }
    }
    printf("Unexpected event type encountered: %d\n", msg->event_type);
}

void * efs_reader_thread(__attribute__((unused)) void * args)
{
    // Set target from args
    g_target = args;

    // Create the client
    es_client_t *client;
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
      handle_event(c, msg);
    });

    // Check if the client was created successfully
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        printf("Failed to create new ES client: %d\n", result);
        return 0;
    }

    // Register the event handlers
    register_event_handler(ES_EVENT_TYPE_NOTIFY_EXEC, handle_exec);
    register_event_handler(ES_EVENT_TYPE_NOTIFY_FORK, handle_fork);
    register_event_handler(ES_EVENT_TYPE_NOTIFY_EXIT, handle_exit);
    // register_event_handler(ES_EVENT_TYPE_NOTIFY_CLOSE, handler_close); To many events, flooding the queue
    register_event_handler(ES_EVENT_TYPE_NOTIFY_CREATE, handler_create);
    // register_event_handler(ES_EVENT_TYPE_NOTIFY_SETMODE, handler_setmode); FIM
    // register_event_handler(ES_EVENT_TYPE_NOTIFY_UNLINK, handler_unlink); FIM
    register_event_handler(ES_EVENT_TYPE_NOTIFY_MOUNT, handler_mount);
    register_event_handler(ES_EVENT_TYPE_NOTIFY_UNMOUNT, handler_unmount);
    // I don't know how to get this event
    // register_event_handler(ES_EVENT_TYPE_NOTIFY_REMOUNT, handler_remount);

    // Subscribe to events
    es_event_type_t *events = malloc(g_handler_event_map_size * sizeof(es_event_type_t));
    for (size_t i = 0; i < g_handler_event_map_size; i++)
    {
        events[i] = g_handler_event_map[i].type;
    }
    if (es_subscribe(client, events, g_handler_event_map_size) != ES_RETURN_SUCCESS)
    {
        printf("Failed to subscribe to events\n");
        es_delete_client(client);
        free(events);
        free(g_handler_event_map);
        return 0;
    }
    free(events);

    // Start the main loop
    // dispatch_main(); --> Not working, but on PoV main thread is used
    while (true) {
        sleep(1);
    }

    // Cleanup
    free(g_handler_event_map);
    return 0;
}




#endif
