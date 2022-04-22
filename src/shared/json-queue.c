/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

// Initializes queue. Equivalent to initialize every field to 0.
void jqueue_init(file_queue * queue) {
    memset(queue, 0, sizeof(file_queue));
}

/*
 * Open queue with the JSON alerts log file.
 * Returns 0 on success or -1 on error.
 */
int jqueue_open(file_queue * queue, int tail) {

    strncpy(queue->file_name, ALERTSJSON_DAILY, MAX_FQUEUE);

    if (queue->fp) {
        fclose(queue->fp);
    }

    if (queue->fp = fopen(queue->file_name, "r"), !queue->fp) {
        merror(FOPEN_ERROR, queue->file_name, errno, strerror(errno));
        return -1;
    }

    /* Position file queue to end of the file */
    if (tail && fseek(queue->fp, 0, SEEK_END) == -1) {
        merror(FOPEN_ERROR, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    /* File inode time */
    if (fstat(fileno(queue->fp), &queue->f_status) < 0) {
        merror(FSTAT_ERROR, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    return 0;
}

/*
 * Return next JSON object from the queue, or NULL if it is not available.
 * If no more data is available and the inode has changed, queue is reloaded.
 */
cJSON * jqueue_next(file_queue * queue) {
    struct stat buf;
    cJSON * alert;

    if (!queue->fp && jqueue_open(queue, 1) < 0) {
        return NULL;
    }

    clearerr(queue->fp);
    alert = jqueue_parse_json(queue);

    if (alert && !(queue->flags & CRALERT_READ_FAILED)) {
        return alert;

    } else {
        queue->flags = 0;

        if (stat(queue->file_name, &buf) < 0) {
            merror(FSTAT_ERROR, queue->file_name, errno, strerror(errno));
            fclose(queue->fp);
            queue->fp = NULL;
            return NULL;
        }

        // If the inode has changed, reopen and retry to open  
        if (!((queue->read_attempts+1) % MAX_INODE_CHANGE)){   // y si cambia MAX_INODE_CHANGE
            if (buf.st_ino != queue->f_status.st_ino) {
                mdebug2("jqueue_next(): Alert file inode changed. Reloading.");

                if (jqueue_open(queue, 0) < 0) {
                    return NULL;
                }

                return jqueue_parse_json(queue);

            } else {
                return NULL;
            }
        }
    }
}

// Close queue
void jqueue_close(file_queue * queue) {
    fclose(queue->fp);
    queue->fp = NULL;
}

/**
 * @brief Read and validate a JSON alert from the file queue
 *
 * @param queue pointer to the file_queue struct
 * @post The flag variable may be set to CRALERT_READ_FAILED if the read operation got no data.
 * @post The read position is restored if failed to get a JSON object.
 * @retval NULL No data read or could not get a valid JSON object. Pointer to the JSON object otherwise.
 */
cJSON * jqueue_parse_json(file_queue * queue) {
    cJSON * object = NULL;
    char buffer[OS_MAXSTR + 1];
    int64_t current_pos;
    const char * jsonErrPtr;
    char * end;

    current_pos = w_ftell(queue->fp);

    if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {

        if (end = strchr(buffer, '\n'), end) {
            *end = '\0';                               // --> TIENE \N

            if ((object = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0), object) && (*jsonErrPtr == '\0')) {   
                queue->read_attempts = 0;                                // --> ES JSON VALIDO
                return object;
            }

            // The read JSON is invalid                       
            if (object){        //check si hace falta este if, que devuelve cuando falla arriba?
                cJSON_Delete(object);
            }

            merror("Invalid JSON alert read from '%s': '%s'", queue->file_name, buffer);
            return NULL;
        }

        while (buffer >= OS_MAXSTR) // SI NO HAY /n Y BUFFER LLENO --> WHILE DE FGETS HASTA /n Y RETURN NULL Y merror o mwarn
        {
            fgets(buffer, OS_MAXSTR + 1, queue->fp);

            if (end = strchr(buffer, '\n'), end){
                merror("Overlong JSON alert read from '%s'", queue->file_name);
                return NULL;
            }
        }
        
        // CAMBIAR MAX_READ_ATTEMPTS POR ALGO COMO MAX_INODE_CHANGE
        queue->read_attempts++;
        mdebug2("Invalid JSON alert read from '%s'.", queue->file_name);


        // LECTURAS INFINITAS PERO CADA 3 CHECKEO INODO  condicion para q de true cada 3 | multiplo de 3   :  if (!((queue->read_attempts+1) % 3) && i>0 )
        // para checkear inodo sino q reintente sin tener en cuenta MAX_READ_ATTEMPTS
        if (current_pos >= 0) {
            if (fseek(queue->fp, current_pos, SEEK_SET) != 0) {
                queue->flags = CRALERT_READ_FAILED;
            }
        }
    } else {
        // Force the queue reload when the read fails
        queue->flags = CRALERT_READ_FAILED;
    }

    return NULL;
}
