/*
 * URL download support library
 * Copyright (C) 2015-2020, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include <os_net/os_net.h>

int wurl_get(const char * url, const char * dest, const char * header, const char *data){
    CURL *curl;
    FILE *fp;
    CURLcode res;
    curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE];
    int old_mask;

    if (curl){
        old_mask = umask(0006);
        fp = fopen(dest,"wb");
        umask(old_mask);
        if (!fp) {
            mdebug1(FOPEN_ERROR, dest, errno, strerror(errno));
            curl_easy_cleanup(curl);
            return OS_FILERR;
        }
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        if (header) {
            struct curl_slist *c_header = curl_slist_append(NULL, header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, c_header);
        }

        if (data) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        }

        // Enable SSL check if url is HTTPS
        if(!strncmp(url,"https",5)){
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
        }

        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER,errbuf);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
        res = curl_easy_perform(curl);

        if(res){
            mdebug1("CURL ERROR %s",errbuf);
            curl_easy_cleanup(curl);
            fclose(fp);
            unlink(dest);
            return OS_CONNERR;
        }
        curl_easy_cleanup(curl);
        fclose(fp);
    }

    return 0;
}

int w_download_status(int status,const char *url,const char *dest){

    switch(status){
        case OS_FILERR:
            mwarn(WURL_WRITE_FILE_ERROR,dest);
            break;
        case OS_CONNERR:
            mwarn(WURL_DOWNLOAD_FILE_ERROR, dest, url);
            break;
    }

    return status;
}

// Request download
int wurl_request(const char * url, const char * dest, const char *header, const char *data) {
    const char * COMMAND = "download";
    char response[64];
    char * _url;
    char * srequest;
    size_t zrequest;
    ssize_t zrecv;
    int sock;
    int retval = -1;
    char *parsed_dest;
    char *parsed_header = NULL;
    char *parsed_data = NULL;

    if (!url) {
        return -1;
    }

    // Escape whitespaces

    _url = wstr_replace(url, " ", "%20");

    // Escape delimiter

    parsed_dest = wstr_replace(dest, "|", "\\|");
    if (header) {
        parsed_header = wstr_replace(header, "|", "\\|");
    }
    if (data) {
        parsed_data = wstr_replace(data, "|", "\\|");
    }

    // Build request

    zrequest = strlen(_url) + strlen(parsed_dest) + strlen(COMMAND) +
               (parsed_header ? strlen(parsed_header) : 0) +
               (parsed_data ? strlen(parsed_data) : 0) + 6;
    os_malloc(zrequest, srequest);
    snprintf(srequest, zrequest, "%s %s|%s|%s|%s|", COMMAND, _url, parsed_dest, parsed_header ? parsed_header : "", parsed_data ? parsed_data : "");
    os_free(parsed_dest);
    os_free(parsed_header);
    os_free(parsed_data);

    // Connect to downlod module

    if (sock = OS_ConnectUnixDomain(isChroot() ? WM_DOWNLOAD_SOCK : WM_DOWNLOAD_SOCK_PATH, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mwarn("Couldn't connect to download module socket '%s'", WM_DOWNLOAD_SOCK_PATH);
        goto end;
    }

    // Send request

    if (send(sock, srequest, zrequest - 1, 0) != (ssize_t)(zrequest - 1)) {
        merror("Couldn't send request to download module.");
        goto end;
    }

    // Receive response

    switch (zrecv = recv(sock, response, sizeof(response) - 1, 0), zrecv) {
    case -1:
        merror("Couldn't receive URL response from download module.");
        goto end;

    case 0:
        merror("Couldn't receive URL response from download module (closed unexpectedly).");
        goto end;

    default:
        response[zrecv] = '\0';

        // Parse responses

        if (!strcmp(response, "ok")) {
            retval = 0;
        } else if (!strcmp(response, "err connecting to url")) {
            mdebug1(WURL_DOWNLOAD_FILE_ERROR, dest, _url);
            retval = OS_CONNERR;
        } else if (!strcmp(response, "err writing file")) {
            mdebug1(WURL_WRITE_FILE_ERROR, dest);
            retval = OS_FILERR;
        } else {
            mdebug1("Couldn't download from '%s': %s", _url, response);
        }
    }

end:
    free(_url);
    free(srequest);

    if (sock >= 0) {
        close(sock);
    }

    return retval;
}

// Request a uncompressed download (.gz)
int wurl_request_gz(const char * url, const char * dest, const char * header, const char * data) {
    char compressed_file[OS_SIZE_6144 + 1];
    int retval = OS_INVALID;

    snprintf(compressed_file, OS_SIZE_6144, "tmp/req-%u", os_random());

    if (wurl_request(url, compressed_file, header, data)) {
        return retval;
    } else {
        if (w_uncompress_gzfile(compressed_file, dest)) {
            merror("Could not uncompress the file downloaded from '%s'.", url);
        } else {
            retval = 0;
        }
    }

    if (remove(compressed_file) < 0) {
        mdebug1("Could not remove '%s'. Error: %d.", compressed_file, errno);
    }

    return retval;
}

/* Check download module availability */
int wurl_check_connection() {
    int sock = OS_ConnectUnixDomain(isChroot() ? WM_DOWNLOAD_SOCK : WM_DOWNLOAD_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        return -1;
    } else {
        close(sock);
        return 0;
    }
}

// Callback function to extract the body from the HTTP response
static size_t body_callback(void* contents, size_t size, size_t n_items, void* user_data) {
    // Static/automatic memory allocation variables
    size_t new_size;

    // Dynamic memory allocation variables
    char* new_body; // No need to be freed
    whttp_response_t* response; // No need to be freed. It is the purpose of this callback

    // Calculate new size
    new_size = size * n_items;
    // Cast user data to HTTP response struct
    response = (whttp_response_t*)user_data;

    // Allocate memory to adapt to new body size
    new_body = realloc(response->body, response->body_size + new_size + 1);

    // Return 0 if reallocation failed (needed by libcurl)
    if(!new_body) {
        return 0;
    }

    // Assign new body to the HTTP response struct
    response->body = new_body;

    // Copy the new contents at the end of the previous chunk
    memcpy(&(response->body[response->body_size]), contents, new_size);
    // Update body size
    response->body_size += new_size;
    // Include end of string
    response->body[response->body_size] = 0;

    // Return new size (needed by libcurl)
    return new_size;
}

// Callback function to extract the header from the HTTP response
static size_t header_callback(void* contents, size_t size, size_t n_items, void* user_data) {
    // Static/automatic memory allocation variables
    size_t new_size;

    // Dynamic memory allocation variables
    char* new_header; // No need to be freed
    whttp_response_t* response; // No need to be freed. It is the purpose of this callback

    // Calculate new size
    new_size = size * n_items;
    // Cast user data to HTTP response struct
    response = (whttp_response_t*)user_data;

    // Allocate memory to adapt to new header size
    new_header = realloc(response->header, response->header_size + new_size + 1);

    // Return 0 if reallocation failed (needed by libcurl)
    if(!new_header) {
        return 0;
    }

    // Assign new header to the HTTP response struct
    response->header = new_header;

    // Copy the new content at the end of the previous chunk
    memcpy(&(response->header[response->header_size]), contents, new_size);
    // Update header size
    response->header_size += new_size;
    // Include end of string
    response->header[response->header_size] = 0;

    // Return new size (needed by libcurl)
    return new_size;
}

// Helper function to create a new HTTP response struct
static whttp_response_t* new_whttp_response() {
    whttp_response_t* new_response = malloc(sizeof(whttp_response_t));

    new_response->body = malloc(1);
    new_response->header = malloc(1);
    new_response->status_code = 0;
    new_response->body_size = 0;
    new_response->header_size = 0;

    return new_response;
}

// HTTP request
whttp_response_t* whttp_request(const char* method, const char* url, const char* header, const char* data, long timeout) {
    // Static/automatic memory allocation variables
    CURLcode result;
    char errbuf[CURL_ERROR_SIZE];
    long status_code;

    // Dynamic memory allocation variables
    CURL* curl = NULL;
    whttp_response_t* response = NULL;
    struct curl_slist* libcurl_header = NULL;

    // Check method
    if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0) {
        merror("Invalid method for the HTTP request. Valid ones are GET, POST.");
        return NULL;
    }

    // Check the url parameter
    if (!url) {
        merror("No url was provided for HTTP request.");
        return NULL;
    }

    // Check the timeout parameter
    if (timeout < 0) {
        merror("Invalid negative timeout for HTTP request.");
        return NULL;
    }

    // Initialize response object
    response = new_whttp_response();

    curl = curl_easy_init();

    if (curl) {
        // Set the url for the request
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set timeout
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

        // Error settings
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

        // Check if the HTTP request is POST
        if (strcmp(method, "POST") == 0) {
            // Set POST request
            curl_easy_setopt(curl, CURLOPT_POST, 1L);

            // If there's data to add to the request 
            if (data) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));
            // Otherwise set the content length to 0 in the header as most servers won't accept the request without it
            } else {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);
            }
        }

        // Add body call back and response object
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

        // Add header callback and response object
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)response);

        // Add header if necessary
        if (header) {
            libcurl_header = curl_slist_append(libcurl_header, header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, libcurl_header);
        }

        // Enable SSL check if url is HTTPS
        if (!strncmp(url, "https", 5)) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
        }

        // Perform HTTP request
        result = curl_easy_perform(curl);

        // Get response status code
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        response->status_code = status_code;

        // Check if there's an error
        if (result != CURLE_OK) {
            mdebug1("CURL ERROR %s", errbuf);
        }

        // Clean libcurl objects
        curl_easy_cleanup(curl);
        curl_slist_free_all(libcurl_header);
    }

    return response;
}
