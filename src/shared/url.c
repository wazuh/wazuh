/*
 * URL download support library
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include <os_net/os_net.h>
struct MemoryStruct {
  char *memory;
  size_t size;
};

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
            mwarn("CURL ERROR %s",errbuf);
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
    snprintf(srequest, zrequest, "%s %s|%s|%s|%s|", COMMAND, _url, parsed_dest, parsed_header ? parsed_header : "", parsed_header ? parsed_header : "");
    free(parsed_dest);
    free(parsed_header);
    free(parsed_data);

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

    remove(compressed_file);
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

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

char * wurl_http_get(const char * url) {
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE];

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    if (curl){
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Enable SSL check if url is HTTPS
        if(!strncmp(url,"https",5)){
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
        }

        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER,errbuf);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
        res = curl_easy_perform(curl);

        if(res){
            mwarn("CURL ERROR %s",errbuf);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            return NULL;
        }
        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}
