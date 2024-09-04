/*
 * URL download support library
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_crypto/sha256/sha256_op.h"
#include <os_net/os_net.h>

#ifdef WAZUH_UNIT_TESTING
    #ifdef WIN32
        #include "unit_tests/wrappers/windows/url_wrappers.h"
    #else
        #include "unit_tests/wrappers/wazuh/shared/url_wrappers.h"
    #endif
#endif

struct MemoryStruct {
  char *memory;
  size_t size;
  size_t max_response_size;
  bool max_size_error;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  if ((mem->size + realsize) > mem->max_response_size) {
    mwarn("Response buffer size limit reached.");
    mem->max_size_error = true;
    return 0;
  }

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (ptr == NULL) {
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

#ifndef WIN32
/*
 * These values ​​were taken from how libcurl looks for the paths at compilation time,
 * here it is modified to be able to support the precompiled deps.
 *
 * https://github.com/curl/curl/blob/5930cb1c465ef5f0de6f1b91a843bb6f0bed1f23/acinclude.m4#L2182
 */
const char* certs_list[] = {
    "/etc/ssl/certs/ca-certificates.crt",       // Debian systems
    "/etc/pki/tls/certs/ca-bundle.crt",         // Redhat and Mandriva
    "/usr/share/ssl/certs/ca-bundle.crt",       // RedHat
    "/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD
    "/etc/ssl/cert.pem",                        // OpenBSD, FreeBSD, MacOS
    NULL
};

char const * find_cert_list() {
    char const * ret_val = NULL;

    for (size_t i = 0; NULL != certs_list[i]; ++i) {
        if (-1 != FileSize(certs_list[i])) {
            ret_val = certs_list[i];
            break;
        }
    }

    return ret_val;
}

int wurl_get(const char * url, const char * dest, const char * header, const char *data, const long timeout) {
    CURL *curl;
    FILE *fp;
    CURLcode res;
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT, NULL);
    curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE];
    int old_mask;

    if (curl) {
        char const *cert = find_cert_list();

        old_mask = umask(0006);
        fp = wfopen(dest, "wb");
        umask(old_mask);
        if (!fp) {
            mdebug1(FOPEN_ERROR, dest, errno, strerror(errno));
            curl_easy_cleanup(curl);
            return OS_FILERR;
        }

        res = curl_easy_setopt(curl, CURLOPT_URL, url);
        res += curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        res += curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        if (header) {
            struct curl_slist *c_header = curl_slist_append(NULL, header);
            res += curl_easy_setopt(curl, CURLOPT_HTTPHEADER, c_header);
        }

        if (data) {
            res += curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        }

        if (timeout) {
            res += curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        }

        // Enable SSL check if url is HTTPS
        if (!strncmp(url, "https", 5)) {
            if (NULL != cert) {
                res += curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
            }
        }

        res += curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        res += curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

        if (res != 0) {
            mdebug1("Parameter setup error at CURL");
            curl_easy_cleanup(curl);
            fclose(fp);
            unlink(dest);
            return OS_CONNERR;
        }

        res = curl_easy_perform(curl);

        switch(res) {
        case CURLE_OK:
            break;
        case CURLE_OPERATION_TIMEDOUT:
            mdebug1("CURL ERROR: %s", errbuf);
            curl_easy_cleanup(curl);
            fclose(fp);
            unlink(dest);
            return OS_TIMEOUT;
        default:
            mdebug1("CURL ERROR: %s",errbuf);
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

int w_download_status(int status,const char *url,const char *dest) {

    switch(status) {
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
int wurl_request(const char * url, const char * dest, const char *header, const char *data, const long timeout) {
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
               (parsed_data ? strlen(parsed_data) : 0) + sizeof(long) + 7;
    os_calloc(1, zrequest, srequest);
    snprintf(srequest, zrequest, "%s %s|%s|%s|%s|%ld|", COMMAND, _url, parsed_dest, parsed_header ? parsed_header : "", parsed_data ? parsed_data : "", timeout ? timeout : 0);
    os_free(parsed_dest);
    os_free(parsed_header);
    os_free(parsed_data);

    // Connect to downlod module

    if (sock = OS_ConnectUnixDomain(WM_DOWNLOAD_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mwarn("Couldn't connect to download module socket '%s'", WM_DOWNLOAD_SOCK);
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
            retval = OS_CONNERR;
        } else if (!strcmp(response, "err writing file")) {
            retval = OS_FILERR;
        } else if (!strcmp(response, "err timeout")) {
            retval = OS_TIMEOUT;
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
int wurl_request_gz(const char * url, const char * dest, const char * header, const char * data, const long timeout, char *sha256) {
    char compressed_file[OS_SIZE_6144 + 1];
    int retval = OS_INVALID;

    snprintf(compressed_file, OS_SIZE_6144, "tmp/req-%u", os_random());

    if (wurl_request(url, compressed_file, header, data, timeout)) {
        return retval;

    } else {
        os_sha256 filehash = {0};
        if (sha256 && !OS_SHA256_File(compressed_file, filehash, 'r') && strcmp(sha256, filehash)) {
            merror("Invalid file integrity for '%s'", compressed_file);

        } else if (w_uncompress_gzfile(compressed_file, dest)) {
            merror("Could not uncompress the file downloaded from '%s'", url);

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
    int sock = OS_ConnectUnixDomain(WM_DOWNLOAD_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        return -1;
    } else {
        close(sock);
        return 0;
    }
}

char * wurl_http_get(const char * url, size_t max_size, const long timeout) {
    CURL *curl;
    CURLcode res;
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT, NULL);
    curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE];

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */
    chunk.max_response_size = max_size;
    chunk.max_size_error = false;

    if (curl) {
        char const *cert = find_cert_list();

        res = curl_easy_setopt(curl, CURLOPT_URL, url);
        res += curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        res += curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Enable SSL check if url is HTTPS
        if (!strncmp(url, "https", 5)) {
            if (NULL != cert) {
                res += curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
            }
        }

        res += curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        res += curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

        if (timeout) {
            res += curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        }

        if (res != 0) {
            mdebug1("Parameter setup error at CURL");
            curl_easy_cleanup(curl);
            free(chunk.memory);
            return NULL;
        }

        res = curl_easy_perform(curl);

        if (res) {
            mdebug1("CURL ERROR %s",errbuf);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            return NULL;
        }
        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

#endif
#ifndef CLIENT

// Request a download of a bzip2 file and uncompress it.
int wurl_request_bz2(const char * url, const char * dest, const char * header, const char * data, const long timeout, char *sha256) {
    char compressed_file[OS_SIZE_6144 + 1];
    int retval = OS_INVALID;

    snprintf(compressed_file, OS_SIZE_6144, "tmp/req-%u", os_random());

    if (wurl_request(url, compressed_file, header, data, timeout)) {
        return retval;

    } else {
        os_sha256 filehash = {0};
        if (sha256 && !OS_SHA256_File(compressed_file, filehash, 'r') && strcmp(sha256, filehash)) {
            merror("Invalid file integrity for '%s'", compressed_file);

        } else if (bzip2_uncompress(compressed_file, dest)) {
            merror("Could not uncompress the file downloaded from '%s'", url);

        } else {
            retval = 0;
        }
    }

    if (remove(compressed_file) < 0) {
        mdebug1("Could not remove '%s'. Error: %d.", compressed_file, errno);
    }

    return retval;
}

// Check the compression type of the file and try to download and uncompress it.
int wurl_request_uncompress_bz2_gz(const char * url, const char * dest, const char * header, const char * data, const long timeout, char *sha256) {
    int res_url_request;
    int compress = 0;

    if (wstr_end((char *)url, ".gz")) {
        compress = 1;
        res_url_request = wurl_request_gz(url, dest, header, data, timeout, sha256);
    } else if (wstr_end((char *)url, ".bz2")) {
        compress = 1;
        res_url_request = wurl_request_bz2(url, dest, header, data, timeout, sha256);
    } else {
        res_url_request = wurl_request(url, dest, header, data, timeout);
    }

    if (compress == 1 && !res_url_request) {
        mdebug1("File from URL '%s' was successfully uncompressed into '%s'", url, dest);
    }

    return res_url_request;
}
#endif

curl_response* wurl_http_request(char *method, char **headers, const char* url, const char *payload, size_t max_size, const long timeout, const char *userpass, bool ssl_verify) {
    curl_response *response;
    struct curl_slist* headers_list = NULL;
    struct curl_slist* headers_tmp = NULL;
    CURLcode res;
    struct MemoryStruct req;
    struct MemoryStruct req_header;

    if (!url) {
        mdebug1("url not defined");
        return NULL;
    }

    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT, NULL);
    CURL* curl = curl_easy_init();

    if (!curl) {
        mdebug1("curl initialization failure");
        return NULL;
    }

    res = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

#ifndef WIN32
    char const *cert = find_cert_list();

    // Enable SSL check if url is HTTPS
    if (!strncmp(url, "https", 5)) {
        if (NULL != cert) {
            res += curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
        }
    }
#endif

    // Ignore SSL verification
    if (!ssl_verify) {
        res += curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        res += curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    headers_list = curl_slist_append(headers_list, "User-Agent: curl/7.58.0");

    if (headers_list == NULL) {
        curl_easy_cleanup(curl);
        mdebug1("curl append header failure");
        return NULL;
    }

    // Append custom headers
    char** ptr = headers;
    for (char* header = *ptr; header; header=*++ptr) {
        headers_tmp = curl_slist_append(headers_list, header);

        if (headers_tmp == NULL) {
            curl_slist_free_all(headers_list);
            curl_easy_cleanup(curl);
            mdebug1("curl append custom header failure");
            return NULL;
        }

        headers_list = headers_tmp;
    }

    req.memory = malloc(1);  /* will be grown as needed by the realloc above */
    req.size = 0;    /* no data at this point */
    req.max_response_size = max_size;
    req.max_size_error = false;

    req_header.memory = malloc(1);  /* will be grown as needed by the realloc above */
    req_header.size = 0;    /* no data at this point */
    req_header.max_response_size = max_size;
    req_header.max_size_error = false;

    res += curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    res += curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&req);
    res += curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);
    res += curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
    res += curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&req_header);
    res += curl_easy_setopt(curl, CURLOPT_URL, (void *)url);

    if (userpass) {
        res += curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
    }

    if (payload) {
        res += curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void *)payload);
    }

    if (timeout) {
        res += curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    }

    if (res != CURLE_OK) {
        mdebug1("Parameter setup error at CURL");
        curl_slist_free_all(headers_list);
        curl_easy_cleanup(curl);
        os_free(req.memory);
        os_free(req_header.memory);
        return NULL;
    }

    res = curl_easy_perform(curl);

    if (res != CURLE_OK && !(req.max_size_error || req_header.max_size_error)) {
        mdebug1("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        curl_slist_free_all(headers_list);
        curl_easy_cleanup(curl);
        os_free(req.memory);
        os_free(req_header.memory);
        return NULL;
    }

    os_calloc(1, sizeof(curl_response), response);
    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response->status_code);
    response->header = req_header.memory;
    response->body = req.memory;

    if (req.max_size_error || req_header.max_size_error) {
        response->max_size_reached = true;
    }

    curl_slist_free_all(headers_list);
    curl_easy_cleanup(curl);

    return response;
}

void wurl_free_response(curl_response* response) {
    os_free(response->header);
    os_free(response->body);
    os_free(response);
}
