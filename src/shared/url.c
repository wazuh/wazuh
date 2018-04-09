/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

int wurl_get(const char * url, const char * dest){
    CURL *curl;
    FILE *fp;
    CURLcode res;
    curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE];
    
    if (curl){   
        fp = fopen(dest,"wb");
        if(!fp){
          curl_easy_cleanup(curl);
          return OS_FILERR;
        }
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        // Enable SSL check if url is HTTPS
        if(!strncmp(url,"https",5)){
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
        }
        
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER,errbuf);
        res = curl_easy_perform(curl);
        
        if(res){
            merror("CURL ERROR %s",errbuf);
            curl_easy_cleanup(curl);
            return OS_CONNERR;
        }  
        curl_easy_cleanup(curl);
        fclose(fp);
    }   
    return 1;
}

int w_download_status(int status,const char *url,const char *dest){

    switch(status){
        case OS_FILERR:
            merror(WURL_WRITE_FILE_ERROR,dest);
            break;
        case OS_CONNERR:
            merror(WURL_DOWNLOAD_FILE_ERROR,url);
            break;
    } 

    return status;
}

