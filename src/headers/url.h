#ifndef URL_GET_H_
#define URL_GET_H_

#include <external/curl/include/curl/curl.h>

#define WURL_WRITE_FILE_ERROR "Failed opening file '%s'"
#define WURL_DOWNLOAD_FILE_ERROR "Failed to download file from url: %s"

int wurl_get(const char * url, const char * dest);
int w_download_status(int status,const char *url,const char *dest);
// Request download
int wurl_request(const char * url, const char * dest);

#endif /* CUSTOM_OUTPUT_SEARCH_H_ */
