#pragma once

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Turn off the services provided by the shared library.
 */
    EXPORTED void teardown(void);

/**
 * @brief Initialize DBSync.
 *
 * @param host_type Define the dynamic library host type.
 * @param db_type Define the type of database.
 * @param path path of local db.
 * @param sql_statement sql statement to create tables
 *
 * @return return a instance number to be used in the future.
 */
  EXPORTED unsigned long long initialize(
    const HostType host_type, 
    const DatabaseType db_type,
    const char* path, 
    const char* sql_statement);

/**
 * @brief Insert bulk data based on json string.
 *
 * @param handle Define the dynamic library host type.
 * @param json_raw path of local db.
 *
 * @return return the bulk data is success.
 */
  EXPORTED bool insert_bulk(
    const unsigned long long handle,
    const char* json_raw);


#ifdef __cplusplus
    }
#endif