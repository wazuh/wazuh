#ifndef _SCHEMA_VALIDATOR_C_H
#define _SCHEMA_VALIDATOR_C_H

// Define EXPORTED for any platform
#ifndef EXPORTED
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
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Initialize the schema validator factory with embedded schema resources
 *
 * @return true if initialization was successful, false otherwise
 */
EXPORTED bool schema_validator_initialize(void);

/**
 * @brief Check if the validator factory is initialized
 *
 * @return true if initialized, false otherwise
 */
EXPORTED bool schema_validator_is_initialized(void);

/**
 * @brief Validate a JSON message against a schema for a specific index
 *
 * @param indexPattern Index pattern (e.g., "wazuh-states-fim-file")
 * @param message JSON message as string
 * @param errorMessage Output parameter for error message (caller must free)
 * @return true if message is valid, false if invalid
 */
EXPORTED bool schema_validator_validate(const char* indexPattern,
                                          const char* message,
                                          char** errorMessage);

#ifdef __cplusplus
}
#endif

#endif // _SCHEMA_VALIDATOR_C_H
