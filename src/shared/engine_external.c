#include "engine_external.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "../config/config.h"
#include "../config/indexer-config.h"

char* read_engine_cnf(const char* cnf_file, char* err_buf, size_t err_buf_size)
{

    // Return dummy value for now
    merror("read_engine_cnf is a stub, returning dummy value.");
    return strdup("http://localhost:9200");

    // ReadConfig the configuration file into a JSON object
    //int read_status = ReadConfig(CWMODULE, cnf_file, &config_json
}
