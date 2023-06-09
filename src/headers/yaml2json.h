/* Copyright (C) 2015, Wazuh Inc.
 * August 4, 2018
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef YAML2JSON_H
#define YAML2JSON_H

#include "../external/libyaml/include/yaml.h"
#include <cJSON.h>

int yaml_parse_stdin(yaml_document_t * document);
int yaml_parse_file(const char * path, yaml_document_t * document);
cJSON * yaml2json(yaml_document_t * document, int quoted_float_as_string );

#endif
