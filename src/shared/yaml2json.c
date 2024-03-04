/* Copyright (C) 2015, Wazuh Inc.
 * August 4, 2018
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "shared.h"

static cJSON * yaml2json_node(yaml_document_t * document, yaml_node_t * node, int quoted_float_as_string);

int yaml_parse_stdin(yaml_document_t * document) {
    yaml_parser_t parser;
    int error = -1;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, stdin);

    if (yaml_parser_load(&parser, document)) {
        error = 0;
    } else {
        mwarn("Failed to load YAML document at line %u", (unsigned int)parser.problem_mark.line);
    }

    yaml_parser_delete(&parser);

    return error;
}

int yaml_parse_file(const char * path, yaml_document_t * document) {
    yaml_parser_t parser;
    FILE * finput;
    int error = -1;

    if (finput = wfopen(path, "rb"), finput) {
        yaml_parser_initialize(&parser);
        yaml_parser_set_input_file(&parser, finput);

        if (yaml_parser_load(&parser, document)) {
            error = 0;
        } else {
            mwarn("Failed to load YAML document in %s:%u", path, (unsigned int)parser.problem_mark.line);
            yaml_document_delete(document);
        }

        yaml_parser_delete(&parser);
        fclose(finput);
    } else {
        mwarn("Cannot open file '%s': %s (%d)", path, strerror(errno), errno);
    }

    return error;
}

cJSON * yaml2json(yaml_document_t * document, int single_quote_float_as_string) {
    yaml_node_t * node;

    if (node = yaml_document_get_root_node(document), !node) {
        mwarn("No document defined.");
        return NULL;
    }

    return yaml2json_node(document, node, single_quote_float_as_string);
}

cJSON * yaml2json_node(yaml_document_t * document, yaml_node_t * node,int quoted_float_as_string) {
    yaml_node_t * key;
    yaml_node_t * value;
    yaml_node_item_t * item_i;
    yaml_node_pair_t * pair_i;
    double number;
    char * scalar;
    char * end;
    cJSON * object;

    switch (node->type) {
    case YAML_NO_NODE:
        object = cJSON_CreateObject();
        break;

    case YAML_SCALAR_NODE:
        scalar = (char *)node->data.scalar.value;
        number = strtod(scalar, &end);

        if(quoted_float_as_string && (node->data.scalar.style == YAML_SINGLE_QUOTED_SCALAR_STYLE || node->data.scalar.style == YAML_DOUBLE_QUOTED_SCALAR_STYLE)) {
            object = cJSON_CreateString(scalar);
        } else {
            object = (end == scalar || *end) ? cJSON_CreateString(scalar) : cJSON_CreateNumber(number);
        }

        break;

    case YAML_SEQUENCE_NODE:
        object = cJSON_CreateArray();

        for (item_i = node->data.sequence.items.start; item_i < node->data.sequence.items.top; ++item_i) {
            cJSON_AddItemToArray(object, yaml2json_node(document, yaml_document_get_node(document, *item_i),quoted_float_as_string));
        }

        break;

    case YAML_MAPPING_NODE:
        object = cJSON_CreateObject();

        for (pair_i = node->data.mapping.pairs.start; pair_i < node->data.mapping.pairs.top; ++pair_i) {
            key = yaml_document_get_node(document, pair_i->key);
            value = yaml_document_get_node(document, pair_i->value);

            if (key->type != YAML_SCALAR_NODE) {
                mwarn("Mapping key is not scalar (line %u).", (unsigned int)key->start_mark.line);
                continue;
            }

            cJSON_AddItemToObject(object, (char *)key->data.scalar.value, yaml2json_node(document, value,quoted_float_as_string));
        }

        break;

    default:
        mwarn("Unknown node type (line %u).", (unsigned int)node->start_mark.line);
        object = NULL;
    }

    return object;
}
