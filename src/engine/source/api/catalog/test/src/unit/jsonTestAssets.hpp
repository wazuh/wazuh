#ifndef _CATALOG_JSON_ASSETS_H
#define _CATALOG_JSON_ASSETS_H

/** @brief malformed schemas */
constexpr auto schema_malformed = R"(
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "wazuh-decoders.json",
  "title": "Malformed Schema",
  "description": "Validate Wazuh decoder specification",
  "invalid_type_not_str": object,
  "additionalProperties": false
}
)";

/** @brief malformed yaml */
constexpr auto yaml_decoder_malformed = R"(
---
# without `:` after name
name malformed
draft: true

metadata:
  description: Syslog header
  references: [ https://datatracker.ietf.org/doc/html/rfc3164, https://datatracker.ietf.org/doc/html/rfc5424 ]

)";

/** @brief Draft isn't int */
constexpr auto yaml_decoder_invalid_schema = R"(
---
name: syslog2
draft: 123456

metadata:
  description: Syslog header
  references: [ https://datatracker.ietf.org/doc/html/rfc3164, https://datatracker.ietf.org/doc/html/rfc5424 ]
  product.name: Syslog
  formats: [ rfc3164, rfc5424 ]
  json_event_name: syslog

define:
  header: <timestamp/SYSLOG> <host.hostname>

check:
  - wazuh.event.format: text

parse:
  logpar:
    # BSD Syslog RFC 3164
    - event.original: "<$header> <process.name>[<process.pid>]: <message>"

    # IETF Syslog RFC 5424
    - event.original: <timestamp/ISO8601> <host.hostname> <process.name> <process.pid> <_> <_/quoted/[/]> <message>

)";

/** @brief Valid decoder json  to test*/
constexpr auto yaml_decoder_valid = R"(
---
name: syslog2
draft: true

metadata:
  description: Syslog header
  references: [ https://datatracker.ietf.org/doc/html/rfc3164, https://datatracker.ietf.org/doc/html/rfc5424 ]
  product.name: Syslog
  formats: [ rfc3164, rfc5424 ]
  json_event_name: syslog

define:
  header: <timestamp/SYSLOG> <host.hostname>

check:
  - wazuh.event.format: text

parse:
  logpar:
    # BSD Syslog RFC 3164
    - event.original: "<$header> <process.name>[<process.pid>]: <message>"

    # IETF Syslog RFC 5424
    - event.original: <timestamp/ISO8601> <host.hostname> <process.name> <process.pid> <_> <_/quoted/[/]> <message>

)";

/** @brief JSON Schema for decoder */
constexpr auto json_schema_decoder = R"(
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "wazuh-decoders.json",
  "title": "Schema for Wazuh decoders specification",
  "description": "Validate Wazuh decoder specification",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "name",
    "check"
  ],
  "if": {
    "not": {
      "required": [
        "parent"
      ]
    }
  },
  "then": {
    "required": [
      "metadata"
    ]
  },
  "properties": {
    "draft": {
      "description": "Excecute decoder with debug information",
      "type": "boolean"
    },
    "name": {
      "description": "Decoder unique name.",
      "type": "string"
    },
    "parents": {
      "description": "[Optional] A list with names of parent decoders.",
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "define": {
      "type": "object",
      "description": "Define variables (var_name: var_value) to be used on stages of this decoder, currently only logpar definitions supported"
    },
    "metadata": {
      "additionalProperties": false,
      "type": "object",
      "description": "Additional information about the decoder.",
      "properties": {
        "description": {
          "type": "string",
          "description": "Overview of decoder functionality and the product."
        },
        "references": {
          "type": "array",
          "description": "A list of references about product, versions supported or other useful information.",
          "items": {
            "type": "string"
          },
          "minItems": 1
        },
        "product.name": {
          "type": "string",
          "description": "Vendor's product name that the decoder will be used for."
        },
        "product.versions": {
          "type": "array",
          "description": "Version supported by decoder, one item for single version, two items for a range of versions where first entry is minimum supported version and second entry maximum.",
          "items": {
            "type": "string"
          },
          "minItems": 1,
          "maxItems": 2
        },
        "formats": {
          "type": "array",
          "description": "A list of log formats supported by decoder.",
          "items": {
            "type": "string"
          },
          "minItems": 1
        },
        "json_event_name": {
          "type": "string",
          "description": "Key name used in json string after decoding to include all not normalized fields."
        }
      }
    },
    "check": {
      "description": "Evaluates if the received log or event matches with the decoder or not. Every children block inside condition are evaluated as conjuctions, i.e.: child_block_1 AND child_block_2 AND ...",
      "type": "array",
      "items": {
        "$ref": "custom_ecs_field.json#"
      },
      "minItems": 1
    },
    "parse": {
      "description": "Extract from log line once condition evaluates successfully. After a capture operation succeeds it goes to enrichment block.",
      "type": "object",
      "properties": {
        "logpar": {
          "type": "array",
          "description": "Uses logpar syntax expressions",
          "items": {
            "$ref": "only_ecs_field.json#"
          }
        }
      },
      "additionalProperties": false
    },
    "normalize": {
      "description": "Try to enrich the event, all operations are tried",
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "match": {
            "type": "array",
            "items": {
              "$ref": "custom_ecs_field.json#"
            },
            "minItems": 1
          },
          "capture": {
            "$ref": "custom_ecs_field.json#"
          },
          "map": {
            "$ref": "only_ecs_field.json#"
          }
        },
        "required": [
          "map"
        ],
        "minProperties": 1
      },
      "minItems": 1
    }
  },
  "definitions": {
    "operation-block": {
      "type": "object",
      "patternProperties": {
        "^match(?:\\|all|\\|any)?$": {
          "description": "Match operation allows to check conditions on fields, depending on specified modifier:\n - (default) all: every condition must apply in order to evaluate successfully, default behaviour if no modifier specified.\n- any: only one condition must apply in order to evaluate successfully.",
          "type": "array",
          "items": {
            "$ref": "custom_ecs_field.json#"
          },
          "minItems": 1
        },
        "^capture$": {
          "allOf": [
            {
              "description": "Capture operation allows to parse a field with a capturing regex, it is also a condition to perform the map operation and when used under condition block."
            },
            {
              "$ref": "custom_ecs_field.json#"
            }
          ]
        },
        "^map$": {
          "allOf": [
            {
              "description": "Mapping operation is used to map fields with values, where allowed values are:\n- `literal`, literal assignation.\n- `$n`, captured group assignation, must have a successfully `capture` operation in the same block. Accepts the same operations as `$field`.\n- `$field`, assign value of `$field`, where it's value can be transformed with operations:\n- `lower`, value of `$field` is transformed to lower case.\n- `upper`, value of `$field` is transformed to upper case.\n- `replace:regex:value`, if regex matches on `$field`, matched string is replaced by `value`.\n- `$var`, assign value of `$var`."
            },
            {
              "$ref": "only_ecs_field.json#"
            }
          ]
        }
      }
    }
  }
}
)";
#endif // _CATALOG_JSON_ASSETS_H
