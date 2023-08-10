#ifndef _TEST_FAKE_ASSETS_HPP
#define _TEST_FAKE_ASSETS_HPP

namespace test
{
namespace assets
{

auto constexpr INTERNAL_ROUTE_TABLE = R"([
    {
        "name": "allow_all_A1",
        "priority": 50,
        "filter": "filter/allow-all/0",
        "target": "policy/env_A1/0"
    }
])";

auto constexpr DECODER = R"e({
    "name": "decoder/core-hostinfo/0",
    "check": [
        {
        "wazuh.queue": 51
        }
    ],
    "normalize": [
        {
        "map": [
            {
            "wazuh.decoders": "array_append(core-hostinfo)"
            }
        ]
        }
    ]
    })e";

auto constexpr FILTER_ALLOW = R"({
    "name": "filter/allow-all/0"
})";

auto constexpr FILTER_DUMMY = R"({
    "name": "filter/dummy_filter/0",
    "check": [
        {
            "TestSessionID": 1
        }
    ]
})";

auto constexpr INTEGRATION = R"({
    "decoders": [
        "decoder/core-hostinfo/0"
    ],
    "filters": [
        "filter/allow-all/0"
    ],
    "name": "integration/wazuh-core/0"
})";

auto constexpr POLICY_WAZUH = R"({
    "name": "policy/wazuh/0",
    "integrations": [
        "integration/wazuh-core/0"
    ]
})";

auto constexpr POLICY_DUMMY = R"({
    "name": "policy/dummy_policy/0",
    "integrations": [
        "integration/wazuh-core/0"
    ]
})";

auto constexpr WAZUH_ASSET = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "wazuh-asset.json",
    "name": "schema/wazuh-asset/0",
    "title": "Schema for Wazuh assets",
    "type": "object",
    "description": "Schema for Wazuh assets",
    "additionalProperties": false,
    "required": [
        "name",
        "metadata"
    ],
    "anyOf": [
        {
            "anyOf": [
                {
                    "required": [
                        "check"
                    ]
                },
                {
                    "required": [
                        "parse"
                    ]
                },
                {
                    "required": [
                        "normalize"
                    ]
                }
            ],
            "not": {
                "anyOf": [
                    {
                        "required": [
                            "allow"
                        ]
                    },
                    {
                        "required": [
                            "outputs"
                        ]
                    }
                ]
            }
        },
        {
            "required": [
                "outputs"
            ],
            "not": {
                "anyOf": [
                    {
                        "required": [
                            "normalize"
                        ]
                    },
                    {
                        "required": [
                            "parse"
                        ]
                    }
                ]
            }
        },
        {
            "required": [
                "allow",
                "sources"
            ],
            "not": {
                "anyOf": [
                    {
                        "required": [
                            "check"
                        ]
                    },
                    {
                        "required": [
                            "normalize"
                        ]
                    }
                ]
            }
        }
    ],
    "properties": {
        "name": {
            "type": "string",
            "description": "Name of the asset, short and concise name to identify this asset",
            "pattern": "^[^/]+/[^/]+/[^/]+$"
        },
        "metadata": {
            "type": "object",
            "description": "Metadata of this item",
            "additionalProperties": false,
            "required": [
                "module",
                "title",
                "description",
                "compatibility",
                "versions",
                "author",
                "references"
            ],
            "properties": {
                "module": {
                    "type": "string",
                    "description": "The module this item belongs to"
                },
                "title": {
                    "type": "string",
                    "description": "Short and concise description of this item"
                },
                "description": {
                    "type": "string",
                    "description": "Long description of this item, explaining what it does and how it works"
                },
                "compatibility": {
                    "type": "string",
                    "description": "Description of the supported services and versions of the logs processed by this item"
                },
                "versions": {
                    "type": "array",
                    "description": "A list of the service versions supported",
                    "items": {
                        "type": "string"
                    }
                },
                "author": {
                    "type": "object",
                    "description": "Author",
                    "additionalProperties": false,
                    "required": [
                        "name",
                        "date"
                    ],
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name/Organization"
                        },
                        "email": {
                            "type": "string",
                            "description": "Email"
                        },
                        "url": {
                            "type": "string",
                            "description": "URL linking to the author's website"
                        },
                        "date": {
                            "type": "string",
                            "description": "Date of the author"
                        }
                    }
                },
                "references": {
                    "type": "array",
                    "description": "References to external resources"
                }
            }
        },
        "sources": {
            "type": "array",
            "description": "This asset will process events coming only from the specified sources",
            "items": {
                "type": "string"
            }
        },
        "check": {
            "$ref": "#/definitions/_check"
        },
        "allow": {
            "$ref": "#/definitions/_check"
        },
        "normalize": {
            "type": "array",
            "description": "Modify the event. All operations are performed in declaration order and on best effort, this stage is a list composed of blocks, where each block can be a map [map] or a conditional map [check, map].",
            "minItems": 1,
            "items": {
                "$ref": "#/definitions/_normalizeBlock"
            }
        },
        "outputs": {
            "type": "array",
            "description": "Outputs of the asset. All outputs are performed in declaration order and on best effort, this stage is a list composed of specific outputs types.",
            "minItems": 1
        },
        "definitions": {
            "type": "object",
            "description": "Variable definitions, used to define variables that can be reused in other parts of the item",
            "minProperties": 1
        },
        "parse": {
            "$ref": "#/definitions/_parse"
        }
    },
    "definitions": {
        "_check": {
            "oneOf": [
                {
                    "type": "array",
                    "description": "Check list, all conditions must be met in order to further process events with this asset, conditions are expressed as `field`: `condition`, where `field` is the field to check and `condition` can be a value, a reference or a conditional helper function.",
                    "items": {
                        "allOf": [
                            {
                                "$ref": "fields.json#"
                            },
                            {
                                "maxProperties": 1
                            }
                        ]
                    },
                    "minItems": 1
                },
                {
                    "type": "string",
                    "description": "Check conditional expression, the expression must be valuated to true in order to further process events with this asset"
                }
            ]
        },
        "_logpar": {
            "type": "array",
            "description": "Try to parse a field of the event. Terminates once a parser expression matches. If no parser expression matches, this asset will not continue processing the event. Parser expressions are defined using the `field`: `logpar_expression`, where `field` is the field name and `logpar_expression` is the Logpar expression to be evaluated.",
            "minItems": 1,
            "items": {
                "allOf": [
                    {
                        "$ref": "fields.json#"
                    },
                    {
                        "maxProperties": 1
                    }
                ]
            }
        },
        "_parse": {
            "type": "object",
            "description": "Parse the event using the specified parser engine. Suports `logpar` parser.",
            "additionalProperties": false,
            "minProperties": 1,
            "properties": {
                "logpar": {
                    "$ref": "#/definitions/_logpar"
                }
            }
        },
        "_normalizeBlock": {
            "type": "object",
            "description": "Never shown",
            "minItems": 1,
            "additionalProperties": true,
            "properties": {
                "map": {
                    "description": "Modify fields on the event, an array composed of tuples with syntax `- field`: `value`, where `field` is the field to modify and `value` is the new value. If `value` is a function helper, it will be executed and the result will be used as new value if executed correctly. If `value` is a reference it will be used as new value only if the reference exists.",
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "allOf": [
                            {
                                "$ref": "fields.json#"
                            },
                            {
                                "maxProperties": 1
                            }
                        ]
                    }
                },
                "check": {
                    "$ref": "#/definitions/_check"
                },
                "logpar": {
                    "$ref": "#/definitions/_logpar"
                }
            }
        }
    }
})";

auto constexpr WAZUH_POLICY = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "wazuh-policy.json",
    "title": "Schema for Wazuh policies",
    "type": "object",
    "minProperties": 2,
    "required": [
        "name"
    ],
    "additionalProperties": false,
    "properties": {
        "name": {
            "type": "string",
            "description": "Name of the policy, short and concise name to identify this asset",
            "pattern": "^[^/]+/[^/]+/[^/]+$"
        },
        "decoders":{
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string"
            }
        },
        "rules":{
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string"
            }
        },
        "filters":{
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string"
            }
        },
        "outputs":{
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string"
            }
        }
    }
})";

} // namespace assets
} // namespace test
#endif // _TEST_FAKE_ASSETS_HPP
