#ifndef _ENVIRONMENT_TEST_HPP
#define _ENVIRONMENT_TEST_HPP

#include <map>
#include <string>

#include "builder/environment.hpp"
#include <json/json.hpp>

constexpr auto outputPath = "/tmp/file";

std::map<std::string, const char*> decoders =
{
    {
        "decoder1",
        R"({
            "name": "decoder1",
            "check": [
                {"decoder": 1}
            ],
            "normalize": [
                {
                    "map": {
                        "decoded.names": "+s_append/decoder1"
                    }
                }
            ]
        })"
    },
    {
        "decoder1_1",
        R"({
            "name": "decoder1_1",
            "parents": ["decoder1"],
            "check": [
                {"child": 1}
            ],
            "normalize": [
                {
                    "map": {
                        "decoded.names": "+s_append/decoder1_1"
                    }
                }
            ]
        })"
    },
    {
        "decoder1_2",
        R"({
            "name": "decoder1_2",
            "parents": ["decoder1"],
            "check": [
                {"child": 2}
            ],
            "normalize": [
                {
                    "map": {
                        "decoded.names": "+s_append/decoder1_2"
                    }
                }
            ]
        })"
    },
    {
        "decoder2",
        R"({
            "name": "decoder2",
            "check": [
                {"decoder": 2}
            ],
            "normalize": [
                {
                    "map": {
                        "decoded.names": "+s_append/decoder2"
                    }
                }
            ]
        })"
    },
    {
        "decoder3",
        R"({
            "name": "decoder3",
            "check": [
                {"decoder": 3}
            ],
            "normalize": [
                {
                    "map": {
                        "decoded.names": "+s_append/decoder3"
                    }
                }
            ]
        })"
    },
    {
        "decoder23_1",
        R"({
            "name": "decoder23_1",
            "parents": ["decoder2", "decoder3"],
            "check": [
                {"child": 1}
            ],
            "normalize": [
                {
                    "map": {
                        "decoded.names": "+s_append/decoder23_1"
                    }
                }
            ]
        })"
    }
};
std::map<std::string, const char*> rules =
{
    {
        "rule1",
        R"({
            "name": "rule1",
            "check": [
                {"rule": 1}
            ],
            "normalize": [
                {
                    "map": {
                        "alerted.name": "rule1"
                    }
                }
            ]
        })"
    }
    ,
    {
        "rule1_1",
        R"({
            "name": "rule1_1",
            "parents": ["rule1"],
            "check": [
                {"child": 1}
            ],
            "normalize": [
                {
                    "map": {
                        "alerted.name": "rule1_1"
                    }
                }
            ]
        })"
    },
    {
        "rule2",
        R"({
            "name": "rule2",
            "check": [
                {"rule": 2}
            ],
            "normalize": [
                {
                    "map": {
                        "alerted.name": "rule2"
                    }
                }
            ]
        })"
    }
};
std::map<std::string, const char*> filters =
{
    {
        "filter1",
        R"({
            "name": "filter1",
            "after": [
                "decoder1"
            ],
            "check": [
                {"filter": 1}
            ]
        })"
    }
};
std::map<std::string, const char*> outputs =
{
    {
        "output1",
        R"({
            "name": "output1",
            "check": [
                {"output": 1}
            ],
            "outputs": [
                {
                    "file": {
                        "path": "/tmp/file"
                    }
                }
            ]
        })"
    }
};
std::map<std::string, const char*> environments =
{
    {"oneDecEnv",
R"({
"decoders": [
  "decoder1"
]
})"},
    {"oneRuleEnv",
R"({
"rules": [
  "rule1"
]
})"},
    {"oneFilEnv",
R"({
"filters": [
  "filter1"
]
})"},
    {"oneOutEnv",
R"({
"outputs": [
  "output1"
]
})"},
    {"orphanAssetEnv",
R"({
    "decoders": [
        "decoder1_1"
    ],
    "rules": [
        "rule1"
    ],
    "filters": [
        "filter1"
    ],
    "outputs": [
        "output1"
    ]
})"},
    {"orphanFilterEnv",
R"({
    "rules": [
        "rule1"
    ],
    "filters": [
        "filter1"
    ],
    "outputs": [
        "output1"
    ]
})"},
    {"completeEnv",
R"({
    "decoders": [
        "decoder1",
        "decoder1_1",
        "decoder1_2",
        "decoder2",
        "decoder3",
        "decoder23_1"
    ],
    "rules": [
        "rule1",
        "rule1_1",
        "rule2"
    ],
    "filters": [
        "filter1"
    ],
    "outputs": [
        "output1"
    ]
})"}
};

struct FakeCatalog
{
    json::Json getAsset(const std::string& type, const std::string& name) const
    {
        if (type == "decoder")
        {
            return json::Json {decoders[name]};
        }
        else if (type == "rule")
        {
            return json::Json {rules[name]};
        }
        else if (type == "filter")
        {
            return json::Json {filters[name]};
        }
        else if (type == "output")
        {
            return json::Json {outputs[name]};
        }
        else if (type == "environment")
        {
            return json::Json {environments[name]};
        }
        else
        {
            throw std::runtime_error("Unknown asset type: " + type);
        }
    }
};

#endif // _ENVIRONMENT_TEST_HPP
