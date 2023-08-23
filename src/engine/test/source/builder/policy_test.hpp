#ifndef _ENVIRONMENT_TEST_HPP
#define _ENVIRONMENT_TEST_HPP

#include <map>
#include <string>

#include <json/json.hpp>
#include <store/istore.hpp>
#include <error.hpp>

#include "builder/policy.hpp"


constexpr auto outputPath = "/tmp/file";

std::map<std::string, const char*> decoders =
{
    {
        "decoder/decoder1/version",
        R"({
            "name": "decoder/decoder1/version",
            "check": [
                {"decoder": 1}
            ],
            "normalize": [
                {
                    "map": [
                        {"decoded.names": "+array_append/decoder1"}
                    ]
                }
            ]
        })"
    },
    {
        "decoder/decoder1_1/version",
        R"({
            "name": "decoder/decoder1_1/version",
            "parents": ["decoder/decoder1/version"],
            "check": [
                {"child": 1}
            ],
            "normalize": [
                {
                    "map": [
                        {"decoded.names": "+array_append/decoder1_1"}
                    ]
                }
            ]
        })"
    },
    {
        "decoder/decoder1_2/version",
        R"({
            "name": "decoder/decoder1_2/version",
            "parents": ["decoder/decoder1/version"],
            "check": [
                {"child": 2}
            ],
            "normalize": [
                {
                    "map": [
                        {"decoded.names": "+array_append/decoder1_2"}
                    ]
                }
            ]
        })"
    },
    {
        "decoder/decoder2/version",
        R"({
            "name": "decoder/decoder2/version",
            "check": [
                {"decoder": 2}
            ],
            "normalize": [
                {
                    "map": [
                        {"decoded.names": "+array_append/decoder2"}
                    ]
                }
            ]
        })"
    },
    {
        "decoder/decoder3/version",
        R"({
            "name": "decoder/decoder3/version",
            "check": [
                {"decoder": 3}
            ],
            "normalize": [
                {
                    "map": [
                        {"decoded.names": "+array_append/decoder3"}
                    ]
                }
            ]
        })"
    },
    {
        "decoder/decoder23_1/version",
        R"({
            "name": "decoder/decoder23_1/version",
            "parents": ["decoder/decoder2/version", "decoder/decoder3/version"],
            "check": [
                {"child": 1}
            ],
            "normalize": [
                {
                    "map": [
                        {"decoded.names": "+array_append/decoder23_1"}
                    ]
                }
            ]
        })"
    }
};
std::map<std::string, const char*> rules =
{
    {
        "rule/rule1/version",
        R"({
            "name": "rule/rule1/version",
            "check": [
                {"rule": 1}
            ],
            "normalize": [
                {
                    "map": [
                        {"alerted.name": "rule/rule1/version"}
                    ]
                }
            ]
        })"
    }
    ,
    {
        "rule/rule1_1/version",
        R"({
            "name": "rule/rule1_1/version",
            "parents": ["rule/rule1/version"],
            "check": [
                {"child": 1}
            ],
            "normalize": [
                {
                    "map": [
                        {"alerted/name": "rule/rule1_1/version"}
                    ]
                }
            ]
        })"
    },
    {
        "rule/rule2/version",
        R"({
            "name": "rule/rule2/version",
            "check": [
                {"rule": 2}
            ],
            "normalize": [
                {
                    "map": [
                        {"alerted.name": "rule/rule2/version"}
                    ]
                }
            ]
        })"
    }
};
std::map<std::string, const char*> filters =
{
    {
        "filter/filter1/version",
        R"({
            "name": "filter/filter1/version",
            "after": [
                "decoder/decoder1/version"
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
        "output/output1/version",
        R"({
            "name": "output/output1/version",
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
std::map<std::string, const char*> policys =
{
    {"oneDecEnv",
R"({
"name": "policy/oneDecEnv/version",
"decoders": [
  "decoder/decoder1/version"
]
})"},
    {"oneRuleEnv",
R"({
"name": "policy/oneRuleEnv/version",
"rules": [
  "rule/rule1/version"
]
})"},
    {"oneFilEnv",
R"({
"name": "policy/oneFilEnv/version",
"filters": [
  "filter/filter1/version"
]
})"},
    {"oneOutEnv",
R"({
"name": "policy/oneOutEnv/version",
"outputs": [
  "output/output1/version"
]
})"},
    {"orphanAssetEnv",
R"({
    "name": "policy/orphanAssetEnv/version",
    "decoders": [
        "decoder/decoder1_1/version"
    ],
    "rules": [
        "rule/rule1/version"
    ],
    "filters": [
        "filter/filter1/version"
    ],
    "outputs": [
        "output/output1/version"
    ]
})"},
    {"orphanFilterEnv",
R"({
    "name": "policy/orphanFilterEnv/version",
    "rules": [
        "rule/rule1/version"
    ],
    "filters": [
        "filter/filter1/version"
    ],
    "outputs": [
        "output/output1/version"
    ]
})"},
    {"completeEnv",
R"({
    "name": "policy/completeEnv/version",
    "decoders": [
        "decoder/decoder1/version",
        "decoder/decoder1_1/version",
        "decoder/decoder1_2/version",
        "decoder/decoder2/version",
        "decoder/decoder3/version",
        "decoder/decoder23_1/version"
    ],
    "rules": [
        "rule/rule1/version",
        "rule/rule1_1/version",
        "rule/rule2/version"
    ],
    "filters": [
        "filter/filter1/version"
    ],
    "outputs": [
        "output/output1/version"
    ]
})"}
};

#endif // _ENVIRONMENT_TEST_HPP
