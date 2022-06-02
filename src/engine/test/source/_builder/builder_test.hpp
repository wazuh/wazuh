#ifndef _BUILDER_TEST_H
#define _BUILDER_TEST_H

#include <string>
#include <vector>

#include "_builder/json.hpp"

std::unordered_map<std::string, std::string> decoders = {
    {
        "decoder1",
        R"({
        "name": "decoder1",
        "check": [
            {"source": "test"}
        ],
        "normalize": [
            {
                "map": {
                    "decoded.source": "test"
                }
            }
        ]
    })"
    },
    {
        "decoder2",
        R"({
        "name": "decoder2",
        "parents": ["decoder1"],
        "check": [
            {"type": "A"}
        ],
        "normalize": [
            {
                "map": {
                    "typed.letter": "$type"
                }
            }
        ]
    })"
    },
    {
        "decoder3",
        R"({
        "name": "decoder3",
        "parents": ["decoder1"],
        "check": [
            {"type": "B"}
        ],
        "normalize": [
            {
                "map": {
                    "typed.letter": "$type"
                }
            }
        ]
    })"
    },
    {
        "decoder4",
        R"({
        "name": "decoder4",
        "parents": ["decoder2"],
        "check": [
            {"threat.level": 6}
        ],
        "normalize": [
            {
                "map": {
                    "typed.level": "$threat.level"
                }
            },
            {
                "check":[
                    {"threat.name": "threat"}
                ],
                "map": {
                    "type.name": "threat"
                }
            }
        ]
    })"
    },
    {
        "decoder5",
        R"({
        "name": "decoder5",
        "parents": ["decoder4", "decoder3"],
        "check": [
            {"weird.field": "value"}
        ],
        "normalize": [
            {
                "map": {
                    "typed.weird": "$weird.field"
                }
            }
        ]
    })"
    }
};

std::unordered_map<std::string, std::string> filters = {
    {
        "filter1",
        R"({
        "name": "filter1",
        "parents": ["decoder1"],
        "check": [
            {"source": "test"}
        ]
        })"
    },
    {
        "filter2",
        R"({
        "name": "filter2",
        "parents": ["decoder4"],
        "check": [
            {"threat.level": 5}
        ]
        })"
    }
};

std::unordered_map<std::string, std::string> rules = {
    {
        "rule1",
        R"({
        "name": "rule1",
        "check": [
            {"typed.letter": "A"}
        ]
    })"
    },
    {
        "rule2",
        R"({
        "name": "rule2",
        "check": [
             {"typed.letter": "B"}
        ]
    })"
    }
};

const char * enviroment = R"({
    "decoders": ["decoder1", "decoder2", "decoder3", "decoder4", "decoder5"],
    "filters": ["filter1", "filter2"],
    "rules": ["rule1", "rule2"]
})";
struct FakeCatalog
{
    Json getAsset(int assetType, const std::string& name) const
    {
        switch (assetType)
        {
        case 0:
            return Json{decoders[name].c_str()};
        case 1:
            return Json{filters[name].c_str()};
        case 2:
            return Json{rules[name].c_str()};
        case 4:
            return Json{enviroment};
        default:
            throw std::runtime_error{"Unknown asset type"};
        }
    }
};

#endif // _BUILDER_TEST_H
