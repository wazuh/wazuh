#ifndef _BUILDER_TEST_DEFINITIONS_HPP
#define _BUILDER_TEST_DEFINITIONS_HPP

namespace builder::test
{

auto constexpr WAZUH_LOGPAR_TYPES_JSON = R"({
    "fields": {
        "wazuh.message": "text"
    }
}
)";

auto constexpr DECODER_PARENT_JSON = R"({
    "name": "decoder/parent-test/0",
    "parents": ["decoder/Input"],
    "check": [{
        "event.code": 2
    }
    ]
})";

auto constexpr DECODER_JSON = R"({
    "name": "decoder/test/0",
    "parents": ["decoder/parent-test/0"]
})";

auto constexpr DECODER_KEY_DEFECTIVE_JSON = R"({
    "id": "decoder/test/0"
})";

auto constexpr DECODER_STAGE_NOT_FOUND_JSON = R"({
    "name": "decoder/test/0",
    "check_not_found": [{
        "event.code": 2
    }
    ]
})";

auto constexpr DECODER_PARENT_WITHOUT_CHECK_JSON = R"({
    "name": "decoder/parent-test/0",
    "parents": ["decoder/Input"]
})";

auto constexpr DECODER_WITH_SIMPLE_PARENT_JSON = R"({
    "name": "decoder/test/0",
    "parents": ["decoder/parent-test/0"]
})";

auto constexpr DECODER_EMPTY_STAGE_PARSE_JSON = R"x({
    "name": "decoder/test/0",
    "parse|event.event": [
    ]
    })x";

auto constexpr DECODER_STAGE_PARSE_FIELD_NOT_FOUND_JSON = R"x({
    "name": "decoder/test/0",
    "parse|event.original": [
        "<event.notExist>"
    ]
    })x";

auto constexpr DECODER_STAGE_PARSE_NOT_FOUND_JSON = R"x({
    "name": "decoder/test/0",
    "parse|event.nonExit": [
        "<event.code>"
    ]
    })x";

auto constexpr DECODER_STAGE_NORMALIZE_WRONG_MAPPING = R"x({
    "name": "decoder/test/0",
    "normalize": [
      {
        "map": [
          {
            "event.code": 2
          }
        ]
      }
    ]
    })x";

auto constexpr DECODER_NOT_STRING_NAME_JSON = R"({
    "name": 2
})";

auto constexpr DECODER_INVALID_FORMAT_NAME_JSON = R"({
    "name": "decoder//"
})";

auto constexpr DECODER_INVALID_FORMAT_PARENT_JSON = R"({
    "name": "decoder/test/0",
    "parents": {}
})";

auto constexpr DECODER_INVALID_VALUE_PARENT_JSON = R"({
    "name": "decoder/test/0",
    "parents": [2]
})";

auto constexpr INTEGRATION_JSON = R"({
    "name": "integration/test/0",
    "decoders": ["decoder/test/0", "decoder/parent-test/0"]
})";

auto constexpr INTEGRATION_KEY_DEFECTIVE_JSON = R"({
    "id": "integration/test/0"
})";

auto constexpr INTEGRATION_INVALID_FORMAT_JSON = R"({
    "name": "integration/test/0",
    "decoders": [2]
})";

auto constexpr INTEGRATION_INVALID_FORMAT_NAME_JSON = R"({
    "name": "integration/test/0",
    "decoders": ["decoder//"]
})";

auto constexpr INTEGRATION_INVALID_ASSET_TYPE_JSON = R"({
    "name": "integration/test/0",
    "decoders": ["decoder-non-exist/test/0"]
})";

auto constexpr POLICY_JSON = R"({
    "name": "policy/test/0",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": "decoder/parent-test/0"
    }
    })";

auto constexpr DEFECTIVE_POLICY_NAME_JSON = R"({
    "n": "policy/test/0",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": "decoder/parent-test/0"
    }
    })";

auto constexpr DEFECTIVE_POLICY_FORMAT_NAME_JSON = R"({
    "name": "",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": "decoder/parent-test/0"
    }
    })";

auto constexpr DEFECTIVE_POLICY_HASH_JSON = R"({
    "name": "policy/test/0",
    "h": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": "decoder/parent-test/0"
    }
    })";

auto constexpr DEFECTIVE_POLICY_EMPTY_HASH_JSON = R"({
    "name": "policy/test/0",
    "hash": "",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": "decoder/parent-test/0"
    }
    })";

auto constexpr DEFECTIVE_PARENT_POLICY_EMPTY_NAME_JSON = R"({
    "name": "policy",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": ""
    }
    })";

auto constexpr DEFECTIVE_PARENT_POLICY_NOT_STRING_NAME_JSON = R"({
    "name": "policy",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": 2
    }
    })";

auto constexpr DEFECTIVE_ASSET_POLICY_NOT_STRING_NAME_JSON = R"({
    "name": "policy",
    "hash": "11464515449720324140",
    "assets": [2,3],
    "default_parents": {
        "system": "decoder/parent-test/0"
    }
    })";

} // namespace builder::test

#endif // _BUILDER_TEST_DEFINITIONS_HPP
