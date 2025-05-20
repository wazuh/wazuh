#ifndef _BUILDER_TEST_DEFINITIONS_HPP
#define _BUILDER_TEST_DEFINITIONS_HPP

#include <base/behaviour.hpp>
#include <builder/allowedFields.hpp>
#include <builder/builder.hpp>
#include <defs/mockDefinitions.hpp>
#include <logpar/logpar.hpp>
#include <schemf/ivalidator.hpp>
#include <schemf/mockSchema.hpp>
#include <store/mockStore.hpp>

using namespace base::test;
using namespace store::mocks;
using namespace schemf::mocks;
using namespace defs::mocks;

namespace builder::test
{

auto constexpr WAZUH_LOGPAR_TYPES_JSON = R"({
    "name": "name",
    "fields": {
        "wazuh.message": "text",
        "event.code": "text"
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

auto constexpr FILTER_JSON = R"({
    "name": "filter/test/0",
    "check": [{
        "wazuh.queue": 49
    }
    ]
})";

auto constexpr RULE_JSON = R"({
    "name": "rule/test/0",
    "check": [{
        "process.name": "test"
    }
    ],
    "normalize": [
      {
        "map": [
          {
            "event.risk_score": 21
          }
        ]
      }
    ]
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

auto constexpr DECODER_MAP_ON_CHECK_JSON = R"z({
    "name": "decoder/test/0",
    "check": [
        {
            "field": "map(1)"
        }
    ]
})z";

auto constexpr DECODER_FILTER_ON_MAP_JSON = R"z({
    "name": "decoder/test/0",
    "normalize": [
        {
            "map": [
                {
                    "field": "filter(1)"
                }
            ]
        }
    ]
})z";

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

auto constexpr DECODER_STAGE_PARSE_WITHOUT_SEPARATOR_JSON = R"x({
    "name": "decoder/test/0",
    "parse": [
    ]
    })x";

auto constexpr DECODER_STAGE_PARSE_WITHOUT_FIELD_JSON = R"x({
    "name": "decoder/test/0",
    "parse|": [
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

auto constexpr DECODER_STAGE_NORMALIZE_WRONG_PARSE_WITHOUT_SEPARATOR = R"x({
    "name": "decoder/test/0",
    "normalize": [
      {
        "map": [
          {
            "event.code": "2"
          }
        ],
        "parse": [
            "<event.code>"
        ]
      }
    ]
    })x";

auto constexpr DECODER_STAGE_NORMALIZE_WRONG_PARSE_WITHOUT_FIELD = R"x({
    "name": "decoder/test/0",
    "normalize": [
      {
        "map": [
          {
            "event.code": "2"
          }
        ],
        "parse|": [
            "<event.code>"
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
        "system": ["decoder/parent-test/0"]
    }
    })";

auto constexpr DEFECTIVE_POLICY_NAME_JSON = R"({
    "n": "policy/test/0",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": ["decoder/parent-test/0"]
    }
    })";

auto constexpr DEFECTIVE_POLICY_FORMAT_NAME_JSON = R"({
    "name": "",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": ["decoder/parent-test/0"]
    }
    })";

auto constexpr DEFECTIVE_POLICY_HASH_JSON = R"({
    "name": "policy/test/0",
    "h": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": ["decoder/parent-test/0"]
    }
    })";

auto constexpr DEFECTIVE_POLICY_EMPTY_HASH_JSON = R"({
    "name": "policy/test/0",
    "hash": "",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": ["decoder/parent-test/0"]
    }
    })";

auto constexpr DEFECTIVE_PARENT_POLICY_EMPTY_NAME_JSON = R"({
    "name": "policy",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": [""]
    }
    })";

auto constexpr DEFECTIVE_PARENT_POLICY_NOT_STRING_NAME_JSON = R"({
    "name": "policy",
    "hash": "11464515449720324140",
    "assets": ["integration/test/0"],
    "default_parents": {
        "system": [2]
    }
    })";

auto constexpr DEFECTIVE_ASSET_POLICY_NOT_STRING_NAME_JSON = R"({
    "name": "policy",
    "hash": "11464515449720324140",
    "assets": [2,3],
    "default_parents": {
        "system": ["decoder/parent-test/0"]
    }
    })";

struct Mocks
{
    std::shared_ptr<MockStore> m_spStore;
    std::shared_ptr<MockSchema> m_spSchemf;
    std::shared_ptr<MockDefinitionsBuilder> m_spDefBuilder;
    std::shared_ptr<MockDefinitions> m_spDef;
};

template<typename T>
class BuilderTestFixture : public ::testing::TestWithParam<T>
{
public:
    std::shared_ptr<Mocks> m_spMocks;
    std::shared_ptr<builder::Builder> m_spBuilder;

    void SetUp() override
    {
        m_spMocks = std::make_shared<Mocks>();
        m_spMocks->m_spStore = std::make_shared<MockStore>();
        m_spMocks->m_spSchemf = std::make_shared<MockSchema>();
        m_spMocks->m_spDefBuilder = std::make_shared<MockDefinitionsBuilder>();
        m_spMocks->m_spDef = std::make_shared<MockDefinitions>();
        initializeBuilder();
    }

    void initializeBuilder()
    {
        builder::BuilderDeps builderDeps;
        builderDeps.logparDebugLvl = 0;

        ON_CALL(*m_spMocks->m_spSchemf, hasField(DotPath("wazuh.message"))).WillByDefault(testing::Return(true));
        ON_CALL(*m_spMocks->m_spSchemf, hasField(DotPath("event.code"))).WillByDefault(testing::Return(true));
        ON_CALL(*m_spMocks->m_spSchemf, isArray(DotPath("wazuh.message"))).WillByDefault(testing::Return(false));
        ON_CALL(*m_spMocks->m_spSchemf, isArray(DotPath("event.code"))).WillByDefault(testing::Return(false));

        builderDeps.logpar =
            std::make_shared<hlp::logpar::Logpar>(json::Json {WAZUH_LOGPAR_TYPES_JSON}, m_spMocks->m_spSchemf);
        builderDeps.kvdbScopeName = "builder";
        builderDeps.kvdbManager = nullptr;

        auto emptyAllowedFields = std::make_shared<builder::AllowedFields>();

        m_spBuilder = std::make_shared<builder::Builder>(
            m_spMocks->m_spStore, m_spMocks->m_spSchemf, m_spMocks->m_spDefBuilder, emptyAllowedFields, builderDeps);
    }
};

} // namespace builder::test

#endif // _BUILDER_TEST_DEFINITIONS_HPP
