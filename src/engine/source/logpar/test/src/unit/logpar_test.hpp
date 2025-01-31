#ifndef _LOGPAR_TEST_HPP
#define _LOGPAR_TEST_HPP

#include <gtest/gtest.h>

#include <memory>

#include <fmt/format.h>

#include <base/json.hpp>
#include <logpar/logpar.hpp>

#include <schemf/mockSchema.hpp>

using namespace schemf::mocks;
namespace logpar_test
{

const std::string LONG_FIELD_OVERRIDE = "long.override";
const std::string LONG_FIELD_OVERRIDE_PATH = "/fields/long.override";
const std::string TEXT_FIELD_OVERRIDE = "text.override";
const std::string TEXT_FIELD_OVERRIDE_PATH = "/fields/text.override";

json::Json getConfig()
{
    json::Json config {};
    config.setObject();
    config.setString("schema/wazuh-logpar-overrides/0", "/name");
    config.setObject("/fields");
    config.setString(hlp::parserTypeToStr(hlp::ParserType::P_LONG), LONG_FIELD_OVERRIDE_PATH);
    config.setString(hlp::parserTypeToStr(hlp::ParserType::P_TEXT), TEXT_FIELD_OVERRIDE_PATH);
    return config;
}

class LogparPBase
{
protected:
    std::shared_ptr<MockSchema> schema;
    std::shared_ptr<hlp::logpar::Logpar> logpar;

    void init()
    {
        auto config = getConfig();

        schema = std::make_shared<MockSchema>();
        ON_CALL(*schema, hasField(::testing::_))
            .WillByDefault(::testing::Invoke(
                [](const auto& param)
                {
                    return param == "text" || param == "long" || param == "literal" || param == TEXT_FIELD_OVERRIDE
                           || param == LONG_FIELD_OVERRIDE || param == "array";
                }));

        ON_CALL(*schema, isArray(::testing::_))
            .WillByDefault(::testing::Invoke([](const auto& param) { return param == "array"; }));

        ON_CALL(*schema, getType(::testing::_))
            .WillByDefault(::testing::Invoke(
                [](const auto& param)
                {
                    if (param == "text")
                        return schemf::Type::TEXT;
                    if (param == "long")
                        return schemf::Type::LONG;
                    if (param == "literal")
                        return schemf::Type::KEYWORD;
                    if (param == TEXT_FIELD_OVERRIDE)
                        return schemf::Type::TEXT;
                    if (param == LONG_FIELD_OVERRIDE)
                        return schemf::Type::LONG;
                    if (param == "array")
                        return schemf::Type::TEXT;
                    return schemf::Type::ERROR;
                }));

        logpar = std::make_shared<hlp::logpar::Logpar>(config, schema);
        logpar->registerBuilder(hlp::ParserType::P_TEXT, hlp::parsers::getTextParser);
        logpar->registerBuilder(hlp::ParserType::P_LONG, hlp::parsers::getLongParser);
        logpar->registerBuilder(hlp::ParserType::P_LITERAL, hlp::parsers::getLiteralParser);
    }
};

json::Json J(std::string_view txt)
{
    return json::Json(txt.data());
}
} // namespace logpar_test

#endif // _LOGPAR_TEST_HPP
