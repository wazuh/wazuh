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

json::Json getConfig()
{
    json::Json config {};
    config.setObject();
    config.setString(hlp::schemaTypeToStr(hlp::SchemaType::LONG), "/fields/long");
    config.setString(hlp::schemaTypeToStr(hlp::SchemaType::TEXT), "/fields/text");
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
            .WillByDefault(::testing::Invoke([](const auto& param)
                                             { return param == "text" || param == "long" || param == "literal"; }));

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
