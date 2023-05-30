#ifndef _LOGPAR_TEST_HPP
#define _LOGPAR_TEST_HPP

#include <gtest/gtest.h>

#include <fmt/format.h>

#include <json/json.hpp>
#include <logpar/logpar.hpp>

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

hlp::logpar::Logpar getLogpar()
{
    hlp::logpar::Logpar ret {getConfig()};
    ret.registerBuilder(hlp::ParserType::P_TEXT, hlp::parsers::getTextParser);
    ret.registerBuilder(hlp::ParserType::P_LONG, hlp::parsers::getLongParser);
    ret.registerBuilder(hlp::ParserType::P_LITERAL, hlp::parsers::getLiteralParser);
    return ret;
}

json::Json J(std::string_view txt)
{
    return json::Json(txt.data());
}
} // namespace logpar_test

#endif // _LOGPAR_TEST_HPP
