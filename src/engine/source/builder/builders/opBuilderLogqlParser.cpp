#include "opBuilderLogqlParser.hpp"

#include <any>
#include <stdexcept>
#include <string>
#include <typeindex>
#include <typeinfo>
#include <vector>
// TODO test
#include <fstream>

#include <fmt/format.h>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "json.hpp"
#include <hlp/hlp.hpp>
#include <logging/logging.hpp>

namespace builder::internals::builders
{
static bool any2Json(std::any const& anyVal, std::string const& path, base::Event event)
{
    auto& type = anyVal.type();
    if (typeid(void) == type)
    {
        json::Json val;
        val.setNull();
        event->set(path, val);
    }
    else if (typeid(long) == type || typeid(int) == type || typeid(unsigned) == type)
    {
        json::Json val;
        val.setInt(std::any_cast<long>(anyVal));
        event->set(path, val);
    }
    else if (typeid(float) == type || typeid(double) == type)
    {
        json::Json val;
        val.setDouble(std::any_cast<double>(anyVal));
        event->set(path, val);
    }
    else if (typeid(std::string) == type)
    {
        const auto& s = std::any_cast<std::string>(anyVal);
        json::Json val;
        val.setString(s);
        event->set(path, val);
    }
    else if (typeid(hlp::JsonString) == type)
    {
        const auto& s = std::any_cast<hlp::JsonString>(anyVal);
        json::Json val;
        try
        {
            val = json::Json(s.jsonString.c_str());
        }
        catch (const std::exception& e)
        {
            return false;
        }

        event->set(path, val);
    }
    else
    {
        // ASSERT
        return false;
    }
    return true;
}

base::Expression opBuilderLogqlParser(const std::any& definition)
{
    // Assert definition is as expected
    json::Json jsonDefinition;

    try
    {
        jsonDefinition = std::any_cast<json::Json>(definition);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            "[builder::opBuilderLogqlParser(json)] Received unexpected argument type");
    }
    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(
            fmt::format("[builder::opBuilderLogqlParser(json)] Invalid json definition "
                        "type: expected [array] but got [{}]",
                        jsonDefinition.typeName()));
    }
    if (jsonDefinition.size() < 1)
    {
        throw std::runtime_error(
            "[builder::opBuilderLogqlParser(json)] Invalid json definition: expected "
            "at least one element");
    }

    auto logqlArr = jsonDefinition.getArray().value();

    std::vector<base::Expression> parsersExpressions;
    for (const json::Json& item : logqlArr)
    {
        if (!item.isObject())
        {
            throw std::runtime_error(
                fmt::format("[builder::opBuilderLogqlParser(json)] Invalid item json "
                            "type: expected [object] but got [{}]",
                            item.typeName()));
        }
        if (item.size() != 1)
        {
            throw std::runtime_error(
                fmt::format("[builder::opBuilderLogqlParser(json)] Invalid item json "
                            "size: expected exactly one element but got {}",
                            item.size()));
        }

        auto itemObj = item.getObject().value();
        auto field = json::Json::formatJsonPath(std::get<0>(itemObj[0]));
        auto logql = std::get<1>(itemObj[0]).getString().value();

        ParserFn parseOp;
        try
        {
            parseOp = hlp::getParserOp(logql);
        }
        catch (std::runtime_error& e)
        {
            const char* msg = "Stage [parse] builder encountered exception parsing logQl "
                              "expr";
            std::throw_with_nested(std::runtime_error(msg));
        }

        // Traces
        auto name = fmt::format("{}: {}", field, logql);
        auto successTrace = fmt::format("{} -> Success", name);

        // field to be parsed not exists
        auto errorTrace1 =
            fmt::format("[{}] -> Failure: field [{}] not found", name, field);
        // Parsing failed
        auto errorTrace2 = fmt::format("[{}] -> Failure:\nParser trace: ", name);
        // Parsing ok, mapping failed
        auto errorTrace3 = fmt::format(
            "[{}] -> Failure: parsing succeded but mapping failed at:\n", name);

        base::Expression parseExpression;
        try
        {
            parseExpression = base::Term<base::EngineOp>::create(
                "parse.logql",
                [=, parserOp = std::move(parseOp)](base::Event event)
                {
                    if (!event->exists(field))
                    {
                        return base::result::makeFailure(std::move(event), errorTrace1);
                    }
                    auto ev = event->getString(field);
                    ParseResult result;
                    auto parseResult = parserOp(ev.value(), result);
                    if (!parseResult)
                    {
                        return base::result::makeFailure(std::move(event),
                                                         errorTrace2 + parseResult.trace);
                    }

                    for (auto const& val : result)
                    {
                        auto resultPath = json::Json::formatJsonPath(val.first.c_str());
                        if (!any2Json(val.second, resultPath, event))
                        {
                            return base::result::makeFailure(std::move(event),
                                                             errorTrace3 + resultPath);
                        }
                    }

                    return base::result::makeSuccess(std::move(event), successTrace);
                });
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format(
                "[builder::opBuilderLogqlParser(json)] Exception creating [{}: {}]: {}",
                field,
                logql,
                e.what()));
        }

        parsersExpressions.push_back(parseExpression);
    }

    return base::Or::create("parse.logql", parsersExpressions);
}
} // namespace builder::internals::builders
