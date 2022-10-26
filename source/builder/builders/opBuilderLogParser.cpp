#include "opBuilderLogParser.hpp"

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
#include <baseHelper.hpp>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
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
    else if (typeid(float) == type)
    {
        json::Json val;
        val.setDouble(std::any_cast<float>(anyVal));
        event->set(path, val);
    }
    else if (typeid(double) == type)
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
    else if (typeid(json::Json) == type)
    {
        try
        {
            event->set(path, std::any_cast<json::Json>(anyVal));
        }
        catch (const std::exception& e)
        {
            return false;
        }
    }
    else
    {
        // ASSERT
        return false;
    }
    return true;
}

base::Expression opBuilderLogParser(const std::any& definition)
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
            std::string(
                "Engine log parser builder: Definition could not be converted to json: ")
            + e.what());
    }
    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(
            fmt::format("Engine log parser builder: Invalid json definition type: "
                        "expected \"array\" but got \"{}\".",
                        jsonDefinition.typeName()));
    }
    if (jsonDefinition.size() < 1)
    {
        throw std::runtime_error("Engine log parser builder: Invalid json definition, "
                                 "expected at least one element.");
    }

    auto logparArr = jsonDefinition.getArray().value();

    std::vector<base::Expression> parsersExpressions;
    for (const json::Json& item : logparArr)
    {
        if (!item.isObject())
        {
            throw std::runtime_error(
                fmt::format("Engine log parser builder: Invalid json item type: expected "
                            "an object but got {}.",
                            item.typeName()));
        }
        if (item.size() != 1)
        {
            throw std::runtime_error(
                fmt::format("Engine log parser builder: Invalid json item size, expected "
                            "exactly one element but got {}",
                            item.size()));
        }

        auto itemObj = item.getObject().value();
        const auto field = json::Json::formatJsonPath(std::get<0>(itemObj[0]));
        const auto logpar = std::get<1>(itemObj[0]).getString().value();

        ParserFn parseOp;
        try
        {
            parseOp = hlp::getParserOp(logpar);
        }
        catch (std::runtime_error& e)
        {
            std::throw_with_nested(std::runtime_error(
                std::string(
                    "Engine log parser builder: An error occurred while parsing a log: ")
                + e.what()));
        }

        // Traces
        const auto name = fmt::format("{}: {}", field, logpar);
        const auto successTrace = fmt::format("[{}] -> Success", name);

        // field to be parsed not exists
        const std::string failureTrace1 = fmt::format(
            "[{}] -> Failure: Parameter \"{}\" reference not found", name, field);
        // Parsing failed
        const std::string failureTrace2 =
            fmt::format("[{}] -> Failure: Parse operation failed: ", name);
        // Parsing ok, mapping failed
        const std::string failureTrace3 = fmt::format(
            "[{}] -> Failure: Parsing succeded but mapping failed at: ", name);

        base::Expression parseExpression;
        try
        {
            parseExpression = base::Term<base::EngineOp>::create(
                "parse.logpar", [=, parserOp = std::move(parseOp)](base::Event event)
                {
                    if (!event->exists(field))
                    {
                        return base::result::makeFailure(event, failureTrace1);
                    }
                    auto ev = event->getString(field);
                    ParseResult result;
                    auto parseResult = parserOp(ev.value(), result);
                    if (!parseResult)
                    {
                        return base::result::makeFailure(
                            event, failureTrace2 + parseResult.trace);
                    }

                    for (auto const& val : result)
                    {
                        auto resultPath = json::Json::formatJsonPath(val.first.c_str());
                        if (!any2Json(val.second, resultPath, event))
                        {
                            return base::result::makeFailure(event,
                                                             failureTrace3 + resultPath);
                        }
                    }

                    return base::result::makeSuccess(event, successTrace);
                });
        }
        catch (const std::exception& e) // TODO: is this right?
        {
            throw std::runtime_error(fmt::format(
                "Engine log parser builder: Exception creating \"{}: {}\": {}",
                field,
                logpar,
                e.what()));
        }

        parsersExpressions.push_back(parseExpression);
    }

    return base::Or::create("parse.logpar", parsersExpressions);
}
} // namespace builder::internals::builders
