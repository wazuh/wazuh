#include "opBuilderLogParser.hpp"

#include <any>

#include "baseTypes.hpp"
#include "expression.hpp"
#include <json/json.hpp>

namespace builder::internals::builders
{

Builder getOpBuilderLogParser(std::shared_ptr<hlp::logpar::Logpar> logpar,
                              size_t debugLvl)
{
    if (debugLvl != 0 && debugLvl != 1)
    {
        throw std::runtime_error(
            "[builder::opBuilderLogParser] Invalid debug level: expected 0 or 1");
    }

    return [logpar, debugLvl](std::any definition)
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
                std::string("Definition could not be converted to json: ") + e.what());
        }
        if (!jsonDefinition.isArray())
        {
            throw std::runtime_error(fmt::format(
                R"(Invalid json definition type: Expected "array" but got "{}")",
                jsonDefinition.typeName()));
        }
        if (jsonDefinition.size() < 1)
        {
            throw std::runtime_error(
                "Invalid json definition, expected at least one element");
        }

        auto logparArr = jsonDefinition.getArray().value();
        std::vector<base::Expression> parsersExpressions{};
        for (const json::Json& item : logparArr)
        {
            if (!item.isObject())
            {
                throw std::runtime_error(fmt::format(
                    "Invalid json item type: Expected an \"object\" but got \"{}\"",
                    item.typeName()));
            }
            if (item.size() != 1)
            {
                throw std::runtime_error(fmt::format(
                    "Invalid json item size: Expected exactly one element but got {}",
                    item.size()));
            }

            auto itemObj = item.getObject().value();
            auto field = json::Json::formatJsonPath(std::get<0>(itemObj[0]));
            auto logparExpr = std::get<1>(itemObj[0]).getString().value();

            parsec::Parser<json::Json> parser;
            try
            {
                parser = logpar->build(logparExpr);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(
                    fmt::format("An error occurred while parsing a log: {}", e.what()));
            }

            // Traces
            const auto name = fmt::format("{}: {}", field, logparExpr);
            const auto successTrace = fmt::format("[{}] -> Success", name);

            // field to be parsed not exists
            const std::string failureTrace1 = fmt::format(
                "[{}] -> Failure: Parameter \"{}\" reference not found", name, field);
            // Parsing failed
            const std::string failureTrace2 =
                fmt::format("[{}] -> Failure: Parse operation failed: ", name);
            // Parsing ok, mapping failed
            const std::string failureTrace3 =
                fmt::format("[{}] -> Failure: field [{}] is not a string", name, field);

            base::Expression parseExpression;
            try
            {
                parseExpression = base::Term<base::EngineOp>::create(
                    "parse.logpar",
                    [=, parser = std::move(parser)](base::Event event)
                    {
                        if (!event->exists(field))
                        {
                            return base::result::makeFailure(std::move(event),
                                                             failureTrace1);
                        }
                        if (!event->isString(field))
                        {
                            return base::result::makeFailure(std::move(event),
                                                             failureTrace3);
                        }

                        auto ev = event->getString(field).value();
                        auto parseResult = parser(ev, 0);
                        if (parseResult.failure())
                        {
                            return base::result::makeFailure(
                                std::move(event),
                                failureTrace2
                                    + parsec::formatTrace(
                                        ev, parseResult.trace(), debugLvl));
                        }

                        auto val = parseResult.value();
                        if (!val.isNull() && val.size() > 0)
                        {
                            // event->merge(val);
                            auto obj = val.getObject().value();
                            for (auto& [key, value] : obj)
                            {
                                auto formatKey = json::Json::formatJsonPath(key);
                                event->set(formatKey, value);
                            }
                        }

                        return base::result::makeSuccess(std::move(event), successTrace);
                    });
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format(
                    "[builder::opBuilderLogParser(json)] Exception creating [{}: {}]: {}",
                    field,
                    logparExpr,
                    e.what()));
            }

            parsersExpressions.push_back(parseExpression);
        }

        return base::Or::create("parse.logpar", parsersExpressions);
    };
}

} // namespace builder::internals::builders
