#include "opBuilderLogParser.hpp"

#include <any>

#include "baseTypes.hpp"
#include "expression.hpp"
#include <json/json.hpp>

namespace builder::internals::builders
{

Builder getOpBuilderLogParser(std::shared_ptr<hlp::logpar::Logpar> logpar, size_t debugLvl)
{
    // TODO: Implement debug level
    if (debugLvl != 0 && debugLvl != 1)
    {
        throw std::runtime_error("[builder::opBuilderLogParser] Invalid debug level: expected 0 or 1");
    }

    return [logpar, debugLvl](std::any definition, std::shared_ptr<defs::IDefinitions> definitions)
    {
        // Assert definition is as expected
        json::Json jsonDefinition;

        try
        {
            jsonDefinition = std::any_cast<json::Json>(definition);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(std::string("Definition could not be converted to json: ") + e.what());
        }
        if (!jsonDefinition.isArray())
        {
            throw std::runtime_error(fmt::format("Invalid json definition type: Expected \"array\" but got \"{}\"",
                                                 jsonDefinition.typeName()));
        }
        if (jsonDefinition.size() < 1)
        {
            throw std::runtime_error("Invalid json definition, expected at least one element");
        }

        auto logparArr = jsonDefinition.getArray().value();
        std::vector<base::Expression> parsersExpressions {};
        for (const json::Json& item : logparArr)
        {
            if (!item.isObject())
            {
                throw std::runtime_error(
                    fmt::format("Invalid json item type: Expected an \"object\" but got \"{}\"", item.typeName()));
            }
            if (item.size() != 1)
            {
                throw std::runtime_error(
                    fmt::format("Invalid json item size: Expected exactly one element but got {}", item.size()));
            }

            auto itemObj = item.getObject().value();
            auto field = json::Json::formatJsonPath(std::get<0>(itemObj[0]));
            auto logparExpr = std::get<1>(itemObj[0]).getString().value();
            logparExpr = definitions->replace(logparExpr);

            parsec::Parser<hlp::jFnList> parser;
            try
            {
                parser = logpar->build(logparExpr);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("An error occurred while parsing a log: {}", e.what()));
            }

            // Traces
            const auto name = fmt::format("{}: {}", field, logparExpr);
            const auto successTrace = fmt::format("[{}] -> Success", name);

            // field to be parsed not exists
            const std::string failureTrace1 =
                fmt::format("[{}] -> Failure: Parameter \"{}\" reference not found", name, field);
            // Parsing failed
            const std::string failureTrace2 = fmt::format("[{}] -> Failure: Parse operation failed: ", name);
            // Parsing ok, mapping failed
            const std::string failureTrace3 = fmt::format("[{}] -> Failure: field [{}] is not a string", name, field);

            base::Expression parseExpression;
            try
            {
                parseExpression = base::Term<base::EngineOp>::create(
                    "parse.logpar",
                    [=, parser = std::move(parser)](base::Event event)
                    {
                        if (!event->exists(field))
                        {
                            return base::result::makeFailure(std::move(event), failureTrace1);
                        }
                        if (!event->isString(field))
                        {
                            return base::result::makeFailure(std::move(event), failureTrace3);
                        }

                        auto ev = event->getString(field).value();
                        auto parseResult = parser(parsec::ParserState(ev, debugLvl));


                        // TODO: move this to a function in parsec
                        std::string trace {};
                        if (parseResult.hasTraces())
                        {
                            trace += "\n";
                            for (const auto& t : parseResult.getTraces())
                            {
                                // TODO: check if the order is necesary
                                // Format: [order]: | offset: [offset] | [message]
                                trace += fmt::format(
                                    "{:4}: | offset: {:3} | {}\n", t.getOrder(), t.getOffset(), t.getMessage());
                            }
                        }

                        if (parseResult.isFailure())
                        {
                            trace = failureTrace2 + (trace.empty() ? "No traces" : trace);
                            return base::result::makeFailure(std::move(event), trace);
                        }

                        auto listFn = parseResult.popValue();
                        for(const auto& fn : listFn) {
                            fn(*event); // TODO: check if this is the correct way to do it
                        }

                        // TODO Implement a better way to get the optional trace
                        return base::result::makeSuccess(std::move(event), successTrace + trace);
                    });
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(
                    fmt::format("[builder::opBuilderLogParser(json)] Exception creating [{}: {}]: {}",
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
