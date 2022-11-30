#include "opBuilderLogParser.hpp"

#include <any>

#include "baseTypes.hpp"
#include "expression.hpp"
#include <json/json.hpp>

namespace builder::internals::builders
{

Builder getOpBuilderLogParser(std::shared_ptr<hlp::logpar::Logpar> logpar)
{
    return [logpar](std::any definition)
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
                "[builder::opBuilderLogParser(json)] Received unexpected argument type");
        }
        if (!jsonDefinition.isArray())
        {
            throw std::runtime_error(
                fmt::format("[builder::opBuilderLogParser(json)] Invalid json definition "
                            "type: expected [array] but got [{}]",
                            jsonDefinition.typeName()));
        }
        if (jsonDefinition.size() < 1)
        {
            throw std::runtime_error(
                "[builder::opBuilderLogParser(json)] Invalid json definition: expected "
                "at least one element");
        }

        auto logparArr = jsonDefinition.getArray().value();
        std::vector<base::Expression> parsersExpressions;
        for (const json::Json& item : logparArr)
        {
            if (!item.isObject())
            {
                throw std::runtime_error(
                    fmt::format("[builder::opBuilderLogParser(json)] Invalid item json "
                                "type: expected [object] but got [{}]",
                                item.typeName()));
            }
            if (item.size() != 1)
            {
                throw std::runtime_error(
                    fmt::format("[builder::opBuilderLogParser(json)] Invalid item json "
                                "size: expected exactly one element but got {}",
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
                const char* msg =
                    "Stage [parse] builder encountered exception parsing logpar "
                    "expr";
                std::throw_with_nested(std::runtime_error(msg));
            }

            // Traces
            auto name = fmt::format("{}: {}", field, logparExpr);
            auto successTrace = fmt::format("{} -> Success", name);

            // field to be parsed not exists
            auto errorTrace1 =
                fmt::format("[{}] -> Failure: field [{}] not found", name, field);
            // Parsing failed
            auto errorTrace2 = fmt::format("[{}] -> Failure:\nParser trace: ", name);
            // Field to be parsed is not a string
            auto errorTrace3 =
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
                                                             errorTrace1);
                        }
                        if (!event->isString(field))
                        {
                            return base::result::makeFailure(std::move(event),
                                                             errorTrace3);
                        }

                        auto ev = event->getString(field).value();
                        auto parseResult = parser(ev, 0);
                        if (parseResult.failure())
                        {
                            return base::result::makeFailure(
                                std::move(event), errorTrace2 + parseResult.error().msg);
                        }

                        auto val = parseResult.value();
                        if (!val.isNull() && val.size() > 0)
                        {
                            event->merge(val);
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
