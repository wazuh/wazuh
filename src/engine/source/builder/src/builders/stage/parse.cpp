#include "parse.hpp"

#include <json/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{
// TODO: QoL error messages
StageBuilder getParseBuilder(std::shared_ptr<hlp::logpar::Logpar> logpar, size_t debugLvl)
{
    if (debugLvl != 0 && debugLvl != 1)
    {
        throw std::runtime_error("[builder::opBuilderLogParser] Invalid debug level: expected 0 or 1");
    }

    if (!logpar)
    {
        throw std::runtime_error("[builder::opBuilderLogParser] Invalid logpar");
    }

    return [logpar, debugLvl](const json::Json& definition,
                              const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        // Assert definition is as expected
        if (!definition.isArray())
        {
            throw std::runtime_error(fmt::format(
                "Stage '{}' expects an array but got '{}'", syntax::asset::PARSE_KEY, definition.typeName()));
        }
        if (definition.size() < 1)
        {
            throw std::runtime_error(
                fmt::format("Stage '{}' expects a non-empty array but got an empty array", syntax::asset::PARSE_KEY));
        }

        auto logparArr = definition.getArray().value();
        std::vector<base::Expression> parsersExpressions {};
        for (const json::Json& item : logparArr)
        {
            if (!item.isObject())
            {
                throw std::runtime_error(
                    fmt::format(R"(Invalid json item type: Expected an "object" but got "{}")", item.typeName()));
            }
            if (item.size() != 1)
            {
                throw std::runtime_error(
                    fmt::format("Invalid json item size: Expected exactly one element but got {}", item.size()));
            }

            auto itemObj = item.getObject().value();
            auto field = json::Json::formatJsonPath(std::get<0>(itemObj[0]));
            auto logparExpr = std::get<1>(itemObj[0]).getString().value();
            logparExpr = buildCtx->definitions().replace(logparExpr);

            hlp::parser::Parser parser;
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
                fmt::format(R"([{}] -> Failure: Parameter "{}" reference not found)", name, field);
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
                        auto error = hlp::parser::run(parser, ev, *event);
                        if (error)
                        {
                            return base::result::makeFailure(std::move(event), failureTrace2 + error.value().message);
                        }

                        return base::result::makeSuccess(std::move(event), successTrace);
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

} // namespace builder::builders
