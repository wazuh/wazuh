#include "stageBuilderExpressionCheck.hpp"

#include <string>

#include "registry.hpp"
#include "syntax.hpp"
#include <logicExpression/logicExpression.hpp>

using namespace builder::internals;

namespace builder::internals::builders
{
base::Lifter stageBuilderExpressionCheck(const base::DocumentValue& def,
                                          types::TracerFn tr)
{
    // Assert value is as expected
    if (!def.IsString())
    {
        std::string msg = fmt::format(
            "Stage expression check builder, expected a string but got [{}]",
            def.GetType());
        throw std::invalid_argument(std::move(msg));
    }

    // Obtain expression
    auto expression = def.GetString();

    // Inject builder
    auto termBuilder =
        [=](std::string term) -> std::function<bool(base::Event)>
    {
        std::string field;
        std::string value;

        // Term to json def
        if (term.find("==") != std::string::npos)
        {
            auto pos = term.find("==");
            field = term.substr(0, pos);
            value = term.substr(pos + 2);
        }
        // TODO: handle rest of operators
        else if (term[0] == syntax::FUNCTION_HELPER_ANCHOR)
        {
            auto pos1 = term.find("/");
            auto pos2 = [&]()
            {
                auto tmp = term.find("/", pos1 + 1);
                if (tmp != std::string::npos)
                {
                    return tmp;
                }
                return term.size();
            }();

            field = term.substr(pos1 + 1, pos2);
            value = term.substr(0, pos1) + term.substr(pos2, term.size());
        }

        // Transform KstringPair to object, because that is what expects the builder
        // Todo: this is a hack, we should use a proper builder
        base::Document doc;
        doc.m_doc.SetObject();
        doc.m_doc.GetObject().AddMember({field.c_str(), doc.getAllocator()},
                                        {value.c_str(), doc.getAllocator()},
                                        doc.getAllocator());

        // TODO: we need to rethink how and why we are using the registry
        auto termFunction = std::get<types::MiddleBuilderCondition>(
            Registry::getBuilder("middle.condition"))(doc.getObject(), tr);
        return termFunction;
    };

    // Evaluator function
    auto evaluator = logicExpression::buildDijstraEvaluator<base::Event>(
        expression, termBuilder);

    return [=](base::Observable observable) -> base::Observable
    {
        return observable.filter([=](base::Event event)
                                 { return evaluator(event); });
    };
}

} // namespace builder::internals::builders
