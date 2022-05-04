#include "stageBuilderExpressionCheck.hpp"

#include <string>

#include "registry.hpp"
#include "syntax.hpp"
#include <logicExpression/logicExpression.hpp>

using namespace builder::internals;

namespace builder::internals::builders
{
types::Lifter stageBuilderExpressionCheck(const types::DocumentValue& def,
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
        [=](std::string term) -> std::function<bool(types::Event)>
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

        types::Document doc;
        doc.m_doc.SetObject();
        doc.m_doc.GetObject().AddMember({field.c_str(), doc.getAllocator()},
                                        {value.c_str(), doc.getAllocator()},
                                        doc.getAllocator());

        auto termFunction = std::get<types::MiddleBuilderCondition>(
            Registry::getBuilder("middle.condition"))(doc.getObject(), tr);
        return termFunction;
    };

    // Evaluator function
    auto evaluator = logicExpression::buildDijstraEvaluator<types::Event>(
        expression, termBuilder);

    return [=](types::Observable observable) -> types::Observable
    {
        return observable.filter([=](types::Event event)
                                 { return evaluator(event); });
    };
}

} // namespace builder::internals::builders
