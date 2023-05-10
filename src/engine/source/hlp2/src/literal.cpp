#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{
parsec::MergeableParser<jFnList> getLiteralParser(const ParserSpec& spec)
{
    if (spec.args().size() != 1)
    {
        throw(std::runtime_error("Literal parser requires exactly one option"));
    }

    return [spec](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        auto result = parsec::MergeableResultP<jFnList>::failure(state);

        if (state.getRemainingSize() == 0)
        {
            if (state.isTraceEnabled())
            {
                auto trace =
                    fmt::format("[failure] {} -> Unexpected EOF, expected literal '{}'", spec.name(), spec.args()[0]);
                result.concatenateTraces(trace);
            }
            return result;
        }

        auto inputStr = state.getRemainingData();

        // Fail
        if (inputStr.substr(0, spec.args()[0].size()) != spec.args()[0])
        {
            if (state.isTraceEnabled())
            {
                auto trace = fmt::format("[failure] {} -> Unexpected literal '{}', expected literal '{}'",
                                         spec.name(),
                                         inputStr,
                                         spec.args()[0]);
                result.concatenateTraces(trace);
            }
            return result;
        }

        // Success
        parsec::Mergeable<jFnList> mergeable {.m_semanticProcessor = internal::semanticProcessorPass};
        result.setSuccess(state.advance(spec.args()[0].size()), std::move(mergeable));

        if (state.isTraceEnabled())
        {
            auto trace = fmt::format("[success] {} -> Literal '{}'", spec.name(), spec.args()[0]);
            result.concatenateTraces(trace);
        }

        return result;
    };
}
} // namespace hlp
