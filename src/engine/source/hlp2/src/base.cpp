#include <hlp/base.hpp>

namespace hlp::internal
{

// this function should not be in the header, we don't want it to be treated as inline (Merable struct referenses)
void concatenateJFnList(jFnList& dst, jFnList& src)
{
    dst.insert(dst.end(), std::make_move_iterator(src.begin()), std::make_move_iterator(src.end()));
};

// this function should not be in the header, we don't want it to be treated as inline (Merable struct referenses)
std::pair<bool, std::optional<parsec::TraceP>>
semanticProcessorPass(jFnList&, const std::deque<std::string_view>&, const parsec::ParserState&)
{
    return {true, std::nullopt};
};
} // namespace hlp::internal
