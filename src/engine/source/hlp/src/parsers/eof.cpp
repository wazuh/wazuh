
#include "hlp.hpp"

namespace hlp::parsers
{
Parser getEofParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw(std::runtime_error("Eof parser does not accept options"));
    }

    return [name = params.name, semP = noSemParser()](std::string_view txt)
    {
        if (txt.empty())
        {
            return abs::makeSuccess<ResultT>(SemToken {txt, semP}, txt);
        }
        else
        {
            return abs::makeFailure<ResultT>(txt, name);
        }
    };
}
} // namespace hlp::parsers
