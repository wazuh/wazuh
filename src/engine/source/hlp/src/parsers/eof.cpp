
#include "hlp.hpp"

namespace hlp::parsers
{
    Parser getEofParser(const Params& params)
    {
        return [name = params.name](std::string_view txt)
        {
            if (txt.empty())
            {
                return abs::makeSuccess<ResultT>(txt);
            }
            else
            {
                return abs::makeFailure<ResultT>(txt, name);
            }
        };
    }
}
