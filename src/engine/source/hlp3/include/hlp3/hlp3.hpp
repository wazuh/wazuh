#ifndef _HLP3_HLP3_HPP
#define _HLP3_HLP3_HPP

#include <hlp3/parser.hpp>
#include <tuple>

// Parsers builders
namespace hlp3::parser
{
namespace builder
{

} // namespace builder

namespace combinator
{

// cartesian product
template<typename L, typename R>
Parser<std::tuple<L, R>> operator&(const Parser<L>& l, const Parser<R>& r)
{
    return [l, r](InputP input) -> ResultP<std::tuple<L, R>>
    {
        auto resultL = l(input);
        if (!resultL)
        {
            auto result = ResultP<std::tuple<L, R>>::failure();
            return result.concatenateTraces(std::move(resultL));
        }

        auto resultR = r(resultL.getRemaining());
        if (!resultR)
        {
            auto result = ResultP<std::tuple<L, R>>::failure();
            return result.concatenateTraces(std::move(resultL)).concatenateTraces(std::move(resultR));
        }

        return ResultP<std::tuple<L, R>>::success(resultR.getRemaining())
            .concatenateTraces(std::move(resultL))
            .concatenateTraces(std::move(resultR));
    };
}

// Optional parser
template<typename T>
Parser<T> opt(const Parser<T>& p)
{
    return [p](InputP input) -> ResultP<T>
    {
        auto result = p(input);
        if (!result)
        {
            return ResultP<T>::success(input).concatenateTraces(std::move(result));
        }
        return result;
    };
}


template<typename T>
struct preParserResult
{
    T m_result;
    std::list<std::string_view> m_tokens;
    std::function<std::optional<std::string>(T&, const std::list<std::string_view>&)> m_tokenProcessor;

    // Merge the result of T and process the tokens using the tokenProcessor
    std::optional<std::string> mergeResult(T& result) const
    {
        return m_tokenProcessor(result, m_tokens);
    }
};

template<typename T>
Parser<T> seq(const std::list<Parser<preParserResult<T>>>& parsers)
{
    return [parsers](const InputP input) -> ResultP<T>
    {
        InputP currentInput = input;
        std::list<preParserResult<T>> preResults;
        for (auto& parser : parsers)
        {
            auto result = parser(currentInput);
            if (!result)
            {
                return ResultP<T>::failure().concatenateTraces(std::move(result));
            }
            if (auto value = result.popValue(); value)
            {
                preResults.push_back(std::move(*value));
            }
            currentInput = result.getRemaining();
        }

        // if all pre-parsers succeeded, process the tokens
        T finalResult;
        for (auto& preResult : preResults)
        {
            auto error = preResult.mergeResult(finalResult);
            if (error)
            {
                return ResultP<T>::failure(TraceP(*error, currentInput.getPos()));
            }
        }

        return ResultP<T>::success(currentInput, std::move(finalResult));
    };
}

} // namespace combinator
} // namespace hlp3::parser

#endif // _HLP3_HLP3_HPP
