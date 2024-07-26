#ifndef _POC_PARSEC_HPP
#define _POC_PARSEC_HPP

#include <functional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "baseTypes.hpp" // hlpc
#include <arpa/inet.h>   // ip
#include <variant>       // SemParser
#include <iostream> // TODO delete


namespace pocp
{

template<typename T>
class Result
{
public:
    using Nested = std::vector<Result>;
    static_assert(std::is_move_constructible_v<T>, "T must be move constructible");

private:
    T m_value;
    std::string_view m_remaining;
    std::string_view m_trace;
    bool m_success;
    bool m_hasValue;
    Nested m_nested;

public:
    Result() = default;
    ~Result() = default;

    Result(T&& value, std::string_view remaining, bool success, std::string_view trace, bool hasValue)
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
    {
    }

    Result(T&& value, std::string_view remaining, bool success, std::string_view trace, bool hasValue, Nested&& nested)
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
        , m_nested(std::move(nested))
    {
    }

    template<typename... Nested>
    Result(
        T&& value, std::string_view remaining, bool success, std::string_view trace, bool hasValue, Nested&&... nested)
        : m_value(std::move(value))
        , m_remaining(remaining)
        , m_success(success)
        , m_trace(trace)
        , m_hasValue(hasValue)
    {
        m_nested.reserve(sizeof...(Nested));
        (m_nested.emplace_back(std::move(nested)), ...);
    }

    Result(const Result& other)
        : m_value(other.m_value)
        , m_remaining(other.m_remaining)
        , m_trace(other.m_trace)
        , m_success(other.m_success)
        , m_hasValue(other.m_hasValue)
        , m_nested(other.m_nested)
    {
    }

    Result(Result&& other) noexcept
        : m_value(std::move(other.m_value))
        , m_remaining(std::move(other.m_remaining))
        , m_trace(std::move(other.m_trace))
        , m_success(std::move(other.m_success))
        , m_hasValue(std::move(other.m_hasValue))
        , m_nested(std::move(other.m_nested))
    {
    }

    bool success() const { return m_success; }
    bool failure() const { return !m_success; }

    std::string_view remaining() const { return m_remaining; }

    bool hasValue() const { return m_hasValue; }
    const T& value() const { return m_value; }

    const Nested& nested() const { return m_nested; }

    std::string_view trace() const { return m_trace; }
};

template<typename T>
auto makeSuccess(std::string_view remaining)
{
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    return Result<T>({}, remaining, true, {}, false);
}

template<typename T>
auto makeSuccess(T&& value, std::string_view remaining)
{
    return Result<T>(std::move(value), remaining, true, {}, true);
}

template<typename T, typename... Nested>
auto makeSuccess(T&& value, std::string_view remaining, Nested&&... nested)
{
    return Result<T>(std::move(value), remaining, true, {}, true, std::move(nested)...);
}

template<typename T>
auto makeSuccess(std::string_view remaining, typename Result<T>::Nested&& nested)
{
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    return Result<T>({}, remaining, true, {}, false, std::move(nested));
}

template<typename T, typename... Nested>
auto makeSuccess(std::string_view remaining, Nested&&... nested)
{
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    return Result<T>({}, remaining, true, {}, false, std::move(nested)...);
}

template<typename T>
auto makeFailure(std::string_view remaining, std::string_view trace)
{
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    return Result<T>({}, remaining, false, trace, false);
}

template<typename T>
auto makeFailure(std::string_view remaining, std::string_view trace, typename Result<T>::Nested&& nested)
{
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    return Result<T>({}, remaining, false, trace, false, std::move(nested));
}

template<typename T, typename... Nested>
auto makeFailure(std::string_view remaining, std::string_view trace, Nested&&... nested)
{
    static_assert(std::is_default_constructible_v<T>, "T must be default constructible");
    return Result<T>({}, remaining, false, trace, false, std::move(nested)...);
}

template<typename T>
using Parser = std::function<Result<T>(std::string_view)>;
} // namespace pocp

namespace syntaxc
{
using ResultT = std::string_view;
using Result = pocp::Result<ResultT>;
using Parser = pocp::Parser<ResultT>;
using namespace pocp;

Parser operator&(const Parser& lhs, const Parser& rhs)
{
    return [lhs, rhs](std::string_view input) -> Result
    {
        auto resultL = lhs(input);
        if (resultL.failure())
        {
            return std::move(resultL);
        }

        auto resultR = rhs(resultL.remaining());
        if (resultR.failure())
        {
            return std::move(resultR);
        }

        return makeSuccess<ResultT>(resultR.remaining());
    };
}

Parser operator|(const Parser& lhs, const Parser& rhs)
{
    return [lhs, rhs](std::string_view input) -> Result
    {
        auto resultL = lhs(input);
        if (resultL.success())
        {
            return std::move(resultL);
        }

        auto resultR = rhs(input);
        if (resultR.success())
        {
            return std::move(resultR);
        }

        return makeFailure<ResultT>(input, {});
    };
}

Parser opt(const Parser& parser)
{
    return [parser](std::string_view input) -> Result
    {
        auto result = parser(input);
        if (result.success())
        {
            return std::move(result);
        }

        return makeSuccess<ResultT>(input);
    };
}

Parser times(const Parser& parser, size_t min = 0, size_t max = 0)
{
    return [parser, min, max](std::string_view input) -> Result
    {
        auto matched = 0;
        auto remaining = input;

        do
        {
            auto result = parser(remaining);
            if (result.failure())
            {
                break;
            }

            remaining = result.remaining();
            ++matched;
        } while (matched < max | max == 0);

        if (matched < min)
        {
            return makeFailure<ResultT>(input, {});
        }

        return makeSuccess<ResultT>(remaining);
    };
}

Parser many(const Parser& parser)
{
    return times(parser);
}

Parser many1(const Parser& parser)
{
    return times(parser, 1);
}

Parser repeat(const Parser& parser, size_t count)
{
    return times(parser, count, count);
}

namespace basic
{
Parser any()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty())
        {
            return makeFailure<ResultT>(input, {});
        }

        return makeSuccess<ResultT>(input.substr(1));
    };
}

Parser char_(char c)
{
    return [c](std::string_view input) -> Result
    {
        if (input.empty() || input[0] != c)
        {
            return makeFailure<ResultT>(input, {});
        }

        return makeSuccess<ResultT>(input.substr(1));
    };
}

Parser digit()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty() || !std::isdigit(input[0]))
        {
            return makeFailure<ResultT>(input, {});
        }

        return makeSuccess<ResultT>(input.substr(1));
    };
}

Parser literal(const std::string lit)
{
    return [lit](std::string_view input) -> Result
    {
        if (input.empty() || input.substr(0, lit.size()) != lit)
        {
            return makeFailure<ResultT>(input, {});
        }

        return makeSuccess<ResultT>(input.substr(lit.size()));
    };
}
} // namespace basic
} // namespace syntaxc

namespace hlpc
{

using Mapper = std::function<void(base::Event)>;

struct SemToken
{
    Mapper mapper;
};

using SemParser = std::function<std::variant<SemToken, base::Error>(std::string_view)>;

struct SynToken
{
    std::string_view parsed;
    SemParser semParser;
};

using ResultT = SynToken;
using Result = pocp::Result<ResultT>;
using Parser = pocp::Parser<ResultT>;
using namespace pocp;

Parser operator&(const Parser& lhs, const Parser& rhs)
{
    return [lhs, rhs](std::string_view input) -> Result
    {
        auto resultL = lhs(input);
        if (resultL.failure())
        {
            return makeFailure<ResultT>(input, "&: lhs failed", std::move(resultL));
        }

        auto resultR = rhs(resultL.remaining());
        if (resultR.failure())
        {
            return makeFailure<ResultT>(input, "&: rhs failed", std::move(resultL), std::move(resultR));
        }

        return makeSuccess<ResultT>(resultR.remaining(), std::move(resultL), std::move(resultR));
    };
}

Parser times(const Parser& parser, size_t min = 0, size_t max = 0)
{
    return [parser, min, max](std::string_view input) -> Result
    {
        auto matched = 0;
        auto remaining = input;
        std::vector<Result> results;

        do
        {
            auto result = parser(remaining);
            if (result.failure())
            {
                break;
            }

            remaining = result.remaining();
            ++matched;
            results.emplace_back(std::move(result));
        } while (matched < max | max == 0);

        if (matched < min)
        {
            return makeFailure<ResultT>(input, "times: not enough matches", std::move(results));
        }

        return makeSuccess<ResultT>(remaining, std::move(results));
    };
}

Parser repeat(const Parser& parser, size_t count)
{
    return times(parser, count, count);
}

// Logpar combinators
Parser choice(const Parser& lhs, const Parser& rhs)
{
    return [lhs, rhs](std::string_view input) -> Result
    {
        auto resultL = lhs(input);
        if (resultL.success())
        {
            return std::move(resultL);
        }

        auto resultR = rhs(input);
        if (resultR.success())
        {
            return std::move(resultR);
        }

        return makeFailure<ResultT>(input, "choice: both failed");
    };
}

Parser opt(const Parser& parser)
{
    return [parser](std::string_view input) -> Result
    {
        auto result = parser(input);
        if (result.success())
        {
            return std::move(result);
        }

        return makeSuccess<ResultT>(input);
    };
}

Parser all(const std::vector<Parser>& parsers)
{
    return [parsers](std::string_view input) -> Result
    {
        auto remaining = input;
        Result::Nested results;

        for (const auto& parser : parsers)
        {
            auto result = parser(remaining);
            if (result.failure())
            {
                return std::move(result);
            }

            remaining = result.remaining();
            results.emplace_back(std::move(result));
        }

        return makeSuccess<ResultT>(remaining, std::move(results));
    };
}

// Logpar return function
using LogParser = std::function<std::optional<base::Error>(std::string_view, base::Event)>;
LogParser logparParser(const hlpc::Parser& parser)
{
    return [parser](std::string_view input, base::Event event) -> std::optional<base::Error>
    {
        // Syntax parsing
        auto result = parser(input);
        if (result.failure())
        {
            return base::Error {result.trace().data()};
        }

        // Semantinc parsing
        std::vector<hlpc::SemToken> semTokens;
        auto semVisitor = [&semTokens](const hlpc::Result& result, auto& recurRef) -> std::optional<base::Error>
        {
            if (result.hasValue())
            {
                auto res = result.value().semParser(result.value().parsed);
                if (std::holds_alternative<base::Error>(res))
                {
                    return std::get<base::Error>(res);
                }

                semTokens.emplace_back(std::get<hlpc::SemToken>(std::move(res)));
            }

            for (const auto& child : result.nested())
            {
                auto error = recurRef(child, recurRef);
                if (error)
                {
                    return std::move(error);
                }
            }

            return std::nullopt;
        };

        auto error = semVisitor(result, semVisitor);
        if (error)
        {
            return std::move(error);
        }

        // Mappings
        for (const auto& token : semTokens)
        {
            token.mapper(event);
        }

        return std::nullopt;
    };
}

} // namespace hlpc

namespace pocParsers
{
hlpc::Mapper mapperLiteral(std::string_view parsed, std::string_view targetField)
{
    return [parsed, targetField](base::Event event)
    {
        event->setString(parsed, targetField);
    };
}

hlpc::SemParser semLiteral(std::string_view parsed, hlpc::Mapper mapper)
{
    return [parsed, mapper](std::string_view)
    {
        return hlpc::SemToken {mapper};
    };
}

hlpc::Parser synLiteral(const std::string& literal, const std::string& name, const std::string& targetField)
{
    auto mapper = mapperLiteral(literal, targetField);
    auto semParser = semLiteral(literal, mapper);
    auto synParser = syntaxc::basic::literal(literal);

    return [synParser, semParser, name](std::string_view input) -> hlpc::Result
    {
        auto res = synParser(input);
        if (res.failure())
        {
            return pocp::makeFailure<hlpc::ResultT>(res.remaining(), name);
        }

        return pocp::makeSuccess(hlpc::SynToken {input.substr(0, input.size() - res.remaining().size()), semParser},
                           res.remaining());
    };
}

hlpc::SemParser semIp(std::string_view parsed, const std::string& targetField)
{
    return [mapper = mapperLiteral(parsed, targetField)](std::string_view parsed) -> std::variant<hlpc::SemToken, base::Error>
    {
        struct in_addr addr;
        const std::string parsedStr {parsed};
        if (inet_pton(AF_INET, parsedStr.c_str(), &addr) != 1)
        {
            return base::Error {"Invalid IP address"};
        }
        return hlpc::SemToken {mapper};
    };
}

hlpc::Parser ipParser(const std::string& name, const std::string& targetField)
{
    using namespace syntaxc;
    auto part = syntaxc::times(syntaxc::basic::digit(), 1, 3);
    auto sepPart = part & syntaxc::basic::char_('.');
    auto synParser = syntaxc::repeat(sepPart, 3) & part;

    return [synParser, name, targetField](std::string_view input) -> hlpc::Result
    {
        auto res = synParser(input);
        if (res.failure())
        {
            return makeFailure<hlpc::ResultT>(res.remaining(), name);
        }
        auto parsed = input.substr(0, input.size() - res.remaining().size());

        return makeSuccess(hlpc::SynToken {parsed, semIp(parsed, targetField)},
                           res.remaining());
    };
}

} // namespace pocParsers

#endif // _POC_PARSEC_HPP
