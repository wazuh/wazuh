#include <functional>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <iostream>

#include "baseTypes.hpp"
#include <json/json.hpp>

// using Mapper = std::function<void(Event)>;

// struct SemToken
// {
//     Mapper m_mapper;
// };

// using SemResult = std::variant<SemToken, base::Error>;
// using SemParser = std::function<SemResult(std::string_view)>;

// class SynResult
// {
// private:
//     std::string_view m_parsed;
//     SemParser m_semParser;

//     std::string_view m_remaining;
//     std::string_view m_name;
//     bool m_success;
//     bool m_hasValue;

// public:
//     SynResult() = default;
//     ~SynResult() = default;

//     SynResult(std::string_view m_parsed,
//               SemParser&& semParser,
//               std::string_view remaining,
//               bool success,
//               std::string_view name)
//         : m_parsed(m_parsed)
//         , m_semParser(std::move(semParser))
//         , m_hasValue(true)
//         , m_remaining(remaining)
//         , m_success(success)
//         , m_name(name)
//     {
//     }

//     SynResult(std::string_view remaining, bool success, std::string_view name)
//         : m_hasValue(false)
//         , m_remaining(remaining)
//         , m_success(success)
//         , m_name(name)
//     {
//     }

//     SynResult(const Result& other)
//         : m_parsed(other.m_parsed)
//         , m_semParser(other.m_semParser)
//         , m_hasValue(other.m_hasValue)
//         , m_remaining(other.m_remaining)
//         , m_success(other.m_success)
//         , m_name(other.m_name)
//     {
//     }

//     SynResult(Result&& other) noexcept
//         : m_parsed(std::move(other.m_parsed))
//         , m_semParser(std::move(other.m_semParser))
//         , m_hasValue(std::move(other.m_hasValue))
//         , m_remaining(std::move(other.m_remaining))
//         , m_success(std::move(other.m_success))
//         , m_name(std::move(other.m_name))
//     {
//     }

//     bool success() const { return m_success; }
//     bool failure() const { return !m_success; }

//     std::string_view remaining() const { return m_remaining; }

//     bool hasValue() const { return m_hasValue; }
//     std::string_view parsed() const { return m_parsed; }
//     const SemParser& semParser() const { return m_semParser; }

//     std::string_view name() const { return m_name; }
// };

// using SynParser = std::function<SynResult(std::string_view)>;
// using SynList = std::vector<SynResult>;

// SynResult synSuccess(std::string_view remaining, std::string_view name);
// {
//     return SynResult(remaining, true, name);
// }
// SynResult synSuccess(std::string_view parsed, SemParser&& semParser, std::string_view remaining, std::string_view name)
// {
//     return SynResult(parsed, std::move(semParser), remaining, true, name);
// }
// SynResult synFailure(std::string_view remaining, std::string_view name)
// {
//     return SynResult(remaining, false, name);
// }


// class SynProcessor
// {
// private:
//     std::vector<SynParser> m_parsers;

// public:
//     SynProcessor() = default;
//     ~SynProcessor() = default;

//     void add(SynParser&& parser) { m_parsers.emplace_back(std::move(parser)); }

//     void add(SynProcessor&& processor)
//     {
//         m_parsers.insert(m_parsers.end(),
//                          std::make_move_iterator(processor.m_parsers.begin()),
//                          std::make_move_iterator(processor.m_parsers.end()));
//         processor.m_parsers.clear();
//     }

//     std::variant<SynList, SynResult> operator()(std::string_view input) const
//     {
//         SynList results {};
//         auto remaining = input;
//         for (const auto& parser : m_parsers)
//         {
//             auto result = parser(remaining);
//             if (result.failure())
//             {
//                 return std::move(result);
//             }

//             if (result.hasValue())
//             {
//                 results.emplace_back(std::move(result));
//             }

//             remaining = result.remaining();
//         }

//         return std::move(results);
//     }
// };

// SynParser opt(SynParser&& parser)
// {

//     return [parser = std::move(parser)](std::string_view input)
//     {
//         auto result = parser(input);
//         if (result.failure())
//         {
//             return synSuccess(input, "optional");
//         }

//         return std::move(result);
//     };
// }



// SynParser choice(SynParser&& parser1, SynParser&& parser2)
// {
//     return [parser1 = std::move(parser1), parser2 = std::move(parser2)](std::string_view input)
//     {
//         auto result = parser1(input);
//         if (result.success())
//         {
//             return std::move(result);
//         }

//         return parser2(input);
//     };
// }

// using SemList = std::vector<SemToken>;

// std::variant<SemList, base::Error> semProcessor(const SynList& synResults)
// {
//     SemList results {};
//     for (const auto& synResult : synResults)
//     {
//         auto semResult = synResult.semParser()(synResult.parsed());
//         if (std::holds_alternative<base::Error>(semResult))
//         {
//             return std::get<base::Error>(std::move(semResult));
//         }

//         results.emplace_back(std::get<SemToken>(std::move(semResult)));
//     }

//     return std::move(results);
// }

// void mapProcessor(const SemList& semResults, base::Event event)
// {
//     for (const auto& semResult : semResults)
//     {
//         semResult.m_mapper(event);
//     }
// }
