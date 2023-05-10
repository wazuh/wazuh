#include "hlp/logpar.hpp"

#include <list>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>
#include <hlp/parsec.hpp>

namespace parsec
{
std::size_t TraceP::s_order = 0;
}
namespace hlp::logpar::parser
{
parsec::Parser<char> pChar(std::string chars)
{
    return [=](const parsec::ParserState& state) -> parsec::ResultP<char>
    {
        auto retResult = parsec::ResultP<char>::failure(state);
        bool isRemaining = state.getRemainingSize() > 0;

        if (isRemaining)
        {
            const auto inputChar = state.getRemainingData()[0];
            if (chars.find(inputChar) != std::string::npos)
            {
                retResult.setSuccess(state.advance(1), char(inputChar));
            }
        }

        if (state.isTraceEnabled())
        {
            std::string trace = retResult.isSuccessful() ? "[success]" : "[failure]";
            trace += fmt::format(" pChar({}) -> ", chars);
            trace += isRemaining ? std::string {state.getRemainingData()[0]} : "EOF";
            retResult.concatenateTraces(trace);
        }

        return retResult;
    };
}

parsec::Parser<char> pNotChar(std::string chars)
{
    return [=](const parsec::ParserState& state) -> parsec::ResultP<char>
    {
        auto retResult = parsec::ResultP<char>::failure(state);
        bool isRemaining = state.getRemainingSize() > 0;

        if (isRemaining)
        {
            const auto inputChar = state.getRemainingData()[0];
            if (chars.find(inputChar) == std::string::npos)
            {
                retResult.setSuccess(state.advance(1), char(inputChar));
            }
        }

        if (state.isTraceEnabled())
        {
            std::string trace = retResult.isSuccessful() ? "[success]" : "[failure]";
            trace += fmt::format(" pNotChar({}) -> ", chars);
            trace += isRemaining ? std::string {state.getRemainingData()[0]} : "EOF";
            retResult.concatenateTraces(trace);
        }
        return retResult;
    };
}

parsec::Parser<char> pEscapedChar(std::string chars, char esc)
{
    return pChar(std::string {esc}) >> pChar(std::string {chars + esc});
}

parsec::Parser<std::string> pRawLiteral(std::string reservedChars, char esc)
{
    return parsec::fmap<std::string, parsec::Values<char>>(
        [=](parsec::Values<char> values)
        {
            std::string result {};
            for (auto c : values)
            {
                result += c;
            }
            return result;
        },
        parsec::many(pNotChar(reservedChars + esc) | pEscapedChar(reservedChars, esc)));
}

parsec::Parser<std::string> pRawLiteral1(std::string reservedChars, char esc)
{
    return parsec::fmap<std::string, parsec::Values<char>>(
        [=](parsec::Values<char> values)
        {
            std::string result {};
            for (auto c : values)
            {
                result += c;
            }
            return result;
        },
        parsec::many1(pNotChar(reservedChars + esc) | pEscapedChar(reservedChars, esc)));
}

parsec::Parser<char> pCharAlphaNum(std::string extended)
{
    return [=](const parsec::ParserState& state) -> parsec::ResultP<char>
    {
        auto retResult = parsec::ResultP<char>::failure(state);
        bool isRemaining = state.getRemainingSize() > 0;
        if (isRemaining)
        {
            const auto inputChar = state.getRemainingData()[0];
            if (std::isalnum(inputChar) || extended.find(inputChar) != std::string::npos)
            {
                retResult.setSuccess(state.advance(1), char(inputChar));
            }
        }

        if (state.isTraceEnabled())
        {
            std::string trace = retResult.isSuccessful() ? "[success]" : "[failure]";
            trace += fmt::format(" pCharAlphaNum({}) -> ", extended);
            trace += isRemaining ? std::string {state.getRemainingData()[0]} : "EOF";
            retResult.concatenateTraces(trace);
        }

        return retResult;
    };
}

parsec::Parser<parsec::Values<std::string>> pArgs()
{
    auto pArg =
        pChar({syntax::EXPR_ARG_SEP}) >> pRawLiteral({syntax::EXPR_ARG_SEP, syntax::EXPR_END}, {syntax::EXPR_ESCAPE});

    return parsec::many(pArg);
}

parsec::Parser<FieldName> pFieldName()
{
    parsec::Parser<std::string> pCustom = [](const parsec::ParserState& state) -> parsec::ResultP<std::string>
    {
        auto retResult = parsec::ResultP<std::string>::failure(state);
        bool isRemaining = state.getRemainingSize() > 0;

        if (isRemaining)
        {
            const auto inputChar = state.getRemainingData()[0];
            if (syntax::EXPR_CUSTOM_FIELD == inputChar)
            {
                retResult.setSuccess(state.advance(1), std::string {inputChar});
            }
            else
            {
                retResult.setSuccess(state, std::string {});
            }
        }

        if (state.isTraceEnabled())
        {
            std::string trace = retResult.isSuccessful() ? "[success]" : "[failure]";
            trace += fmt::format(" pCustom -> ");
            trace += isRemaining ? std::string {state.getRemainingData()[0]} : "EOF";
            retResult.concatenateTraces(trace);
        }

        return retResult;
    };

    std::string extendedChars = syntax::EXPR_FIELD_EXTENDED_CHARS;
    extendedChars += syntax::EXPR_FIELD_SEP;
    std::string extendedCharsFirst = syntax::EXPR_FIELD_EXTENDED_CHARS_FIRST;
    auto pName = parsec::fmap<std::string, std::tuple<char, parsec::Values<char>>>(
        [](auto t)
        {
            std::string result {};
            result.push_back(std::get<0>(t));
            for (auto c : std::get<1>(t))
            {
                result += c;
            }
            return result;
        },
        pCharAlphaNum(extendedCharsFirst) & parsec::many(pCharAlphaNum(extendedChars)));
    parsec::M<FieldName, std::string> m = [=](auto customS)
    {
        if (!customS.empty())
        {
            return parsec::fmap<FieldName, std::string>(
                [](auto s) {
                    return FieldName {s, true};
                },
                parsec::fmap<std::string, std::string>([=](auto s) { return customS + s; }, parsec::opt(pName)));
        }
        else
        {
            return parsec::fmap<FieldName, std::string>([](auto s) { return FieldName {s, false}; }, pName);
        }
    };

    return pCustom >>= m;
}

parsec::Parser<Field> pField()
{
    auto start = pChar({syntax::EXPR_BEGIN});
    auto end = pChar({syntax::EXPR_END});
    auto pField = parsec::fmap<Field, std::tuple<std::tuple<char, FieldName>, parsec::Values<std::string>>>(
        [](auto t)
        {
            const auto& [tInner, args] = t;
            const auto& [c, name] = tInner;
            return Field {name, args, c != '\0'};
        },
        (parsec::opt(pChar({syntax::EXPR_OPT})) & pFieldName()) & pArgs());
    return start >> pField << end;
}

parsec::Parser<Literal> pLiteral()
{
    std::string reservedLiteralChars {};
    reservedLiteralChars.push_back(syntax::EXPR_BEGIN);
    reservedLiteralChars.push_back(syntax::EXPR_OPT);
    reservedLiteralChars.push_back(syntax::EXPR_GROUP_BEGIN);
    reservedLiteralChars.push_back(syntax::EXPR_GROUP_END);

    return parsec::fmap<Literal, std::string>([](auto s) { return Literal {s}; },
                                              pRawLiteral1(reservedLiteralChars, {syntax::EXPR_ESCAPE}));
}

parsec::Parser<Choice> pChoice()
{
    auto p = (pField() << pChar({syntax::EXPR_OPT})) & pField();

    return [=](const parsec::ParserState& state)
    {
        auto res = p(state);
        auto retResult = parsec::ResultP<Choice>::failure(state);

        if (res.isSuccessful())
        {
            const auto [f1, f2] = res.popValue();

            if (!f1.optional && !f2.optional)
            {
                retResult.setSuccess(res.getParserState(), Choice {f1, f2});
            }

            if (state.isTraceEnabled())
            {
                retResult.concatenateTraces(std::move(res));
                std::string trace = retResult.isSuccessful() ? "[success]" : "[failure]";
                trace += fmt::format(" pChoice -> ({}) - ({})", f1.name.value, f2.name.value);
                if (f1.optional || f2.optional)
                {
                    trace += " expected: both fields to be non-optional";
                }
                retResult.concatenateTraces(trace);
            }
        }
        else if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(res)).concatenateTraces("[failure] pChoice failed");
        }

        return retResult;
    };
}

parsec::Parser<parsec::Values<ParserInfo>> pExpr()
{
    auto pF = parsec::fmap<ParserInfo, Field>([](auto f) { return ParserInfo {f}; }, pField());
    auto pL = parsec::fmap<ParserInfo, Literal>([](auto l) { return ParserInfo {l}; }, pLiteral());
    auto pC = parsec::fmap<ParserInfo, Choice>([](auto c) { return ParserInfo {c}; }, pChoice());

    auto pExpr = pC | pF | pL;
    return parsec::many1(pExpr);
}

namespace
{
parsec::ResultP<Group> pG(const parsec::ParserState& state)
{
    auto retResult = parsec::ResultP<Group>::failure(state);

    auto resStart = (pChar({syntax::EXPR_GROUP_BEGIN}) & pChar({syntax::EXPR_OPT}))(state);

    if (!resStart)
    {
        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resStart)).concatenateTraces("[failure] pG failed -> no start");
        }
        return retResult;
    }

    parsec::Parser<Group> pGfn = pG;
    auto pGmap =
        parsec::fmap<parsec::Values<ParserInfo>, Group>([](auto v) { return parsec::Values<ParserInfo> {v}; }, pGfn);
    auto pBody = parsec::fmap<parsec::Values<ParserInfo>, parsec::Values<parsec::Values<ParserInfo>>>(
        [](auto v)
        {
            parsec::Values<ParserInfo> merge {};
            for (auto& vv : v)
            {
                merge.splice(merge.end(), vv);
            }
            return merge;
        },
        parsec::many1(pExpr() | pGmap));

    auto resBody = pBody(resStart.getParserState());
    if (!resBody)
    {
        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resStart))
                .concatenateTraces(std::move(resBody))
                .concatenateTraces("[failure] pG failed -> no body");
        }
        return retResult;
    }

    auto resEnd = pChar({syntax::EXPR_GROUP_END})(resBody.getParserState());
    if (!resEnd)
    {
        if (state.isTraceEnabled())
        {
            retResult.concatenateTraces(std::move(resStart))
                .concatenateTraces(std::move(resBody))
                .concatenateTraces(std::move(resEnd))
                .concatenateTraces("[failure] pG failed -> no end");
        }
        return retResult;
    }

    return retResult.setSuccess(resEnd.getParserState(), Group {resBody.popValue()});
}
} // namespace

parsec::Parser<Group> pGroup()
{
    return [](const parsec::ParserState& state)
    {
        return pG(state);
    };
}

parsec::Parser<std::list<ParserInfo>> pLogpar()
{
    auto pE = pExpr();
    auto pG = pGroup();
    auto p = pE | parsec::fmap<std::list<ParserInfo>, Group>([](auto g) { return std::list<ParserInfo> {g}; }, pG);
    return parsec::fmap<std::list<ParserInfo>, parsec::Values<parsec::Values<ParserInfo>>>(
               [](auto v)
               {
                   std::list<ParserInfo> merged {};
                   for (auto& l : v)
                   {
                       merged.splice(merged.end(), l);
                   }
                   return merged;
               },
               parsec::many1(p))
           << pEof<std::list<ParserInfo>>();
}

// TODO add header and doc
parsec::MergeableParser<jFnList> pToMergeable(const parsec::Parser<jFnList>& p)
{

    parsec::MergeableParser<jFnList> mP = [p](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        auto result = parsec::MergeableResultP<jFnList>::failure(state);
        auto jResult = p(state);

        if (jResult.isSuccessful())
        {
            parsec::Mergeable<jFnList> value;
            value.m_result = jResult.popValue();
            value.m_tokens = {};
            value.m_mergeFunction = [](jFnList& dst, jFnList& src) -> void
            {
                dst.insert(dst.end(), std::make_move_iterator(src.begin()), std::make_move_iterator(src.end()));
            };
            value.m_semanticProcessor =
                [](jFnList& r,
                   const std::deque<std::string_view>& t,
                   const parsec::ParserState& s) -> std::pair<bool, std::optional<parsec::TraceP>>
            {
                return {true, std::nullopt};
            };

            result.setSuccess(jResult.getParserState(), std::move(value));
        }
        if (state.isTraceEnabled())
        {
            result.concatenateTraces(std::move(jResult));
        }

        return result;
    };

    return mP;
}

} // namespace hlp::logpar::parser

namespace hlp::logpar
{
Logpar::Logpar(const json::Json& ecsFieldTypes, size_t maxGroupRecursion, size_t debugLvl)
    : m_maxGroupRecursion(maxGroupRecursion)
    , m_debugLvl(debugLvl)
{
    if (!ecsFieldTypes.isObject())
    {
        // TODO: check message
        throw std::runtime_error("Configuration file must be an object");
    }

    if (!ecsFieldTypes.isObject("/fields"))
    {
        throw std::runtime_error("Configuration file must have a 'fields' object");
    }

    if (ecsFieldTypes.size() == 0)
    {
        // TODO: check message
        throw std::runtime_error("ECS field types must not be empty");
    }

    // Populate m_fieldTypes
    auto obj = ecsFieldTypes.getObject("/fields").value();
    for (const auto& [key, value] : obj)
    {
        if (!value.isString())
        {
            throw std::runtime_error(fmt::format("When loading logpar schema fields, field '{}' must "
                                                 "be a string with the name of the type",
                                                 key));
        }

        const auto schemaType = strToSchemaType(value.getString().value());
        if (schemaType == SchemaType::ERROR_TYPE)
        {
            throw std::runtime_error(fmt::format("When loading logpar schema fields, type '{}' in schema "
                                                 "field '{}' is not supported",
                                                 value.getString().value(),
                                                 key));
        }

        m_fieldTypes[key] = schemaType;
    }

    m_typeParsers = {
        // Numeric types
        {SchemaType::LONG, ParserType::P_LONG},
        {SchemaType::DOUBLE, ParserType::P_DOUBLE},
        {SchemaType::FLOAT, ParserType::P_FLOAT},
        {SchemaType::SCALED_FLOAT, ParserType::P_SCALED_FLOAT},
        {SchemaType::BYTE, ParserType::P_BYTE},
        // String types
        {SchemaType::KEYWORD, ParserType::P_TEXT},
        {SchemaType::TEXT, ParserType::P_TEXT},
        // Other types
        {SchemaType::BOOLEAN, ParserType::P_BOOL},
        {SchemaType::IP, ParserType::P_IP},
        {SchemaType::OBJECT, ParserType::P_TEXT},
        {SchemaType::GEO_POINT, ParserType::P_TEXT},
        {SchemaType::NESTED, ParserType::P_TEXT},
        {SchemaType::DATE, ParserType::P_DATE},
        // Special types, not in schema
        {SchemaType::USER_AGENT, ParserType::P_USER_AGENT},
        {SchemaType::URL, ParserType::P_URI},
    };

    m_parserBuilders = {};
}

parsec::MergeableParser<jFnList> Logpar::buildLiteralParser(const parser::Literal& literal) const
{
    if (m_parserBuilders.count(ParserType::P_LITERAL) == 0)
    {
        throw std::runtime_error(fmt::format("Parser type '{}' not found", parserTypeToStr(ParserType::P_LITERAL)));
    }

    ParserSpec spec {.m_name = literal.value, .m_args = {literal.value}, .m_capture = false};
    return m_parserBuilders.at(ParserType::P_LITERAL)(spec);
}

parsec::MergeableParser<jFnList> Logpar::buildFieldParser(const parser::Field& field,
                                                          std::deque<std::string> endTokens) const
{
    // Get type of the parser to be built
    ParserType type;
    std::vector<std::string> args(field.args.begin(), field.args.end());
    // Custom field
    if (field.name.custom)
    {
        // Custom fields use specified parser in args or text parser by default
        if (args.size() == 0)
        {
            type = ParserType::P_TEXT;
        }
        else
        {
            type = strToParserType(args.front());
            if (type == ParserType::ERROR_TYPE)
            {
                throw std::runtime_error(fmt::format("Parser type '{}' not found", field.args.front()));
            }
            args.erase(args.begin());
        }
    }
    // Schema field
    else
    {
        if (m_fieldTypes.count(field.name.value) == 0)
        {
            throw std::runtime_error(fmt::format("Field '{}' not found in schema", field.name.value));
        }

        const auto schemaType = m_fieldTypes.at(field.name.value);
        if (m_typeParsers.count(schemaType) == 0)
        {
            throw std::runtime_error(
                fmt::format("Parser type for ECS type '{}' not found", schemaTypeToStr(schemaType)));
        }

        type = m_typeParsers.at(schemaType);
    }

    if (m_parserBuilders.count(type) == 0)
    {
        throw std::runtime_error(fmt::format("Parser type '{}' not found", parserTypeToStr(type)));
    }

    // Get parser from type
    ParserSpec spec {
        .m_name = field.toStr(),
        .m_path = json::Json::formatJsonPath(field.name.value, true),
        .m_endTokens = endTokens,
        .m_args = args,
        .m_capture = (field.name.value == std::string {syntax::EXPR_CUSTOM_FIELD}),
    };
    parsec::MergeableParser<jFnList> ret = m_parserBuilders.at(type)(spec);

    // If field is optional, wrap in optional parser
    if (field.optional)
    {
        ret = parsec::opt(ret);
    }

    return ret;
}

parsec::MergeableParser<jFnList> Logpar::buildChoiceParser(const parser::Choice& choice,
                                                           std::deque<std::string> endTokens) const
{
    auto p1 = buildFieldParser(choice.left, endTokens);
    auto p2 = buildFieldParser(choice.right, endTokens);

    auto choiseParser = [p1, p2](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        auto result = parsec::MergeableResultP<jFnList>::failure(state);
        parsec::Mergeable<jFnList> value = {};

        auto parcialResult1 = p1(state);
        if (parcialResult1.isSuccessful())
        {
            auto mergeableP1 = parcialResult1.popValue();
            auto stateP1 = parcialResult1.getParserState();

            jFnList tmpValue = {};

            auto [success, trace] = mergeableP1.m_semanticProcessor(tmpValue, mergeableP1.m_tokens, stateP1);

            if (state.isTraceEnabled())
            {
                result.concatenateTraces("[success] Sintactic choice P1 ");
                result.concatenateTraces(std::move(parcialResult1));
                if (trace.has_value())
                {
                    result.concatenateTraces(std::move(trace.value()));
                }
                std::string trace = success ? "[success] Semantic choice P1" : "[failure] Semantic choice P1";
                result.concatenateTraces(trace);
            }

            if (success)
            {
                // if success, then tmpValue is valid and can be moved to value
                value.m_result = std::move(tmpValue);
                if (mergeableP1.m_mergeFunction.has_value())
                {
                    mergeableP1.m_mergeFunction.value()(value.m_result, mergeableP1.m_result);
                }
                result.setSuccess(stateP1, std::move(value));
                return result;
            }
        }

        if (state.isTraceEnabled())
        {
            result.concatenateTraces(std::move(parcialResult1));
            result.concatenateTraces("[failure] Sintactic choice P1 ");
        }

        auto parcialResult2 = p2(state);
        if (parcialResult2.isSuccessful())
        {
            auto mergeableP2 = parcialResult2.popValue();
            auto stateP2 = parcialResult2.getParserState();

            jFnList tmpValue = {};

            auto [success, trace] = mergeableP2.m_semanticProcessor(tmpValue, mergeableP2.m_tokens, stateP2);

            if (state.isTraceEnabled())
            {
                result.concatenateTraces("[success] Sintactic choice P2 ");
                result.concatenateTraces(std::move(parcialResult2));
                if (trace.has_value())
                {
                    result.concatenateTraces(std::move(trace.value()));
                }
                std::string trace = success ? "[success] Semantic choice P2" : "[failure] Semantic choice P2";
                result.concatenateTraces(trace);
            }

            if (success)
            {
                // if success, then tmpValue is valid and can be moved to value
                value.m_result = std::move(tmpValue);
                if (mergeableP2.m_mergeFunction.has_value())
                {
                    mergeableP2.m_mergeFunction.value()(value.m_result, mergeableP2.m_result);
                }
                result.setSuccess(stateP2, std::move(value));
                return result;
            }
        }

        if (state.isTraceEnabled())
        {
            result.concatenateTraces(std::move(parcialResult2));
            result.concatenateTraces("[failure] Sintactic choice P2");
        }

        return result;
    };
    return choiseParser;
}

parsec::MergeableParser<jFnList> Logpar::buildGroupOptParser(const parser::Group& group, size_t recurLvl) const
{
    auto p = buildParsers(group.children, recurLvl);
    auto mP = parser::pToMergeable(p);
    return parsec::opt(mP);
}

parsec::Parser<jFnList> Logpar::buildParsers(const std::list<parser::ParserInfo>& parserInfos, size_t recurLvl) const
{
    if (recurLvl > m_maxGroupRecursion)
    {
        throw std::runtime_error("Max group recursion level reached");
    }

    std::list<parsec::MergeableParser<jFnList>> parsers;
    for (auto parserInfo = parserInfos.begin(); parserInfo != parserInfos.end(); ++parserInfo)
    {
        auto groupEndToken = [](const parser::Group& group, auto& ref) -> std::deque<std::string>
        {
            auto it = group.children.cbegin();
            std::deque<std::string> endTokens;
            if (std::holds_alternative<parser::Literal>(*it))
            {
                endTokens.push_back(std::get<parser::Literal>(*it).value);
            }
            else if (std::holds_alternative<parser::Group>(*it))
            {
                // If a group is the first element of a group, then resolve its end token
                // recursively and ensure there is a literal after any succesion of groups
                // and each group can resolve its end token
                std::deque<std::string> insideTokens;

                while (it != group.children.cend() && std::holds_alternative<parser::Group>(*it))
                {
                    insideTokens.insert(insideTokens.end(),
                                        ref(std::get<parser::Group>(*it), ref).begin(),
                                        ref(std::get<parser::Group>(*it), ref).end());
                    it = std::next(it);
                }
                if (std::holds_alternative<parser::Literal>(*it))
                {
                    insideTokens.push_back(std::get<parser::Literal>(*it).value);
                }
                else
                {
                    throw std::runtime_error("Group must be followed by a literal");
                }

                endTokens.insert(endTokens.end(), insideTokens.begin(), insideTokens.end());
            }
            else
            {
                throw std::runtime_error("Group must start with a literal or a "
                                         "succession of groups and a literal");
            }

            return endTokens;
        };

        // Get end token from next parser info if it exists
        // If no next, end token is end of line ("")
        // If next is literal, use its value as end token
        // If next is group, resolve its end token/s and get the end token/s after the
        // group/s
        // If next is none of the above, no end token is used (empty list)
        auto getEndToken = [&](const std::list<parser::ParserInfo>& infos,
                               decltype(infos.begin()) it,
                               auto& ref) -> std::deque<std::string>
        {
            std::deque<std::string> endTokens {};
            auto next = std::next(it);
            if (next == infos.end())
            {
                // EOF endToken nomenclature
                endTokens.push_back("");
            }
            else if (std::holds_alternative<parser::Literal>(*next))
            {
                endTokens.push_back(std::get<parser::Literal>(*next).value);
            }
            else if (std::holds_alternative<parser::Group>(*next))
            {
                std::deque<std::string> afterTokens;
                std::deque<std::string> insideTokens;

                // Recursively get end token after the group
                afterTokens = ref(infos, next, ref);

                // if we have end tokens require inside token on the group
                if (!afterTokens.empty())
                {
                    auto group = std::get<parser::Group>(*next);
                    // Throws on errors
                    insideTokens = groupEndToken(group, groupEndToken);

                    endTokens.insert(endTokens.end(), insideTokens.begin(), insideTokens.end());
                    endTokens.insert(endTokens.end(), afterTokens.begin(), afterTokens.end());
                }
            }

            return endTokens;
        };

        // Call specific parser builder based on parser info type
        // Field
        if (std::holds_alternative<parser::Field>(*parserInfo))
        {
            // If the field is followed by a group, make a choice between the field, and
            // the field and group
            auto next = std::next(parserInfo);
            if (next != parserInfos.end() && std::holds_alternative<parser::Group>(*next))
            {
                auto group = std::get<parser::Group>(*next);
                auto endTokens = groupEndToken(group, groupEndToken);

                // Dependendant of recursion allowed, as for now we only allow one
                auto pF = buildFieldParser(std::get<parser::Field>(*parserInfo), {endTokens.front()});
                auto pGBuilded = buildParsers(group.children, recurLvl + 1);
                auto pG = parser::pToMergeable(pGBuilded);

                auto choice1 = parsec::andMergeable(pF, pG);
                auto endToken2 = getEndToken(parserInfos, next, getEndToken);
                auto choice2 = buildFieldParser(std::get<parser::Field>(*parserInfo), endToken2);

                parsers.push_back(choice1 | choice2);
                // Skip group
                ++parserInfo;
                continue;
            }

            // Normal case
            std::deque<std::string> endTokens = getEndToken(parserInfos, parserInfo, getEndToken);

            parsers.push_back(buildFieldParser(std::get<parser::Field>(*parserInfo), endTokens));
        }
        // Literal
        else if (std::holds_alternative<parser::Literal>(*parserInfo))
        {
            parsers.push_back(buildLiteralParser(std::get<parser::Literal>(*parserInfo)));
        }
        // Choice
        else if (std::holds_alternative<parser::Choice>(*parserInfo))
        {
            std::deque<std::string> endTokens = getEndToken(parserInfos, parserInfo, getEndToken);

            parsers.push_back(buildChoiceParser(std::get<parser::Choice>(*parserInfo), endTokens));
        }
        // Group
        else if (std::holds_alternative<parser::Group>(*parserInfo))
        {
            // Check that there are no more than recurLvl groups in a row
            auto it = parserInfo;
            size_t groupCount = 0;
            while (it != parserInfos.end() && std::holds_alternative<parser::Group>(*it))
            {
                groupCount++;
                it = std::next(it);
            }
            if (groupCount > m_maxGroupRecursion)
            {
                throw std::runtime_error("Max group recursion level reached");
            }

            // Recursively calls buildParsers
            parsers.push_back(buildGroupOptParser(std::get<parser::Group>(*parserInfo), recurLvl + 1));
        }
        else
        {
            throw std::runtime_error("Unknown parser info type");
        }
    }

    // return parsers;
    return parsec::merge<jFnList>(parsers);
}

void Logpar::registerBuilder(ParserType type, ParserBuilder builder)
{
    if (m_parserBuilders.count(type) != 0)
    {
        throw std::runtime_error(fmt::format("Parser type '{}' already registered", parserTypeToStr(type)));
    }

    m_parserBuilders[type] = builder;
}

parsec::Parser<jFnList> Logpar::build(std::string_view logpar) const
{
    auto parserSate = parsec::ParserState(logpar, true);
    auto result = parser::pLogpar()(parserSate);

    if (!result)
    {
        if (result.hasTraces())
        {
            auto traces = result.popTraces();
            // Order traces by order
            traces.sort([](const auto& a, const auto& b) -> bool { return a.getOrder() < b.getOrder(); });

            std::string msg;

            // concatenate traces messages
            for (const auto& t : traces)
            {
                msg += std::to_string(t.getOrder()) + ": ";
                msg += "| offset: " + std::to_string(t.getOffset()) + " | ";
                msg += t.getMessage() + "\n";
            }
            throw std::runtime_error(msg);
        }
        throw std::runtime_error("Unknown error, no traces");
    }

    auto parserInfos = result.popValue();
    auto p = buildParsers(parserInfos, 0);
    return p << parser::pEof<jFnList>(); // TODO Add to mergeable sintactic parse
}

} // namespace hlp::logpar
