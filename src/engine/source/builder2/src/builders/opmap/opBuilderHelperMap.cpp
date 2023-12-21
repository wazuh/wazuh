#include "opBuilderHelperMap.hpp"

#include <algorithm>
#include <chrono>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <date/date.h>
#include <date/tz.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <re2/re2.h>

#include <utils/ipUtils.hpp>
#include <utils/stringUtils.hpp>

#include "syntax.hpp"

namespace
{

using namespace builder::builders;

constexpr auto TRACE_SUCCESS = "[{}] -> Success";

constexpr auto TRACE_TARGET_NOT_FOUND = "[{}] -> Failure: Target field '{}' reference not found";
constexpr auto TRACE_TARGET_TYPE_NOT_STRING = "[{}] -> Failure: Target field '{}' type is not string";
constexpr auto TRACE_REFERENCE_NOT_FOUND = "[{}] -> Failure: Parameter '{}' reference not found";
constexpr auto TRACE_REFERENCE_TYPE_IS_NOT = "[{}] -> Failure: Parameter '{}' type is not ";

/**
 * @brief Operators supported by the string helpers.
 *
 */
enum class StringOperator
{
    UP,
    LO,
    TR
};

/**
 * @brief Operators supported by the int helpers.
 *
 */
enum class IntOperator
{
    SUM,
    SUB,
    MUL,
    DIV
};

IntOperator strToOp(const std::string& op)
{
    if ("sum" == op)
    {
        return IntOperator::SUM;
    }
    else if ("sub" == op)
    {
        return IntOperator::SUB;
    }
    else if ("mul" == op)
    {
        return IntOperator::MUL;
    }
    else if ("div" == op)
    {
        return IntOperator::DIV;
    }
    throw std::runtime_error(fmt::format("Operation '{}' not supported", op));
}

/**
 * @brief Tranform the string in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param definition The transformation definition. i.e : field: +s_[up|lo]/value|$ref
 * @param op The operator to use:
 * - `UP`: Upper case
 * - `LO`: Lower case
 * @return base::Expression
 */
MapOp opBuilderHelperStringTransformation(const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx,
                                          StringOperator op)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    const auto& rightParameter = opArgs[0];

    // Depending on the operator we return the correct function
    std::function<std::string(const std::string& value)> transformFunction;
    switch (op)
    {
        case StringOperator::UP:
            transformFunction = [](const std::string& value)
            {
                std::string result;
                std::transform(value.begin(), value.end(), std::back_inserter(result), ::toupper);
                return result;
            };
            break;
        case StringOperator::LO:
            transformFunction = [](const std::string& value)
            {
                std::string result;
                std::transform(value.begin(), value.end(), std::back_inserter(result), ::tolower);
                return result;
            };
            break;
        default: break;
    }

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Reference not found", name)};

    // Function that implements the helper
    return [=](base::ConstEvent event) -> MapResult
    {
        // We assert that references exists, checking if the optional from Json getter
        // is empty ot not. Then if is a reference we get the value from the event,
        // otherwise we get the value from the parameter

        // REF

        if (rightParameter->isReference())
        {
            const auto resolvedRValue {
                event->getString(std::static_pointer_cast<Reference>(rightParameter)->jsonPath())};

            if (!resolvedRValue.has_value())
            {
                return base::result::makeFailure(json::Json {}, failureTrace1);
            }
            else
            {
                // TODO: should we check the result?
                auto res {transformFunction(resolvedRValue.value())};
                json::Json result;
                result.setString(res);
                return base::result::makeSuccess(std::move(result), successTrace);
            }
        }
        else
        {
            // TODO: should we check the result?
            const auto res {
                transformFunction(std::static_pointer_cast<Value>(rightParameter)->value().getString().value())};
            json::Json result;
            result.setString(res);
            return base::result::makeSuccess(std::move(result), successTrace);
        }
    };
}

/**
 * @brief Tranform the int in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param definition The transformation definition. i.e :
 * +int_calculate/[+|-|*|/]/<val1|$ref1>/<.../valN|$refN>/
 * @param op The operator to use:
 * - `SUM`: Sum
 * - `SUB`: Subtract
 * - `MUL`: Multiply
 * - `DIV`: Divide
 * @return base::Expression
 */
MapOp opBuilderHelperIntTransformation(IntOperator op,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    std::vector<int64_t> rValueVector {};
    std::vector<std::string> rReferenceVector {};

    const auto name = buildCtx->context().opName;

    // Depending on rValue type we store the reference or the integer value, avoiding
    // iterating again through values inside lambda
    for (const auto& arg : opArgs)
    {
        int64_t rValue {};
        if (arg->isValue())
        {
            const auto& asValue = std::static_pointer_cast<Value>(arg);
            if (!asValue->value().isInt64())
            {
                throw std::runtime_error(
                    fmt::format("Expected 'int64_t' parameter but got type '{}'", asValue->value().typeName()));
            }

            rValue = asValue->value().getIntAsInt64().value();

            if (IntOperator::DIV == op && 0 == rValue)
            {
                throw std::runtime_error(fmt::format("\"{}\" function: Division by zero", name));
            }

            rValueVector.emplace_back(rValue);
        }
        else
        {
            rReferenceVector.emplace_back(std::static_pointer_cast<Reference>(arg)->jsonPath());
        }
    }
    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace2 {fmt::format(R"([{}] -> Failure: Reference not found: )", name)};
    const std::string failureTrace3 {fmt::format(R"([{}] -> Failure: Parameter is not integer: )", name)};
    const std::string failureTrace4 = fmt::format(R"([{}] -> Failure: Parameter value makes division by zero: )", name);
    const std::string overflowFailureTrace =
        fmt::format(R"([{}] -> Failure: operation result in integer Overflown)", name);
    const std::string underflowFailureTrace =
        fmt::format(R"([{}] -> Failure: operation result in integer Underflown)", name);

    // Depending on the operator we return the correct function
    std::function<int64_t(int64_t l, int64_t r)> transformFunction;
    int64_t startValue;
    switch (op)
    {
        case IntOperator::SUM:
            startValue = 0;
            transformFunction = [overflowFailureTrace, underflowFailureTrace](int64_t l, int64_t r)
            {
                if ((r > 0) && (l > std::numeric_limits<int64_t>::max() - r))
                {
                    throw std::runtime_error(overflowFailureTrace);
                }
                else if ((r < 0) && (l < std::numeric_limits<int64_t>::min() - r))
                {
                    throw std::runtime_error(underflowFailureTrace);
                }
                else
                {
                    return l + r;
                }
            };
            break;
        case IntOperator::SUB:
            startValue = 0;
            transformFunction = [overflowFailureTrace, underflowFailureTrace](int64_t l, int64_t r)
            {
                if ((r < 0) && (l > std::numeric_limits<int64_t>::max() + r))
                {
                    throw std::runtime_error(overflowFailureTrace);
                }
                else if ((r > 0) && (l < std::numeric_limits<int64_t>::min() + r))
                {
                    throw std::runtime_error(underflowFailureTrace);
                }
                else
                {
                    return l - r;
                }
            };
            break;
        case IntOperator::MUL:
            startValue = 1;
            transformFunction = [overflowFailureTrace, underflowFailureTrace](int64_t l, int64_t r)
            {
                if ((r != 0) && (l > std::numeric_limits<int64_t>::max() / r))
                {
                    throw std::runtime_error(overflowFailureTrace);
                }
                else if ((r != 0) && (l < std::numeric_limits<int64_t>::min() * r))
                {
                    throw std::runtime_error(underflowFailureTrace);
                }
                else
                {
                    return l * r;
                }
            };
            break;
        case IntOperator::DIV:
            startValue = 1;
            transformFunction = [name, overflowFailureTrace, underflowFailureTrace](int64_t l, int64_t r)
            {
                if (0 == r)
                {
                    throw std::runtime_error(fmt::format(R"("{}" function: Division by zero)", name));
                }
                else
                {
                    return l / r;
                }
            };
            break;
        default: break;
    }

    // Function that implements the helper
    return [=, rValueVector = std::move(rValueVector), rReferenceVector = std::move(rReferenceVector)](
               base::ConstEvent event) -> MapResult
    {
        std::vector<int64_t> auxVector {};
        auxVector.insert(auxVector.begin(), rValueVector.begin(), rValueVector.end());

        // Iterate throug all references and append them values to the value vector
        for (const auto& rValueItem : rReferenceVector)
        {
            const auto resolvedRValue {event->getIntAsInt64(rValueItem)};
            if (!resolvedRValue.has_value())
            {
                return base::result::makeFailure(json::Json {},
                                                 (!event->exists(rValueItem)) ? (failureTrace2 + rValueItem)
                                                                              : (failureTrace3 + rValueItem));
            }
            else
            {
                if (IntOperator::DIV == op && 0 == resolvedRValue.value())
                {
                    return base::result::makeFailure(json::Json {}, failureTrace4 + rValueItem);
                }

                auxVector.emplace_back(resolvedRValue.value());
            }
        }

        int64_t res;
        try
        {
            res = std::accumulate(auxVector.begin(), auxVector.end(), startValue, transformFunction);
        }
        catch (const std::runtime_error& e)
        {
            return base::result::makeFailure(json::Json {}, e.what());
        }

        json::Json result;
        result.setInt64(res);
        return base::result::makeSuccess(result, successTrace);
    };
}

std::optional<std::string> hashStringSHA1(std::string& input)
{
    // Sha1 digest len (20) * 2 (hex chars per byte)
    constexpr int OS_SHA1_HEXDIGEST_SIZE = (SHA_DIGEST_LENGTH * 2);
    constexpr int OS_SHA1_ARRAY_SIZE_LEN = OS_SHA1_HEXDIGEST_SIZE + 1;

    char* parameter = nullptr;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (!ctx)
    {
        // Failed during hash context creation
        return std::nullopt;
    }

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr))
    {
        // Failed during hash context initialization
        EVP_MD_CTX_destroy(ctx);
        return std::nullopt;
    }

    if (1 != EVP_DigestUpdate(ctx, input.c_str(), input.length()))
    {
        // Failed during hash context update
        return std::nullopt;
    }

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);

    // OS_SHA1_Hexdigest(digest, hexdigest);
    char output[OS_SHA1_ARRAY_SIZE_LEN];
    for (size_t n = 0; n < SHA_DIGEST_LENGTH; n++)
    {
        sprintf(&output[n * 2], "%02x", digest[n]);
    }

    return {output};
}

} // namespace

namespace builder::builders
{

//*************************************************
//*           String tranform                     *
//*************************************************

// field: +upcase/value|$ref
MapOp opBuilderHelperStringUP(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderHelperStringTransformation(opArgs, buildCtx, StringOperator::UP);
    return op;
}

// field: +downcase/value|$ref
MapOp opBuilderHelperStringLO(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderHelperStringTransformation(opArgs, buildCtx, StringOperator::LO);
    return op;
}

// field: +trim/[begin | end | both]/char
TransformOp opBuilderHelperStringTrim(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2);
    // Parameter type check
    builder::builders::utils::assertValue(opArgs);

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Get trim type
    auto trimParam = std::static_pointer_cast<Value>(opArgs[0])->value().getString();
    if (!trimParam)
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }

    const char trimType = trimParam.value() == "begin"  ? 's'
                          : trimParam.value() == "end"  ? 'e'
                          : trimParam.value() == "both" ? 'b'
                                                        : '\0';
    if ('\0' == trimType)
    {
        throw std::runtime_error(fmt::format("\"{}\" function: Invalid trim type \"{}\"", name, trimParam.value()));
    }

    // get trim char
    auto trimCharResp = std::static_pointer_cast<Value>(opArgs[1])->value().getString();
    if (!trimCharResp)
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().typeName()));
    }
    std::string trimChar {trimCharResp.value()};
    if (trimChar.size() != 1)
    {
        throw std::runtime_error(fmt::format("'{}' function: Invalid trim char '{}'", name, trimChar));
    }

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_TYPE_NOT_STRING, name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Invalid trim type '{}'", name, trimType)};

    // Return Op
    return [=, targetField = targetField.jsonPath()](const base::Event& event) -> TransformResult
    {
        // Get field value
        auto resolvedField {event->getString(targetField)};

        // Check if field is a string
        if (!resolvedField.has_value())
        {
            return base::result::makeFailure(event, (!event->exists(targetField)) ? failureTrace1 : failureTrace2);
        }

        // Get string
        std::string strToTrim {resolvedField.value()};

        // Trim
        switch (trimType)
        {
            case 's':
                // Trim begin
                strToTrim.erase(0, strToTrim.find_first_not_of(trimChar));
                break;
            case 'e':
                // Trim end
                strToTrim.erase(strToTrim.find_last_not_of(trimChar) + 1);
                break;
            case 'b':
                // Trim both
                strToTrim.erase(0, strToTrim.find_first_not_of(trimChar));
                strToTrim.erase(strToTrim.find_last_not_of(trimChar) + 1);
                break;
            default: return base::result::makeFailure(event, failureTrace3); break;
        }

        event->setString(strToTrim, targetField);

        return base::result::makeSuccess(event, successTrace);
    };
}

// field: +concat/string1|$ref1/string2|$ref2
MapOp opBuilderHelperStringConcat(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2, builder::builders::utils::MAX_OP_ARGS);
    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    for (const auto& arg : opArgs)
    {
        if (arg->isValue())
        {
            const auto& asValue = std::static_pointer_cast<Value>(arg);
            if (!asValue->value().isString())
            {
                throw std::runtime_error(
                    fmt::format("Expected 'string' parameter but got type '{}'", asValue->value().typeName()));
            }
        }
    }

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format("{} -> Failure: ", name)};
    const std::string failureTrace2 {fmt::format("{} -> Failure: ", name)};

    // Return Op
    return [=](base::ConstEvent event) -> MapResult
    {
        std::string result {};

        for (const auto& arg : opArgs)
        {
            if (arg->isReference())
            {
                // Check path exists
                const auto& ref = std::static_pointer_cast<Reference>(arg)->jsonPath();
                if (!event->exists(ref))
                {
                    return base::result::makeFailure(json::Json {},
                                                     failureTrace1 + fmt::format("Reference '{}' not found", ref));
                }

                // Get field value
                std::string resolvedField {};
                if (event->isDouble(ref))
                {
                    resolvedField = std::to_string(event->getDouble(ref).value());
                }
                else if (event->isInt64(ref))
                {
                    resolvedField = std::to_string(event->getIntAsInt64(ref).value());
                }
                else if (event->isString(ref))
                {
                    resolvedField = event->getString(ref).value();
                }
                else if (event->isObject(ref))
                {
                    resolvedField = event->str(ref).value();
                }
                else
                {
                    return base::result::makeFailure(
                        json::Json {}, failureTrace2 + fmt::format("Parameter '{}' type cannot be handled", ref));
                }

                result.append(resolvedField);
            }
            else
            {
                const auto& value = std::static_pointer_cast<Value>(arg)->value().getString().value();
                result.append(value);
            }
        }
        json::Json resultJson;
        resultJson.setString(result);
        return base::result::makeSuccess(resultJson, successTrace);
    };
}

// field: +join/$<array_reference1>/<separator>
MapOp opBuilderHelperStringFromArray(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2);

    // Check Array reference parameter
    builder::builders::utils::assertRef(opArgs, 0);
    const auto arrayRef = *std::static_pointer_cast<Reference>(opArgs[0]);

    // Check separator parameter
    builder::builders::utils::assertValue(opArgs, 1);
    if (!std::static_pointer_cast<Value>(opArgs[1])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().typeName()));
    }
    const auto separator = std::static_pointer_cast<Value>(opArgs[1])->value().getString().value();

    const std::string traceName = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Array member from '{}' should be a string", traceName, arrayRef.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, arrayRef.dotPath())};
    const std::string failureTrace3 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "array", traceName, arrayRef.dotPath())};

    // Return Op
    return [=, arrayName = arrayRef.jsonPath()](base::ConstEvent event) -> MapResult
    {
        // Getting array field, must be a reference
        const auto stringJsonArray = event->getArray(arrayName);
        if (!stringJsonArray.has_value())
        {
            return base::result::makeFailure(json::Json {},
                                             (!event->exists(arrayName)) ? failureTrace2 : failureTrace3);
        }

        std::vector<std::string> stringArray;
        for (const auto& s_param : stringJsonArray.value())
        {
            if (s_param.isString())
            {
                const auto strVal = s_param.getString().value();
                stringArray.emplace_back(std::move(strVal));
            }
            else
            {
                return base::result::makeFailure(json::Json {}, failureTrace1);
            }
        }

        // accumulated concation without trailing indexes
        const std::string composedValueString {base::utils::string::join(stringArray, separator)};

        json::Json result;
        result.setString(composedValueString);
        return base::result::makeSuccess(result, successTrace);
    };
}

// field: +decode_base16/$<hex_reference>
MapOp opBuilderHelperStringFromHexa(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    // Check Array reference parameter
    builder::builders::utils::assertRef(opArgs);

    const auto hexRef = *std::static_pointer_cast<Reference>(opArgs[0]);
    const std::string traceName = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, hexRef.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "array", traceName, hexRef.dotPath())};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Hexa string has not an even quantity of digits", traceName)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: ", traceName)};

    // Return Op
    return [=, sourceField = hexRef.jsonPath()](base::ConstEvent event) -> MapResult
    {
        std::string strHex {};

        // Getting string field from a reference
        const auto refStrHEX = event->getString(sourceField);
        if (!refStrHEX.has_value())
        {
            return base::result::makeFailure(json::Json {},
                                             (!event->exists(sourceField)) ? failureTrace1 : failureTrace2);
        }

        strHex = refStrHEX.value();

        const auto lenHex = strHex.length();

        if (lenHex % 2)
        {
            return base::result::makeFailure(json::Json {}, failureTrace3);
        }

        std::string strASCII {};
        strASCII.resize((lenHex / 2) + 1);

        for (int iHex = 0, iASCII = 0; iHex < lenHex; iHex += 2, iASCII++)
        {
            char* err = nullptr;

            std::string byte = strHex.substr(iHex, 2);
            char chr = (char)strtol(byte.c_str(), &err, 16); // BASE: 16 (Hexa)

            if (err != nullptr && *err != 0)
            {
                return base::result::makeFailure(
                    json::Json {}, failureTrace4 + fmt::format("Character '{}' is not a valid hexa digit", err));
            }

            strASCII[iASCII] = chr;
        }

        json::Json result;
        result.setString(strASCII);

        return base::result::makeSuccess(result, successTrace);
    };
}

// field: +hex_to_number/$ref
MapOp opBuilderHelperHexToNumber(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    // Check Array reference parameter
    builder::builders::utils::assertRef(opArgs);

    const auto hexRef = *std::static_pointer_cast<Reference>(opArgs[0]);
    const std::string traceName = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, hexRef.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", traceName, hexRef.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: ", traceName)};

    // Return Op
    return [=, sourceField = hexRef.jsonPath()](base::ConstEvent event) -> MapResult
    {
        // Getting string field from a reference
        const auto refStrHEX = event->getString(sourceField);
        if (!refStrHEX.has_value())
        {
            return base::result::makeFailure(
                json::Json {}, fmt::format((!event->exists(sourceField)) ? failureTrace1 : failureTrace2, sourceField));
        }
        std::stringstream ss;
        ss << refStrHEX.value();
        int result;
        ss >> std::hex >> result;
        if (ss.fail() || !ss.eof())
        {
            return base::result::makeFailure(
                json::Json {},
                failureTrace3 + fmt::format("String '{}' is not a hexadecimal value", refStrHEX.value()));
        }

        json::Json resultJson;
        resultJson.setInt64(result);
        return base::result::makeSuccess(resultJson, successTrace);
    };
}

// field: +replace/substring/new_substring
TransformOp opBuilderHelperStringReplace(const Reference& targetField,
                                         const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2);
    builder::builders::utils::assertValue(opArgs);
    for (const auto& arg : opArgs)
    {
        if (arg->isValue())
        {
            const auto& asValue = std::static_pointer_cast<Value>(arg);
            if (!asValue->value().isString())
            {
                throw std::runtime_error(
                    fmt::format("Expected 'string' parameter but got type '{}'", asValue->value().typeName()));
            }
        }
    }

    // If firts argument is a Value it cannot be empty
    if (opArgs[0]->isValue() && std::static_pointer_cast<Value>(opArgs[0])->value().getString().value().empty())
    {
        throw std::runtime_error("First argument cannot be an empty string");
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    const auto oldSubstr = opArgs[0];
    const auto newSubstr = opArgs[1];

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_TYPE_NOT_STRING, name, targetField.dotPath())};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Target field '{}' is empty", name, targetField.dotPath())};

    // Return Op
    return [=, targetField = targetField.jsonPath()](const base::Event& event) -> TransformResult
    {
        if (!event->exists(targetField))
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        // Get field value
        std::optional<std::string> resolvedField {event->getString(targetField)};

        // Check if field is a string
        if (!resolvedField.has_value())
        {
            return base::result::makeFailure(event, failureTrace2);
        }

        // Check if field is a string
        if (resolvedField.value().empty())
        {
            return base::result::makeFailure(event, failureTrace3);
        }

        auto newString {resolvedField.value()};

        std::string oldSubstring;
        if (oldSubstr->isReference())
        {
            resolvedField = event->getString(std::static_pointer_cast<Reference>(oldSubstr)->jsonPath());

            // Check if field is a string
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            // Check if field is a string
            if (resolvedField.value().empty())
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            oldSubstring = resolvedField.value();
        }
        else
        {
            oldSubstring = std::static_pointer_cast<Value>(oldSubstr)->value().getString().value();
        }

        std::string newSubstring;
        if (newSubstr->isReference())
        {
            resolvedField = event->getString(std::static_pointer_cast<Reference>(newSubstr)->jsonPath());

            // Check if field is a string
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            // Check if field is a string
            if (resolvedField.value().empty())
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            newSubstring = resolvedField.value();
        }
        else
        {
            newSubstring = std::static_pointer_cast<Value>(newSubstr)->value().getString().value();
        }

        size_t start_pos = 0;
        while ((start_pos = newString.find(oldSubstring, start_pos)) != std::string::npos)
        {
            newString.replace(start_pos, oldSubstring.length(), newSubstring);
            start_pos += newSubstring.length();
        }

        event->setString(newString, targetField);

        return base::result::makeSuccess(event, successTrace);
    };
}

//*************************************************
//*           Int tranform                        *
//*************************************************

// field: +int_calculate/[+|-|*|/]/<val1|$ref1>/.../<valN|$refN>
MapOp opBuilderHelperIntCalc(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2, builder::builders::utils::MAX_OP_ARGS);
    // Parameter type check
    builder::builders::utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;
    auto op = strToOp(std::static_pointer_cast<Value>(opArgs[0])->value().getString().value());

    auto newArgs = std::vector<OpArg>(opArgs.begin() + 1, opArgs.end());
    auto mapOp = opBuilderHelperIntTransformation(op, newArgs, buildCtx);
    return mapOp;
}

//*************************************************
//*           Regex tranform                      *
//*************************************************

// field: +regex_extract/_field/regexp/
MapOp opBuilderHelperRegexExtract(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs, 0);
    builder::builders::utils::assertValue(opArgs, 1);
    if (!std::static_pointer_cast<Value>(opArgs[1])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().typeName()));
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    const auto refField = *std::static_pointer_cast<Reference>(opArgs[0]);

    auto regex_ptr = std::make_shared<RE2>(std::static_pointer_cast<Value>(opArgs[1])->value().getString().value());
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("\"{}\" function: Error compiling regex \"{}\": {}",
                                             name,
                                             std::static_pointer_cast<Value>(opArgs[1])->value().getString().value(),
                                             regex_ptr->error()));
    }

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, refField.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, refField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Regex did not match", name)};

    // Return Op
    return [=, refField = refField.jsonPath()](base::ConstEvent event) -> MapResult
    {
        const auto resolvedField = event->getString(refField);

        if (!resolvedField.has_value())
        {
            return base::result::makeFailure(json::Json {}, (!event->exists(refField)) ? failureTrace1 : failureTrace2);
        }

        std::string match {};
        if (RE2::PartialMatch(resolvedField.value(), *regex_ptr, &match))
        {
            json::Json result;
            result.setString(match);

            return base::result::makeSuccess(result, successTrace);
        }

        return base::result::makeFailure(json::Json {}, failureTrace3);
    };
}

// field: +merge_recursive/$field
TransformOp opBuilderHelperMergeRecursively(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs);

    const auto name = buildCtx->context().opName;
    const auto refField = *std::static_pointer_cast<Reference>(opArgs[0]);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, refField.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Fields type do not match", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Fields type not supported", name)};

    // Return Op
    return [=, targetField = targetField.jsonPath(), fieldReference = refField.jsonPath()](
               const base::Event& event) -> TransformResult
    {
        // Check target and reference field exists
        if (!event->exists(fieldReference))
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        if (!event->exists(targetField))
        {
            return base::result::makeFailure(event, failureTrace2);
        }

        // Check fields types
        const auto targetType = event->type(targetField);
        if (targetType != event->type(fieldReference))
        {
            return base::result::makeFailure(event, failureTrace3);
        }
        if (targetType != json::Json::Type::Array && targetType != json::Json::Type::Object)
        {
            return base::result::makeFailure(event, failureTrace4);
        }

        // Merge
        event->merge(json::RECURSIVE, fieldReference, targetField);

        return base::result::makeSuccess(event, successTrace);
    };
}

// event: +erase_custom_fields
TransformOp opBuilderHelperEraseCustomFields(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 0);

    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    // Function that check if a field is a custom field
    auto isCustomField = [schema = buildCtx->schemaPtr()](const std::string& path) -> bool
    {
        // Check if field is a custom field
        return !schema->hasField(path);
    };

    // Return Op
    return
        [isCustomField, targetField = targetField.jsonPath(), successTrace](const base::Event& event) -> TransformResult
    {
        // Erase custom fields
        event->eraseIfKey(isCustomField, false, targetField);
        return base::result::makeSuccess(event, successTrace);
    };
}

// field: +split/$field/[,| | ...]
TransformOp opBuilderHelperAppendSplitString(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs, 0);
    builder::builders::utils::assertValue(opArgs, 1);
    if (!std::static_pointer_cast<Value>(opArgs[1])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().typeName()));
    }
    const auto separator = std::static_pointer_cast<Value>(opArgs[1])->value().getString().value();
    if (separator.size() != 1)
    {
        throw std::runtime_error(fmt::format("Separator must be a single character, got '{}'", separator));
    }

    const auto ref = *std::static_pointer_cast<Reference>(opArgs[0]);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, ref.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, ref.dotPath())};

    // Return Op
    return [=, targetField = targetField.jsonPath(), fieldReference = ref.jsonPath(), separator = separator[0]](
               const base::Event& event) -> TransformResult
    {
        const auto resolvedReference = event->getString(fieldReference);
        if (!resolvedReference.has_value())
        {
            return base::result::makeFailure(event, (!event->exists(fieldReference)) ? failureTrace1 : failureTrace2);
        }

        const auto splitted = base::utils::string::split(resolvedReference.value(), separator);

        for (const auto& value : splitted)
        {
            event->appendString(value, targetField);
        }

        return base::result::makeSuccess(event, successTrace);
    };
}

TransformOp opBuilderHelperMerge(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs);

    const auto name = buildCtx->context().opName;
    const auto& refField = *std::static_pointer_cast<Reference>(opArgs[0]);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, refField.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Fields type do not match", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Fields type not supported", name)};

    // Return Op
    return [=, targetField = targetField.jsonPath(), fieldReference = refField.jsonPath()](
               const base::Event& event) -> TransformResult
    {
        // Check target and reference field exists
        if (!event->exists(fieldReference))
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        if (!event->exists(targetField))
        {
            return base::result::makeFailure(event, failureTrace2);
        }

        // Check fields types
        auto targetType = event->type(targetField);
        if (targetType != event->type(fieldReference))
        {
            return base::result::makeFailure(event, failureTrace3);
        }
        if (targetType != json::Json::Type::Array && targetType != json::Json::Type::Object)
        {
            return base::result::makeFailure(event, failureTrace4);
        }

        // Merge
        event->merge(json::NOT_RECURSIVE, fieldReference, targetField);

        return base::result::makeSuccess(event, successTrace);
    };
}

//*************************************************
//*             JSON tranform                     *
//*************************************************

// field: +delete
TransformOp opBuilderHelperDeleteField(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{

    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 0);

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' could not be erased", name, targetField.dotPath())};

    // Return Op
    return [=, targetField = targetField.jsonPath()](const base::Event& event) -> TransformResult
    {
        bool result {false};
        try
        {
            result = event->erase(targetField);
        }
        catch (const std::exception& e)
        {
            return base::result::makeFailure(event, failureTrace1 + e.what());
        }

        if (result)
        {
            return base::result::makeSuccess(event, successTrace);
        }
        else
        {
            return base::result::makeFailure(event, failureTrace2);
        }
    };
}

// field: +rename/$sourceField
TransformOp opBuilderHelperRenameField(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number and type of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs);

    const auto& srcField = *std::static_pointer_cast<Reference>(opArgs[0]);

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' could not be set: ", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, srcField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace4 {
        fmt::format("[{}] -> Failure: Target field '{}' could not be erased", name, targetField.dotPath())};

    return [=, targetField = targetField.jsonPath(), sourceField = srcField.jsonPath()](
               const base::Event& event) -> TransformResult
    {
        if (event->exists(sourceField))
        {
            try
            {
                event->set(targetField, sourceField);
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(event, failureTrace1 + e.what());
            }
        }
        else
        {
            return base::result::makeFailure(event, failureTrace2);
        }

        bool result {false};
        try
        {
            result = event->erase(sourceField);
        }
        catch (const std::exception& e)
        {
            return base::result::makeFailure(event, failureTrace3 + e.what());
        }

        if (result)
        {
            return base::result::makeSuccess(event, successTrace);
        }
        else
        {
            return base::result::makeFailure(event, failureTrace4);
        }
    };
}

//*************************************************
//*              IP tranform                      *
//*************************************************
// field: +s_IPVersion/$ip_field
MapOp opBuilderHelperIPVersionFromIPStr(const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs);

    const auto& ipRef = *std::static_pointer_cast<Reference>(opArgs[0]);

    // Tracing
    const auto name = buildCtx->context().opName;

    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, ipRef.dotPath())};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, ipRef.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: ", name)
                                     + "The string \"{}\" is not a valid IP address"};

    // Return Op
    return [=, name = std::move(name), ipStrPath = ipRef.jsonPath()](base::ConstEvent event) -> MapResult
    {
        const auto strIP = event->getString(ipStrPath);

        if (!strIP)
        {
            return base::result::makeFailure(json::Json {},
                                             (!event->exists(ipStrPath)) ? failureTrace1 : failureTrace2);
        }

        std::string result;
        if (::utils::ip::checkStrIsIPv4(strIP.value()))
        {
            result = "IPv4";
        }
        else if (::utils::ip::checkStrIsIPv6(strIP.value()))
        {
            result = "IPv6";
        }
        else
        {
            return base::result::makeFailure(
                json::Json {}, failureTrace3 + fmt::format("The string '{}' is not a valid IP address", strIP.value()));
        }

        json::Json resultJson;
        resultJson.setString(result);
        return base::result::makeSuccess(resultJson, successTrace);
    };
}

//*************************************************
//*              Time tranform                    *
//*************************************************

// field: + system_epoch
MapOp opBuilderHelperEpochTimeFromSystem(const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Check parameters
    builder::builders::utils::assertSize(opArgs, 0);

    // Tracing
    const auto name = buildCtx->context().opName;

    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace {fmt::format("[{}] -> Failure: Value overflow", name)};

    // Return Op
    return [=](base::ConstEvent event) -> MapResult
    {
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                       .count();
        // TODO: Delete this and dd SetInt64 or SetIntAny to JSON class, get
        // Number of any type (fix concat helper)
        if (sec > std::numeric_limits<int64_t>::max())
        {
            return base::result::makeFailure(json::Json {}, failureTrace);
        }

        json::Json result;
        result.setInt64(sec);

        return base::result::makeSuccess(result, successTrace);
    };
}

// field: +date_from_epoch/<$epoch_field_ref>|epoch_field
MapOp opBuilderHelperDateFromEpochTime(const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Check parameters
    builder::builders::utils::assertSize(opArgs, 1);
    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isInt64())
    {
        throw std::runtime_error(fmt::format("Expected 'int64' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }

    const auto name = buildCtx->context().opName;
    const auto epochParam = opArgs[0];

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace1 {fmt::format("{} -> Failure, reference not found", name)};
    const std::string failureTrace2 {fmt::format("{} -> Failure, reference type is not number", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Value overflow", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Couldn't create int from parameter", name)};

    // Return Op
    return [=, parameter = epochParam](base::ConstEvent event) -> MapResult
    {
        int64_t IntResolvedParameter;
        // Check parameter
        if (parameter->isReference())
        {
            const auto& ref = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            const auto paramValue = event->getIntAsInt64(ref);
            if (paramValue.has_value())
            {
                IntResolvedParameter = paramValue.value();
            }
            else
            {
                return base::result::makeFailure(json::Json {}, (!event->exists(ref) ? failureTrace1 : failureTrace2));
            }
        }
        else
        {
            IntResolvedParameter = std::static_pointer_cast<Value>(parameter)->value().getInt64().value();
        }

        if (IntResolvedParameter < 0 || IntResolvedParameter > std::numeric_limits<int64_t>::max())
        {
            return base::result::makeFailure(json::Json {}, failureTrace3);
        }

        date::sys_time<std::chrono::seconds> tp {std::chrono::seconds {IntResolvedParameter}};
        auto result = date::format("%Y-%m-%dT%H:%M:%SZ", tp);

        json::Json resultJson;
        resultJson.setString(result);
        return base::result::makeSuccess(resultJson, successTrace);
    };
}

//*************************************************
//*              Checksum and hash                *
//*************************************************

// field: +sha1/<string1>|<string_reference1>
MapOp opBuilderHelperHashSHA1(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected minimun number of parameters
    builder::builders::utils::assertSize(opArgs, 1);
    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace1 {fmt::format("{} -> Failure, reference not found", name)};
    const std::string failureTrace2 {fmt::format("{} -> Failure, reference type is not string", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Couldn't create HASH from string", name)};

    // Return Op
    return [=, parameter = opArgs[0]](base::ConstEvent event) -> MapResult
    {
        std::string resolvedParameter;
        // Check parameter
        if (parameter->isReference())
        {
            const auto& ref = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            const auto paramValue = event->getString(ref);
            if (!paramValue.has_value())
            {
                return base::result::makeFailure(json::Json {}, (!event->exists(ref) ? failureTrace1 : failureTrace2));
            }
            resolvedParameter = paramValue.value();
        }
        else
        {
            resolvedParameter = std::static_pointer_cast<Value>(parameter)->value().getString().value();
        }

        const auto resultHash = hashStringSHA1(resolvedParameter);
        if (!resultHash.has_value())
        {
            return base::result::makeFailure(json::Json {}, failureTrace3);
        }

        json::Json resultJson;
        resultJson.setString(resultHash.value());
        return base::result::makeSuccess(resultJson, successTrace);
    };
}

//*************************************************
//*                  Definition                   *
//*************************************************

TransformOp opBuilderHelperGetValueGeneric(const Reference& targetField,
                                           const std::vector<OpArg>& opArgs,
                                           const std::shared_ptr<const IBuildCtx>& buildCtx,
                                           bool isMerge)
{
    // Assert expected number of parameters
    builder::builders::utils::assertSize(opArgs, 2);
    // Parameter type check
    builder::builders::utils::assertRef(opArgs, 1);
    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isObject())
    {
        throw std::runtime_error(fmt::format("Expected 'object' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }

    const auto name = buildCtx->context().opName;

    const auto& keyRef = *std::static_pointer_cast<Reference>(opArgs[1]);
    // If key field is a schema field, the value should be a string
    const auto& schema = buildCtx->schema();
    if (schema.hasField(keyRef.dotPath())
        && (schema.getType(keyRef.dotPath()) != schemf::Type::KEYWORD
            && schema.getType(keyRef.dotPath()) != schemf::Type::TEXT
            && schema.getType(keyRef.dotPath()) != schemf::Type::IP))
    {
        throw std::runtime_error(
            fmt::format("Engine helper builder: [{}] failed schema validation: Field '{}' value is not a string",
                        name,
                        keyRef.dotPath()));
    }

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Reference '{}' not found", name, keyRef.dotPath())};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference Object not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Reference Object has an invalid type", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Reference is not an object", name)};
    const std::string failureTrace5 {
        fmt::format("[{}] -> Failure: Reference Object does not contain '{}'", name, keyRef.dotPath())};
    const std::string failureTrace6 {
        fmt::format("[{}] -> Failure: fields dont match type or type is not supported (array or object)", name)};

    // Return Op
    return [=, targetField = targetField.jsonPath(), parameter = opArgs[0], key = keyRef.jsonPath()](
               const base::Event& event) -> TransformResult
    {
        // Get key
        std::string resolvedKey;
        const auto value = event->getString(key);
        if (value)
        {
            resolvedKey = value.value();
        }
        else
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        auto pointerPath = json::Json::formatJsonPath(resolvedKey);

        // Get object
        std::optional<json::Json> resolvedValue {std::nullopt};

        if (parameter->isReference())
        {
            // Parameter is a reference
            const auto& refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            const auto resolvedJson = event->getJson(refPath);
            if (!resolvedJson.has_value())
            {
                return base::result::makeFailure(event, (!event->exists(refPath)) ? failureTrace2 : failureTrace3);
            }
            if (!resolvedJson->isObject())
            {
                return base::result::makeFailure(event, failureTrace4);
            }
            resolvedValue = resolvedJson->getJson(pointerPath);
        }
        else
        {
            // Parameter is a definition
            const auto& definitionObject = std::static_pointer_cast<Value>(parameter)->value();
            resolvedValue = definitionObject.getJson(pointerPath);
        }

        // Check if object contains the key
        if (!resolvedValue.has_value())
        {
            return base::result::makeFailure(event, failureTrace5);
        }

        if (!isMerge)
        {
            event->set(targetField, resolvedValue.value());
        }
        else
        {
            try
            {
                event->merge(json::NOT_RECURSIVE, resolvedValue.value(), targetField);
            }
            catch (std::runtime_error& e)
            {
                return base::result::makeFailure(event, failureTrace6);
            }
            return base::result::makeSuccess(event, successTrace);
        }

        return base::result::makeSuccess(event, successTrace);
    };
}

// <field>: +get_value/$<definition_object>|$<object_reference>/$<key>
TransformOp opBuilderHelperGetValue(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperGetValueGeneric(targetField, opArgs, buildCtx, false);
}

// <field>: +merge_value/$<definition_object>|$<object_reference>/$<key>
TransformOp opBuilderHelperMergeValue(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperGetValueGeneric(targetField, opArgs, buildCtx, true);
}

} // namespace builder::builders
