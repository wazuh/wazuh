/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderHelperMap.hpp"

#include <algorithm>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <re2/re2.h>

#include "syntax.hpp"
#include <baseHelper.hpp>
#include <utils/ipUtils.hpp>
#include <utils/stringUtils.hpp>

namespace
{

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

IntOperator strToOp(const helper::base::Parameter& op)
{
    if ("sum" == op.m_value)
    {
        return IntOperator::SUM;
    }
    else if ("sub" == op.m_value)
    {
        return IntOperator::SUB;
    }
    else if ("mul" == op.m_value)
    {
        return IntOperator::MUL;
    }
    else if ("div" == op.m_value)
    {
        return IntOperator::DIV;
    }
    throw std::runtime_error(fmt::format("Operation '{}' not supported", op.m_value));
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
base::Expression opBuilderHelperStringTransformation(const std::any& definition, StringOperator op)
{
    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Depending on rValue type we store the reference or the string value, string in both
    // cases
    std::string rValue {};
    const helper::base::Parameter rightParameter {parameters.at(0)};
    const auto rValueType {rightParameter.m_type};
    rValue = rightParameter.m_value;

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

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Reference '{}' not found", name, rightParameter.m_value)};

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
        {
            // We assert that references exists, checking if the optional from Json getter
            // is empty ot not. Then if is a reference we get the value from the event,
            // otherwise we get the value from the parameter

            // REF

            if (helper::base::Parameter::Type::REFERENCE == rValueType)
            {
                const auto resolvedRValue {event->getString(rValue)};

                if (!resolvedRValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
                else
                {
                    // TODO: should we check the result?
                    auto res {transformFunction(resolvedRValue.value())};
                    event->setString(res, targetField);
                    return base::result::makeSuccess(event, successTrace);
                }
            }
            else
            {
                // TODO: should we check the result?
                const auto res {transformFunction(rValue)};
                event->setString(res, targetField);
                return base::result::makeSuccess(event, successTrace);
            }
        });
}

/**
 * @brief Tranform the int in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param definition The transformation definition. i.e :
 * +i_calc/[+|-|*|/]/<val1|$ref1>/<.../valN|$refN>/
 * @param op The operator to use:
 * - `SUM`: Sum
 * - `SUB`: Subtract
 * - `MUL`: Multiply
 * - `DIV`: Divide
 * @return base::Expression
 */
base::Expression opBuilderHelperIntTransformation(const std::string& targetField,
                                                  IntOperator op,
                                                  const std::vector<helper::base::Parameter>& parameters,
                                                  const std::string& name)
{
    std::vector<int> rValueVector {};
    std::vector<std::string> rReferenceVector {};

    // Depending on rValue type we store the reference or the integer value, avoiding
    // iterating again through values inside lambda
    for (const auto& param : parameters)
    {
        int rValue {};
        switch (param.m_type)
        {
            case helper::base::Parameter::Type::VALUE:
                try
                {
                    rValue = std::stoi(param.m_value);
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error(
                        fmt::format("\"{}\" function: Could not convert parameter \"{}\" to int: {}", name, param.m_value, e.what()));
                }
                if (IntOperator::DIV == op && 0 == rValue)
                {
                    throw std::runtime_error(fmt::format("\"{}\" function: Division by zero", name));
                }

                rValueVector.emplace_back(rValue);
                break;

            case helper::base::Parameter::Type::REFERENCE: rReferenceVector.emplace_back(param.m_value); break;

            default:
                throw std::runtime_error(
                    fmt::format("\"{}\" function: Invalid parameter type of \"{}\"", name, param.m_value));
        }
    }
    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace1 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField)};
    const std::string failureTrace2 {fmt::format(R"([{}] -> Failure: Reference not found: )", name)};
    const std::string failureTrace3 {fmt::format(R"([{}] -> Failure: Parameter is not integer: )", name)};
    const std::string failureTrace4 = fmt::format(R"([{}] -> Failure: Parameter value makes division by zero: )", name);
    const std::string overflowFailureTrace =
        fmt::format(R"([{}] -> Failure: operation result in integer Overflown)", name);
    const std::string underflowFailureTrace =
        fmt::format(R"([{}] -> Failure: operation result in integer Underflown)", name);

    // Depending on the operator we return the correct function
    std::function<int(int l, int r)> transformFunction;
    switch (op)
    {
        case IntOperator::SUM:
            transformFunction = [overflowFailureTrace, underflowFailureTrace](int l, int r)
            {
                if ((r > 0) && (l > INT_MAX - r))
                {
                    throw std::runtime_error(overflowFailureTrace);
                }
                else if ((r < 0) && (l < INT_MIN - r))
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
            transformFunction = [overflowFailureTrace, underflowFailureTrace](int l, int r)
            {
                if ((r < 0) && (l > INT_MAX + r))
                {
                    throw std::runtime_error(overflowFailureTrace);
                }
                else if ((r > 0) && (l < INT_MIN + r))
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
            transformFunction = [overflowFailureTrace, underflowFailureTrace](int l, int r)
            {
                if ((r != 0) && (l > INT_MAX / r))
                {
                    throw std::runtime_error(overflowFailureTrace);
                }
                else if ((r != 0) && (l < INT_MIN * r))
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
            transformFunction = [name, overflowFailureTrace, underflowFailureTrace](int l, int r)
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
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         rValueVector = std::move(rValueVector),
         rReferenceVector = std::move(rReferenceVector),
         targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
        {
            std::vector<int> auxVector {};
            auxVector.insert(auxVector.begin(), rValueVector.begin(), rValueVector.end());

            const auto lValue {event->getInt(targetField)};
            if (!lValue.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            // Iterate throug all references and append them values to the value vector
            for (const auto& rValueItem : rReferenceVector)
            {
                const auto resolvedRValue {event->getInt(rValueItem)};
                if (!resolvedRValue.has_value())
                {
                    return base::result::makeFailure(event,
                                                     (!event->exists(rValueItem)) ? (failureTrace2 + rValueItem)
                                                                                  : (failureTrace3 + rValueItem));
                }
                else
                {
                    if (IntOperator::DIV == op && 0 == resolvedRValue.value())
                    {
                        return base::result::makeFailure(event, failureTrace4 + rValueItem);
                    }

                    auxVector.emplace_back(resolvedRValue.value());
                }
            }

            int res;
            try
            {
                res = std::accumulate(auxVector.begin(), auxVector.end(), lValue.value(), transformFunction);
            }
            catch (const std::runtime_error& e)
            {
                return base::result::makeFailure(event, e.what());
            }

            event->setInt(res, targetField);
            return base::result::makeSuccess(event, successTrace);
        });
}

std::optional<std::string> hashStringSHA1(std::string& input)
{
    // Sha1 digest len (20) * 2 (hex chars per byte)
    constexpr int OS_SHA1_HEXDIGEST_SIZE = (SHA_DIGEST_LENGTH * 2);
    constexpr int OS_SHA1_ARRAY_SIZE_LEN = OS_SHA1_HEXDIGEST_SIZE + 1;

    char* parameter = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (!ctx)
    {
        // Failed during hash context creation
        return std::nullopt;
    }

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
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

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
//*************************************************
//*           String tranform                     *
//*************************************************

// field: +s_up/value|$ref
base::Expression opBuilderHelperStringUP(const std::any& definition)
{
    auto expression {opBuilderHelperStringTransformation(definition, StringOperator::UP)};
    return expression;
}

// field: +s_lo/value|$ref
base::Expression opBuilderHelperStringLO(const std::any& definition)
{
    auto expression {opBuilderHelperStringTransformation(definition, StringOperator::LO)};
    return expression;
}

// field: +s_trim/[begin | end | both]/char
base::Expression opBuilderHelperStringTrim(const std::any& definition)
{

    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 2);
    // Parameter type check
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::VALUE);
    helper::base::checkParameterType(name, parameters.at(1), helper::base::Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Get trim type
    const char trimType = parameters.at(0).m_value == "begin"  ? 's'
                          : parameters.at(0).m_value == "end"  ? 'e'
                          : parameters.at(0).m_value == "both" ? 'b'
                                                               : '\0';
    if ('\0' == trimType)
    {
        throw std::runtime_error(
            fmt::format("\"{}\" function: Invalid trim type \"{}\"", name, parameters.at(0).m_value));
    }

    // get trim char
    std::string trimChar {parameters.at(1).m_value};
    if (trimChar.size() != 1)
    {
        throw std::runtime_error(fmt::format("'{}' function: Invalid trim char '{}'", name, trimChar));
    }

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField)};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_TYPE_NOT_STRING, name, targetField)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Invalid trim type '{}'", name, trimType)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
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
        });
}

// field: +s_concat/string1|$ref1/string2|$ref2
base::Expression opBuilderHelperStringConcat(const std::any& definition)
{

    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    checkParametersMinSize(name, parameters, 2);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: ", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
        {
            std::string result {};

            for (auto parameter : parameters)
            {
                if (helper::base::Parameter::Type::REFERENCE == parameter.m_type)
                {
                    // Check path exists
                    if (!event->exists(parameter.m_value))
                    {
                        return base::result::makeFailure(
                            event, failureTrace1 + fmt::format("Reference '{}' not found", parameter.m_value));
                    }

                    // Get field value
                    std::string resolvedField {};
                    if (event->isDouble(parameter.m_value))
                    {
                        resolvedField = std::to_string(event->getDouble(parameter.m_value).value());
                    }
                    else if (event->isInt(parameter.m_value))
                    {
                        resolvedField = std::to_string(event->getInt(parameter.m_value).value());
                    }
                    else if (event->isString(parameter.m_value))
                    {
                        resolvedField = event->getString(parameter.m_value).value();
                    }
                    else if (event->isObject(parameter.m_value))
                    {
                        resolvedField = event->str(parameter.m_value).value();
                    }
                    else
                    {
                        return base::result::makeFailure(
                            event,
                            failureTrace2 + fmt::format("Parameter '{}' type cannot be handled", parameter.m_value));
                    }

                    result.append(resolvedField);
                }
                else
                {
                    result.append(parameter.m_value);
                }
            }

            event->setString(result, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// field: +s_from_array/$<array_reference1>/<separator>
base::Expression opBuilderHelperStringFromArray(const std::any& definition)
{
    const auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    const auto parameters = helper::base::processParameters(name, rawParameters);
    helper::base::checkParametersSize(name, parameters, 2);

    // Check Array reference parameter
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);
    const auto arrayName = parameters.at(0);

    // Check separator parameter
    helper::base::checkParameterType(name, parameters.at(1), helper::base::Parameter::Type::VALUE);
    const auto separator = parameters.at(1);

    const std::string traceName {helper::base::formatHelperName(name, targetField, parameters)};

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Array member from '{}' should be a string", traceName, arrayName.m_value)};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, arrayName.m_value)};
    const std::string failureTrace3 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "array", traceName, arrayName.m_value)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        traceName,
        [=,
         targetField = std::move(targetField),
         separator = std::move(separator.m_value),
         arrayName = std::move(arrayName.m_value)](base::Event event) -> base::result::Result<base::Event>
        {
            // Getting array field, must be a reference
            const auto stringJsonArray = event->getArray(arrayName);
            if (!stringJsonArray.has_value())
            {
                return base::result::makeFailure(event, (!event->exists(arrayName)) ? failureTrace2 : failureTrace3);
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
                    return base::result::makeFailure(event, failureTrace1);
                }
            }

            // accumulated concation without trailing indexes
            const std::string composedValueString {utils::string::join(stringArray, separator)};

            event->setString(composedValueString, targetField);
            return base::result::makeSuccess(event, successTrace);
        });
}

// field: +s_from_hexa/$<hex_reference>
base::Expression opBuilderHelperStringFromHexa(const std::any& definition)
{
    const auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);

    const auto parameters = helper::base::processParameters(name, rawParameters);

    helper::base::checkParametersSize(name, parameters, 1);

    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);

    const auto sourceField = parameters.at(0);

    const std::string traceName {helper::base::formatHelperName(name, targetField, parameters)};

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, sourceField.m_value)};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "array", traceName, sourceField.m_value)};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Hexa string has not an even quantity of digits", traceName)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: ", traceName)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        traceName,
        [=, targetField = std::move(targetField), sourceField = std::move(sourceField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string strHex {};

            // Getting string field from a reference
            const auto refStrHEX = event->getString(sourceField.m_value);
            if (!refStrHEX.has_value())
            {
                return base::result::makeFailure(event,
                                                 (!event->exists(sourceField.m_value)) ? failureTrace1 : failureTrace2);
            }

            strHex = refStrHEX.value();

            const auto lenHex = strHex.length();

            if (lenHex % 2)
            {
                return base::result::makeFailure(event, failureTrace3);
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
                        event, failureTrace4 + fmt::format("Character '{}' is not a valid hexa digit", err));
                }

                strASCII[iASCII] = chr;
            }

            event->setString(strASCII, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// field: +s_hex_to_num/$ref
base::Expression opBuilderHelperHexToNumber(const std::any& definition)
{
    const auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    const auto parameters = helper::base::processParameters(name, rawParameters);
    helper::base::checkParametersSize(name, parameters, 1);
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);
    const auto sourceField = parameters.at(0);

    const std::string traceName {helper::base::formatHelperName(name, targetField, parameters)};

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, sourceField.m_value)};
    const std::string failureTrace2 {
        fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", traceName, sourceField.m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: ", traceName)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        traceName,
        [=, targetField = std::move(targetField), sourceField = std::move(sourceField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // Getting string field from a reference
            const auto refStrHEX = event->getString(sourceField.m_value);
            if (!refStrHEX.has_value())
            {
                return base::result::makeFailure(
                    event,
                    fmt::format((!event->exists(sourceField.m_value)) ? failureTrace1 : failureTrace2,
                                sourceField.m_value));
            }
            std::stringstream ss;
            ss << refStrHEX.value();
            int result;
            ss >> std::hex >> result;
            if (ss.fail() || !ss.eof())
            {
                return base::result::makeFailure(
                    event, failureTrace3 + fmt::format("String '{}' is not a hexadecimal value", refStrHEX.value()));
            }

            event->setInt(result, targetField);
            return base::result::makeSuccess(event, successTrace);
        });
}

// field: +s_replace/substring/new_substring
base::Expression opBuilderHelperStringReplace(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 2);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    const auto paramOldSubstr = parameters.at(0);
    if (paramOldSubstr.m_value.empty())
    {
        throw std::runtime_error(fmt::format("'{}' function: First parameter (substring) cannot be empty", name));
    }
    const auto paramNewSubstr = parameters.at(1);

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField)};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_TYPE_NOT_STRING, name, targetField)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Target field '{}' is empty", name, targetField)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = std::move(targetField),
         paramOldSubstr = std::move(paramOldSubstr),
         paramNewSubstr = std::move(paramNewSubstr)](base::Event event) -> base::result::Result<base::Event>
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

            std::string oldSubstring {paramOldSubstr.m_value};
            if (helper::base::Parameter::Type::REFERENCE == paramOldSubstr.m_type)
            {
                resolvedField = event->getString(paramOldSubstr.m_value);

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

            std::string newSubstring {paramNewSubstr.m_value};
            if (helper::base::Parameter::Type::REFERENCE == paramNewSubstr.m_type)
            {
                resolvedField = event->getString(paramNewSubstr.m_value);

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

            size_t start_pos = 0;
            while ((start_pos = newString.find(oldSubstring, start_pos)) != std::string::npos)
            {
                newString.replace(start_pos, oldSubstring.length(), newSubstring);
                start_pos += newSubstring.length();
            }

            event->setString(newString, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

//*************************************************
//*           Int tranform                        *
//*************************************************

// field: +i_calc/[+|-|*|/]/<val1|$ref1>/.../<valN|$refN>
base::Expression opBuilderHelperIntCalc(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    checkParametersMinSize(name, parameters, 2);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);
    const auto op {strToOp(parameters.at(0))};
    // TODO: check if there's a better way to do this
    //  remove operation parameter in order to handle all the params equally
    parameters.erase(parameters.begin());

    auto expression {opBuilderHelperIntTransformation(targetField, op, parameters, name)};
    return expression;
}

//*************************************************
//*           Regex tranform                      *
//*************************************************

// field: +r_ext/_field/regexp/
base::Expression opBuilderHelperRegexExtract(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 2);
    // Parameter type check
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);
    helper::base::checkParameterType(name, parameters.at(1), helper::base::Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    std::string map_field {parameters.at(0).m_value};

    auto regex_ptr = std::make_shared<RE2>(parameters.at(1).m_value);
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format(
            "\"{}\" function: Error compiling regex \"{}\": {}", name, parameters.at(1).m_value, regex_ptr->error()));
    }

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, map_field)};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, map_field)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Regex did not match", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
        {
            // TODO Remove try catch
            const auto resolvedField = event->getString(map_field);

            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, (!event->exists(map_field)) ? failureTrace1 : failureTrace2);
            }

            std::string match {};
            if (RE2::PartialMatch(resolvedField.value(), *regex_ptr, &match))
            {
                event->setString(match, targetField);

                return base::result::makeSuccess(event, successTrace);
            }

            return base::result::makeFailure(event, failureTrace3);
        });
}

//*************************************************
//*           Array tranform                      *
//*************************************************

// field: +a_append/$field|literal...
base::Expression opBuilderHelperAppend(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(name, rawParameters);

    checkParametersMinSize(name, parameters, 1);

    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureSuffix1 {"Parameter '{}' reference not found"};
    const std::string failureSuffix2 {"Parameter '{}' type is not a string"};
    const std::string failureSuffix3 {"Parameter '{}' type unexpected"};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
        {
            for (const auto& parameter : parameters)
            {
                switch (parameter.m_type)
                {
                    case helper::base::Parameter::Type::REFERENCE:
                    {
                        auto value = event->getJson(parameter.m_value);
                        if (!value)
                        {
                            return base::result::makeFailure(
                                event,
                                failureTrace
                                    + fmt::format((!event->exists(parameter.m_value)) ? failureSuffix1 : failureSuffix2,
                                                  parameter.m_value));
                        }

                        event->appendJson(value.value(), targetField);
                    }
                    break;
                    case helper::base::Parameter::Type::VALUE:
                    {
                        event->appendString(parameter.m_value, targetField);
                    }
                    break;
                    default:
                        return base::result::makeFailure(event,
                                                         failureTrace + fmt::format(failureSuffix3, parameter.m_value));
                }
            }
            return base::result::makeSuccess(event, successTrace);
        });
}

// field: +ef_merge_r/$field
base::Expression opBuilderHelperMergeRecursively(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(name, rawParameters);
    helper::base::checkParametersSize(name, parameters, 1);
    helper::base::checkParameterType(name, parameters[0], helper::base::Parameter::Type::REFERENCE);

    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, parameters[0].m_value)};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Fields type do not match", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Fields type not supported", name)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), fieldReference = std::move(parameters[0].m_value)](
            base::Event event) -> base::result::Result<base::Event>
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
        });
}

// field: +s_to_array/$field/[,| | ...]
base::Expression opBuilderHelperAppendSplitString(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(name, rawParameters);
    helper::base::checkParametersSize(name, parameters, 2);
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);
    helper::base::checkParameterType(name, parameters.at(1), helper::base::Parameter::Type::VALUE);
    if (parameters.at(1).m_value.size() != 1)
    {
        throw std::runtime_error(fmt::format(
            "\"{}\" function: Separator \"{}\" should be one character long", name, parameters.at(1).m_value.size()));
    }

    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, parameters.at(0).m_value)};
    const std::string failureTrace2 {
        fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, parameters.at(0).m_value)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = std::move(targetField),
         fieldReference = std::move(parameters.at(0).m_value),
         separator = std::move(parameters.at(1).m_value[0])](base::Event event) -> base::result::Result<base::Event>
        {
            const auto resolvedReference = event->getString(fieldReference);
            if (!resolvedReference.has_value())
            {
                return base::result::makeFailure(event,
                                                 (!event->exists(fieldReference)) ? failureTrace1 : failureTrace2);
            }

            const auto splitted = utils::string::split(resolvedReference.value(), separator);

            for (const auto& value : splitted)
            {
                event->appendString(value, targetField);
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

base::Expression opBuilderHelperMerge(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(name, rawParameters);
    helper::base::checkParametersSize(name, parameters, 1);
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);

    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, parameters.at(0).m_value)};
    const std::string failureTrace2 {fmt::format(TRACE_TARGET_NOT_FOUND, name, targetField)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Fields type do not match", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Fields type not supported", name)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), fieldReference = std::move(parameters.at(0).m_value)](
            base::Event event) -> base::result::Result<base::Event>
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
        });
}

//*************************************************
//*             JSON tranform                     *
//*************************************************

// field: +ef_delete
base::Expression opBuilderHelperDeleteField(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 0);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' could not be erased", name, targetField)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
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
        });
}

// field: +ef_rename/$sourceField
base::Expression opBuilderHelperRenameField(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, rawParameters)};
    // Assert expected number and type of parameters
    helper::base::checkParametersSize(name, parameters, 1);
    auto sourceField = parameters.at(0);
    helper::base::checkParameterType(name, sourceField, helper::base::Parameter::Type::REFERENCE);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing messages
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' could not be set: ", name, targetField)};
    const std::string failureTrace2 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, sourceField.m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace4 {
        fmt::format("[{}] -> Failure: Target field '{}' could not be erased", name, targetField)};

    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), sourceField = std::move(sourceField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            if (event->exists(sourceField.m_value))
            {
                try
                {
                    event->set(targetField, sourceField.m_value);
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
                result = event->erase(sourceField.m_value);
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
        });
}

//*************************************************
//*              IP tranform                      *
//*************************************************
// field: +s_IPVersion/$ip_field
base::Expression opBuilderHelperIPVersionFromIPStr(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(name, rawParameters)};

    // Check parameters
    helper::base::checkParametersSize(name, parameters, 1);
    helper::base::checkParameterType(name, parameters.at(0), helper::base::Parameter::Type::REFERENCE);

    // Tracing
    name = helper::base::formatHelperName(name, targetField, parameters);

    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};

    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, parameters.at(0).m_value)};
    const std::string failureTrace2 {
        fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, parameters.at(0).m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: ", name)
                                     + "The string \"{}\" is not a valid IP address"};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = std::move(targetField),
         name = std::move(name),
         ipStrPath = std::move(parameters.at(0).m_value)](base::Event event) -> base::result::Result<base::Event>
        {
            const auto strIP = event->getString(ipStrPath);

            if (!strIP)
            {
                return base::result::makeFailure(event, (!event->exists(ipStrPath)) ? failureTrace1 : failureTrace2);
            }

            if (utils::ip::checkStrIsIPv4(strIP.value()))
            {
                event->setString("IPv4", targetField);
            }
            else if (utils::ip::checkStrIsIPv6(strIP.value()))
            {
                event->setString("IPv6", targetField);
            }
            else
            {
                return base::result::makeFailure(
                    event, failureTrace3 + fmt::format("The string '{}' is not a valid IP address", strIP.value()));
            }
            return base::result::makeSuccess(event, successTrace);
        });
}

//*************************************************
//*              Time tranform                    *
//*************************************************

// field: + sys_epoch
base::Expression opBuilderHelperEpochTimeFromSystem(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(name, rawParameters);

    // Check parameters
    helper::base::checkParametersSize(name, parameters, 0);

    // Tracing
    name = helper::base::formatHelperName(name, targetField, parameters);

    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace {fmt::format("[{}] -> Failure: Value overflow", name)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event) -> base::result::Result<base::Event>
        {
            auto sec =
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count();
            // TODO: Delete this and dd SetInt64 or SetIntAny to JSON class, get
            // Number of any type (fix concat helper)
            if (sec > std::numeric_limits<int>::max())
            {
                return base::result::makeFailure(event, failureTrace);
            }
            event->setInt(sec, targetField);
            return base::result::makeSuccess(event, successTrace);
        });
}

//*************************************************
//*              Checksum and hash                *
//*************************************************

// field: +h_sha1/<string1>|<string_reference1>
base::Expression opBuilderHelperHashSHA1(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    const auto parameters = helper::base::processParameters(name, rawParameters);

    // Assert expected minimun number of parameters
    helper::base::checkParametersSize(name, parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Tracing
    const std::string successTrace {fmt::format(TRACE_SUCCESS, name)};
    const std::string failureTrace1 {fmt::format(TRACE_REFERENCE_NOT_FOUND, name, parameters.at(0).m_value)};
    const std::string failureTrace2 {
        fmt::format(TRACE_REFERENCE_TYPE_IS_NOT, "string", name, parameters.at(0).m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Couldn't create HASH from string", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), parameter = std::move(parameters.at(0))](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string resolvedParameter;
            // Check parameter
            if (helper::base::Parameter::Type::REFERENCE == parameter.m_type)
            {
                const auto paramValue = event->getString(parameter.m_value);
                if (!paramValue.has_value())
                {
                    return base::result::makeFailure(
                        event, (!event->exists(parameter.m_value) ? failureTrace1 : failureTrace2));
                }
                resolvedParameter = paramValue.value();
            }
            else
            {
                resolvedParameter = parameter.m_value;
            }

            const auto resultHash = hashStringSHA1(resolvedParameter);
            if (!resultHash.has_value())
            {
                return base::result::makeFailure(event, failureTrace3);
            }
            event->setString(resultHash.value(), targetField);
            return base::result::makeSuccess(event, successTrace);
        });
}

} // namespace builder::internals::builders
