#include "opBuilderSHAfrom.hpp"

#include <iomanip>
#include <optional>
#include <string>

#include <fmt/format.h>
#include <json/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "baseTypes.hpp"
#include "syntax.hpp"

#include <baseHelper.hpp>
#include <utils/stringUtils.hpp>

namespace
{

std::optional<std::string> wdbi_strings_hash(const std::vector<std::string>& input)
{
    char* parameter = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;

    std::string hexdigest {};
    constexpr int SHA_DIGEST_LENGTH = 20;

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (!ctx)
    {
        throw std::runtime_error("Failed during hash context creation");
    }

    if (1 != EVP_DigestInit(ctx, EVP_sha1()))
    {
        EVP_MD_CTX_destroy(ctx);
        throw std::runtime_error("Failed during hash context initialization");
    }

    for (const auto& word : input)
    {
        if (1 != EVP_DigestUpdate(ctx, word.c_str(), word.length()))
        {
            throw std::runtime_error("Failed during hash context update");
        }
    }

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);

    // OS_SHA1_Hexdigest(digest, hexdigest);
    typedef char os_sha1[41];
    char output[41];
    for (size_t n = 0; n < SHA_DIGEST_LENGTH; n++)
    {
        sprintf(&output[n * 2], "%02x", digest[n]);
    }

    std::string finalResult(output, 41);

    return finalResult;
}

} // namespace

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;

// field: +sha1_from/<string1>|<string_reference1>/<string2>|<string_reference2>
base::Expression opBuilderSHAfrom(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(rawParameters);
    if (parameters.empty())
    {
        throw std::runtime_error(
            fmt::format("[opBuilderSHAfrom] parameter can not be empty"));
    }

    if (parameters.size() < 1)
    {
        throw std::runtime_error(
            fmt::format("[opBuilderSHAfrom] should have at least one parameter"));
    }

    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: parameter list shouldn't be empty", name);
    const auto failureTrace2 =
        fmt::format("[{}] -> Failure: Invalid Parameter Type", name);
    const auto failureTrace3 = fmt::format(
        "[{}] -> Failure: Couldn't create HASH and write it in the JSON", name);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event> {
            std::vector<std::string> resolvedParameter;

            // Check parameters
            for (auto& param : parameters)
            {
                // Getting array field name
                switch (param.m_type)
                {
                    case helper::base::Parameter::Type::REFERENCE:
                    {
                        if (!event->isString(param.m_value))
                        {
                            return base::result::makeFailure(event, failureTrace1);
                        }

                        auto s_paramValue = event->getString(param.m_value);
                        if (!s_paramValue.has_value())
                        {
                            return base::result::makeFailure(event, failureTrace1);
                        }

                        resolvedParameter.emplace_back(s_paramValue.value());
                        break;
                    }
                    case helper::base::Parameter::Type::VALUE:
                    {
                        resolvedParameter.emplace_back(param.m_value);
                        break;
                    }
                    default: return base::result::makeFailure(event, failureTrace2);
                }
            }

            std::string composedValue {};
            if (!resolvedParameter.size())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            try
            {
                auto resultHash = wdbi_strings_hash(resolvedParameter);
                if (!resultHash.has_value())
                {
                    return base::result::makeFailure(event, failureTrace3);
                }
                event->setString(resultHash.value(), targetField);
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(event, failureTrace3);
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

} // namespace builder::internals::builders
