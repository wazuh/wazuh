#include <sca_checksum.hpp>

#include <hashHelper.h>
#include <stringHelper.h>

#include <cstdio>
#include <memory>

namespace sca
{
    std::string calculateChecksum(const nlohmann::json& checkData)
    {
        // Extract id as number and convert to string
        std::string id = "";

        if (checkData.contains("id"))
        {
            if (checkData["id"].is_number())
            {
                id = std::to_string(checkData["id"].get<int>());
            }
            else if (checkData["id"].is_string())
            {
                id = checkData["id"].get<std::string>();
            }
        }

        const std::string policyId = checkData.value("policy_id", "");
        const std::string name = checkData.value("name", "");
        const std::string description = checkData.value("description", "");
        const std::string rationale = checkData.value("rationale", "");
        const std::string remediation = checkData.value("remediation", "");

        // Extract refs - might be array or string
        std::string refs = "";

        if (checkData.contains("refs"))
        {
            if (checkData["refs"].is_array())
            {
                refs = checkData["refs"].dump(); // Convert array to JSON string
            }
            else if (checkData["refs"].is_string())
            {
                refs = checkData["refs"].get<std::string>();
            }
        }

        const std::string condition = checkData.value("condition", "");

        // Extract compliance - might be object or string
        std::string compliance = "";

        if (checkData.contains("compliance"))
        {
            if (checkData["compliance"].is_object())
            {
                compliance = checkData["compliance"].dump(); // Convert object to JSON string
            }
            else if (checkData["compliance"].is_string())
            {
                compliance = checkData["compliance"].get<std::string>();
            }
        }

        // Extract rules as array and convert to string
        std::string rules = "";

        if (checkData.contains("rules"))
        {
            if (checkData["rules"].is_array())
            {
                rules = checkData["rules"].dump(); // Convert array to JSON string
            }
            else if (checkData["rules"].is_string())
            {
                rules = checkData["rules"].get<std::string>();
            }
        }

        const std::string regexType = checkData.value("regex_type", "");

        return calculateChecksum(
                   id, policyId, name, description, rationale, remediation, refs, condition, compliance, rules, regexType
               );
    }

    std::string calculateChecksum(const std::string& id,
                                  const std::string& policyId,
                                  const std::string& name,
                                  const std::string& description,
                                  const std::string& rationale,
                                  const std::string& remediation,
                                  const std::string& refs,
                                  const std::string& condition,
                                  const std::string& compliance,
                                  const std::string& rules,
                                  const std::string& regexType)
    {
        // Calculate required buffer size
        const auto size = std::snprintf(nullptr,
                                        0,
                                        "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
                                        id.c_str(),
                                        policyId.c_str(),
                                        name.c_str(),
                                        description.c_str(),
                                        rationale.c_str(),
                                        remediation.c_str(),
                                        refs.c_str(),
                                        condition.c_str(),
                                        compliance.c_str(),
                                        rules.c_str(),
                                        regexType.c_str());

        if (size < 0)
        {
            throw std::runtime_error{"Error calculating checksum size."}; // LCOV_EXCL_LINE
        }

        // Allocate buffer and format the string
        std::unique_ptr<char[]> checksumBuffer(new char[size + 1]);
        std::snprintf(checksumBuffer.get(),
                      size + 1,
                      "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
                      id.c_str(),
                      policyId.c_str(),
                      name.c_str(),
                      description.c_str(),
                      rationale.c_str(),
                      remediation.c_str(),
                      refs.c_str(),
                      condition.c_str(),
                      compliance.c_str(),
                      rules.c_str(),
                      regexType.c_str());

        // Calculate SHA1 hash using Utils::HashData
        try
        {
            Utils::HashData hash(Utils::HashType::Sha1);
            hash.update(checksumBuffer.get(), strlen(checksumBuffer.get()));

            const auto hashResult = hash.hash();
            return Utils::asciiToHex(hashResult);
        }
        // LCOV_EXCL_START
        catch (const std::exception& e)
        {
            throw std::runtime_error{"Error calculating checksum: " + std::string(e.what())};
        }

        // LCOV_EXCL_STOP
    }

} // namespace sca
