#include <sca_checksum.hpp>

#include <hashHelper.h>
#include <stringHelper.h>

#include <cstdio>
#include <memory>

namespace sca
{
    std::string calculateChecksum(const nlohmann::json& checkData)
    {
        const std::string id = checkData.value("id", "");
        const std::string policyId = checkData.value("policy_id", "");
        const std::string name = checkData.value("name", "");
        const std::string description = checkData.value("description", "");
        const std::string rationale = checkData.value("rationale", "");
        const std::string remediation = checkData.value("remediation", "");
        const std::string refs = checkData.value("refs", "");
        const std::string condition = checkData.value("condition", "");
        const std::string compliance = checkData.value("compliance", "");
        const std::string rules = checkData.value("rules", "");

        return calculateChecksum(
            id, policyId, name, description, rationale, remediation, refs, condition, compliance, rules);
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
                                  const std::string& rules)
    {
        // Calculate required buffer size
        const auto size = std::snprintf(nullptr,
                                        0,
                                        "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
                                        id.c_str(),
                                        policyId.c_str(),
                                        name.c_str(),
                                        description.c_str(),
                                        rationale.c_str(),
                                        remediation.c_str(),
                                        refs.c_str(),
                                        condition.c_str(),
                                        compliance.c_str(),
                                        rules.c_str());

        if (size < 0)
        {
            throw std::runtime_error{"Error calculating checksum size."};
        }

        // Allocate buffer and format the string
        std::unique_ptr<char[]> checksumBuffer(new char[size + 1]);
        std::snprintf(checksumBuffer.get(),
                      size + 1,
                      "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
                      id.c_str(),
                      policyId.c_str(),
                      name.c_str(),
                      description.c_str(),
                      rationale.c_str(),
                      remediation.c_str(),
                      refs.c_str(),
                      condition.c_str(),
                      compliance.c_str(),
                      rules.c_str());

        // Calculate SHA1 hash using Utils::HashData
        try
        {
            Utils::HashData hash(Utils::HashType::Sha1);
            hash.update(checksumBuffer.get(), strlen(checksumBuffer.get()));

            const auto hashResult = hash.hash();
            return Utils::asciiToHex(hashResult);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error{"Error calculating checksum: " + std::string(e.what())};
        }
    }

} // namespace sca
