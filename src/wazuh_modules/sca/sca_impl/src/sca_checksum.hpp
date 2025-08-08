#pragma once

#include <json.hpp>
#include <string>

namespace sca
{
    /**
     * @brief Calculate SHA1 checksum for SCA check data
     *
     * This function calculates a checksum based on the check's core attributes.
     * The checksum is based on: id, policy_id, name, description, rationale,
     * remediation, refs, condition, compliance, and rules.
     *
     * @param checkData JSON object containing the check data
     * @return SHA1 checksum as a hex string, or empty string on error
     * @throw std::runtime_error if checksum calculation fails
     */
    std::string calculateChecksum(const nlohmann::json& checkData);

    /**
     * @brief Calculate SHA1 checksum for SCA check data from individual fields
     *
     * @param id Check ID
     * @param policyId Policy ID this check belongs to
     * @param name Check name
     * @param description Check description
     * @param rationale Check rationale
     * @param remediation Check remediation
     * @param refs Check references
     * @param condition Check condition
     * @param compliance Check compliance information
     * @param rules Check rules
     * @return SHA1 checksum as a hex string, or empty string on error
     * @throw std::runtime_error if checksum calculation fails
     */
    std::string calculateChecksum(const std::string& id,
                                  const std::string& policyId,
                                  const std::string& name,
                                  const std::string& description,
                                  const std::string& rationale,
                                  const std::string& remediation,
                                  const std::string& refs,
                                  const std::string& condition,
                                  const std::string& compliance,
                                  const std::string& rules);

} // namespace sca
