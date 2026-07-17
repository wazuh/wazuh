/*
 * AES-CMAC request signing — SPIKE #37738 PoC (C++17 core).
 * Implements the #37732 canonical-request authentication scheme:
 *
 *   canonical = "WAZUH-REQUEST\n" ver "\n" METHOD "\n" target "\n"
 *               agent-id "\n" timestamp "\n" body
 *   mac       = AES-CMAC(agent-key, canonical)        (16 bytes -> 32 hex)
 *   Authorization: Wazuh <agent-id>:<timestamp>:<mac>
 *   protocol-version: 1
 *
 * Uses OpenSSL 3.x EVP_MAC ("CMAC"), which is available in the vendored
 * external/openssl (verified: cmac.h + EVP_MAC_fetch/EVP_MAC_init). The mock
 * manager verifies the same MAC via the `openssl mac` CLI — so a matching run
 * proves cross-implementation interop, not just self-consistency.
 */

#ifndef HC_CMAC_HPP
#define HC_CMAC_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace HcCmac
{
    /* AES-CMAC(key, msg) as 32 lowercase hex chars; std::nullopt on failure. */
    std::optional<std::string> macHex(const std::string& keyHex,
                                      const uint8_t* msg, size_t msgLen);

    /* Build "WAZUH-REQUEST\n1\nMETHOD\ntarget\nid\nts\n" + body. */
    std::vector<uint8_t> canonicalRequest(const std::string& method,
                                          const std::string& target,
                                          const std::string& agentId,
                                          long timestamp,
                                          const uint8_t* body, size_t bodyLen);
} // namespace HcCmac

#endif // HC_CMAC_HPP
