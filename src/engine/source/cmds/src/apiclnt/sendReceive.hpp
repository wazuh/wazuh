#ifndef _CMD_APICLNT_SENDRECEIVE_HPP
#define _CMD_APICLNT_SENDRECEIVE_HPP

#include <string>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>

namespace cmd::apiclnt
{

/**
 * @brief Send a request to the Engine API and receive the response
 *
 * @param socketPath Path to the Engine API socket
 * @param request Request to be sent
 * @return api::WazuhResponse Response received
 */
api::WazuhResponse sendReceive(const std::string& socketPath,
                               const api::WazuhRequest& request);

} // namespace cmd::apiclnt

#endif // _CMD_APICLNT_SENDRECEIVE_HPP
