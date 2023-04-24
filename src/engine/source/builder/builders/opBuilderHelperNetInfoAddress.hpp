#ifndef _OP_BUILDER_HELPER_NETINFO_ADDRES_H
#define _OP_BUILDER_HELPER_NETINFO_ADDRES_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"

/*
 * The helper Map (Transformation), builds a lifter that will chain rxcpp map operation
 * Rxcpp transform expects a function that returns event.
 */

namespace builder::internals::builders
{

/**
 * @brief Get address, netmask and gateway fields from iface IPv4
 * and executes netaddr save query for each one of them
 * e.g: field: +sysc_ni_save_ipv4
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @return base::Expression
 */
base::Expression opBuilderHelperSaveNetInfoIPv4(const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters);

/**
 * @brief Get address, netmask and gateway fields from iface IPv6
 * and executes netaddr save query for each one of them
 * e.g: field: +sysc_ni_save_ipv6
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @return base::Expression
 */
base::Expression opBuilderHelperSaveNetInfoIPv6(const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_NETINFO_ADDRES_H
