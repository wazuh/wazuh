#ifndef _OP_BUILDER_HELPER_NETINFO_ADDRES_H
#define _OP_BUILDER_HELPER_NETINFO_ADDRES_H

#include <wdb/iwdbManager.hpp>

#include "builders/types.hpp"

/*
 * The helper Map (Transformation), builds a lifter that will chain rxcpp map operation
 * Rxcpp transform expects a function that returns event.
 */

namespace builder::builders::optransform
{

/**
 * @brief Get address, netmask and gateway fields from iface IPv4
 * and executes netaddr save query for each one of them
 * e.g: field: +sysc_ni_save_ipv4
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression
 */
TransformBuilder getSaveNetInfoIPv4Builder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager);

/**
 * @brief Get address, netmask and gateway fields from iface IPv6
 * and executes netaddr save query for each one of them
 * e.g: field: +sysc_ni_save_ipv6
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression
 */
TransformBuilder getSaveNetInfoIPv6Builder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager);

} // namespace builder::builders::optransform

#endif // _OP_BUILDER_HELPER_NETINFO_ADDRES_H
