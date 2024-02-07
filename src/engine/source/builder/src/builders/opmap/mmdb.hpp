#ifndef _BUILDER_BUILDERS_OPTRANSFORM_MMDB_HPP
#define _BUILDER_BUILDERS_OPTRANSFORM_MMDB_HPP

#include <mmdb/imanager.hpp>

#include "builders/types.hpp"

namespace builder::builders::mmdb
{
/**
 * @brief Get the builder for the MMDB Geo operation.
 *
 * This builder is used to create a Geo operation that uses the MaxMind DB file format, offered by MaxMind Inc.
 * http://www.maxmind.com for looking up IP addresses in MMDB databases. The extract the fields from the MMDB database
 * according to the Wazuh schema.
 *
 * @param mmdbManager The MMDB manager.
 * @return The builder for the MMDB Geo operation.
 * @see mmdb::IManager
 */
MapBuilder getMMDBGeoBuilder(const std::shared_ptr<::mmdb::IManager>& mmdbManager);

/**
 * @brief Get the builder for the MMDB ASN operation.
 *
 * This builder is used to create an ASN operation that uses the MaxMind DB file format, offered by MaxMind Inc.
 * http://www.maxmind.com for looking up IP addresses in MMDB databases. The extract the fields from the MMDB database
 * according to the Wazuh schema:
 * - as.organization.name: The name of the organization that owns the ASN.
 * - as.number: The ASN number.
 *
 * @param mmdbManager The MMDB manager.
 * @return The builder for the MMDB ASN operation.
 * @see mmdb::IManager
 */
MapBuilder getMMDBASNBuilder(const std::shared_ptr<::mmdb::IManager>& mmdbManager);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_OPTRANSFORM_MMDB_HPP
