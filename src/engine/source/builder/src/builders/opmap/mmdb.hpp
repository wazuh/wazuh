#ifndef _BUILDER_BUILDERS_OPTRANSFORM_MMDB_HPP
#define _BUILDER_BUILDERS_OPTRANSFORM_MMDB_HPP

#include <geo/imanager.hpp>

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
 * @param geoManager The geo manager.
 * @return The builder for the MMDB Geo operation.
 * @see geo::IManager
 */
MapBuilder getMMDBGeoBuilder(const std::shared_ptr<geo::IManager>& geoManager);

/**
 * @brief Get the builder for the MMDB ASN operation.
 *
 * This builder is used to create an ASN operation that uses the MaxMind DB file format, offered by MaxMind Inc.
 * http://www.maxmind.com for looking up IP addresses in MMDB databases. The extract the fields from the MMDB database
 * according to the Wazuh schema:
 * - as.organization.name: The name of the organization that owns the ASN.
 * - as.number: The ASN number.
 *
 * @param geoManager The geo manager.
 * @return The builder for the MMDB ASN operation.
 * @see mmdb::IManager
 */
MapBuilder getMMDBASNBuilder(const std::shared_ptr<geo::IManager>& geoManager);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_OPTRANSFORM_MMDB_HPP
